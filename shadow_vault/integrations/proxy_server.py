"""
OpenAI-compatible FastAPI proxy server with bi-directional PII dehydration and streaming SSE hydration.
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator
import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, StreamingResponse

from shadow_vault.engine import ShadowVault


def create_proxy_app(
    vault: ShadowVault,
    upstream_base_url: str = "https://api.openai.com/v1",
    upstream_url: str | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Create an OpenAI-compatible FastAPI proxy server application.

    Intercepts /v1/chat/completions requests:
    - Reads session scope from X-Session-ID header (defaults to 'default').
    - Recursively dehydrates messages in the request payload before forwarding to upstream.
    - Hydrates choices content in non-streaming JSON responses.
    - Hydrates streaming Server-Sent Events (SSE) text deltas in real-time via StreamHydrator.

    Args:
        vault: ShadowVault engine instance.
        upstream_base_url: Upstream LLM API endpoint base URL.
        http_client: Optional custom httpx.AsyncClient (useful for testing or custom transports).

    Returns:
        Configured FastAPI application instance.
    """
    app = FastAPI(
        title="Shadow Vault OpenAI Proxy",
        description="Format-preserving reversible PII proxy server for LLM chat completions.",
        version="0.3.0",
    )

    client = http_client or httpx.AsyncClient()

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "ok", "service": "shadow-vault-proxy"}

    @app.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
        x_session_id: str | None = Header(default=None, alias="X-Session-ID"),
    ) -> Any:
        session_id = x_session_id or "default"
        payload = await request.json()

        # 1. Dehydrate messages before forwarding to upstream LLM
        if "messages" in payload:
            payload["messages"] = vault.dehydrate(payload["messages"], session_id=session_id)

        is_stream = bool(payload.get("stream", False))

        # Forward authorization headers if provided by the client
        forward_headers: dict[str, str] = {"content-type": "application/json"}
        auth_header = request.headers.get("authorization")
        if auth_header:
            forward_headers["authorization"] = auth_header

        target_base = upstream_url or upstream_base_url
        target_url = f"{target_base.rstrip('/')}/chat/completions"

        if not is_stream:
            # Non-streaming JSON path
            upstream_resp = await client.post(
                target_url,
                json=payload,
                headers=forward_headers,
                timeout=120.0,
            )

            try:
                resp_json = upstream_resp.json()
            except Exception:
                return JSONResponse(
                    content={"error": upstream_resp.text},
                    status_code=upstream_resp.status_code,
                )

            # Hydrate choices content if response succeeded
            if upstream_resp.status_code == 200 and isinstance(resp_json, dict):
                choices = resp_json.get("choices", [])
                for choice in choices:
                    msg = choice.get("message")
                    if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                        msg["content"] = vault.hydrate(msg["content"], session_id=session_id)

            return JSONResponse(content=resp_json, status_code=upstream_resp.status_code)

        else:
            # Streaming SSE path with StreamHydrator holdback buffer
            stream_hydrator = vault.stream(session_id=session_id)

            async def sse_event_stream() -> AsyncIterator[str]:
                async with client.stream(
                    "POST",
                    target_url,
                    json=payload,
                    headers=forward_headers,
                    timeout=120.0,
                ) as response:
                    async for raw_line in response.aiter_lines():
                        if not raw_line:
                            yield "\n"
                            continue

                        if raw_line.startswith("data: "):
                            data_str = raw_line[6:].strip()
                            if data_str == "[DONE]":
                                # Flush any remaining held back tokens
                                flushed_text = stream_hydrator.flush()
                                if flushed_text:
                                    flush_payload = {
                                        "id": "chatcmpl-flush",
                                        "object": "chat.completion.chunk",
                                        "choices": [
                                            {
                                                "index": 0,
                                                "delta": {"content": flushed_text},
                                                "finish_reason": None,
                                            }
                                        ],
                                    }
                                    yield f"data: {json.dumps(flush_payload)}\n\n"

                                yield "data: [DONE]\n\n"
                                break

                            try:
                                chunk_data = json.loads(data_str)
                                choices = chunk_data.get("choices", [])
                                if choices:
                                    delta = choices[0].get("delta", {})
                                    content_str = delta.get("content")
                                    if content_str:
                                        emitted = stream_hydrator.process_chunk(content_str)
                                        if emitted:
                                            delta["content"] = emitted
                                            yield f"data: {json.dumps(chunk_data)}\n\n"
                                        # If emitted is empty, it was held back in buffer
                                    else:
                                        # Non-content delta (e.g. role or finish_reason)
                                        yield f"data: {json.dumps(chunk_data)}\n\n"
                                else:
                                    yield f"data: {json.dumps(chunk_data)}\n\n"
                            except json.JSONDecodeError:
                                yield f"{raw_line}\n\n"
                        else:
                            yield f"{raw_line}\n"

            return StreamingResponse(sse_event_stream(), media_type="text/event-stream")

    return app
