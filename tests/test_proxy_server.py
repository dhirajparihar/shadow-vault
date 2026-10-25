"""
Unit tests for create_proxy_app (OpenAI-compatible FastAPI proxy server).
"""

from __future__ import annotations

import json
from typing import AsyncIterator
import httpx
import pytest
from starlette.testclient import TestClient

from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.proxy_server import create_proxy_app
from shadow_vault.synthesizer import is_synthetic


def test_proxy_health_endpoint() -> None:
    """Test /health endpoint."""
    vault = ShadowVault()
    app = create_proxy_app(vault=vault)
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "shadow-vault-proxy"}
    vault.close()


@pytest.mark.asyncio
async def test_proxy_non_streaming_chat_completions() -> None:
    """Test non-streaming /v1/chat/completions dehydrates prompt and hydrates response."""
    vault = ShadowVault()
    session_id = "sess_proxy_non_stream"

    real_email = "alice@example.com"
    real_card = "4532 0151 1283 0366"
    # Pre-register real_card so it can be hydrated on response
    synth_card = vault.dehydrate(real_card, session_id=session_id)
    assert is_synthetic(synth_card)

    received_upstream_body: dict = {}

    def mock_upstream(request: httpx.Request) -> httpx.Response:
        nonlocal received_upstream_body
        received_upstream_body = json.loads(request.read())
        # Upstream mock responds with synthetic card
        upstream_response_data = {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Confirmed booking. Charged card {synth_card}.",
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        return httpx.Response(200, json=upstream_response_data)

    transport = httpx.MockTransport(mock_upstream)
    async_mock_client = httpx.AsyncClient(transport=transport)

    app = create_proxy_app(
        vault=vault,
        upstream_base_url="https://api.openai.com/v1",
        http_client=async_mock_client,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as test_client:
        client_payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": f"My email is {real_email}. Book the ticket."}
            ],
            "stream": False,
        }

        resp = await test_client.post(
            "/v1/chat/completions",
            json=client_payload,
            headers={"X-Session-ID": session_id, "Authorization": "Bearer fake_token"},
        )

        assert resp.status_code == 200
        resp_json = resp.json()

        # 1. Verify upstream received dehydrated prompt
        sent_messages = received_upstream_body["messages"]
        assert real_email not in sent_messages[0]["content"]
        assert "@shadow.vault" in sent_messages[0]["content"]

        # 2. Verify client response received hydrated card
        assistant_content = resp_json["choices"][0]["message"]["content"]
        assert real_card in assistant_content
        assert synth_card not in assistant_content
        assert assistant_content == f"Confirmed booking. Charged card {real_card}."

    vault.close()


@pytest.mark.asyncio
async def test_proxy_streaming_chat_completions_sse() -> None:
    """Test streaming SSE /v1/chat/completions re-hydrates split tokens in real time."""
    vault = ShadowVault()
    session_id = "sess_proxy_stream"

    real_email = "bob@example.com"
    synth_email = vault.dehydrate(real_email, session_id=session_id)
    assert is_synthetic(synth_email)

    # Intentionally split synthetic email across SSE chunk boundaries
    chunk_p1 = synth_email[:6]
    chunk_p2 = synth_email[6:15]
    chunk_p3 = synth_email[15:]

    sse_lines = [
        f'data: {{"choices": [{{"delta": {{"content": "Your email is "}}}}]}}\n\n',
        f'data: {{"choices": [{{"delta": {{"content": "{chunk_p1}"}}}}]}}\n\n',
        f'data: {{"choices": [{{"delta": {{"content": "{chunk_p2}"}}}}]}}\n\n',
        f'data: {{"choices": [{{"delta": {{"content": "{chunk_p3}."}}}}]}}\n\n',
        "data: [DONE]\n\n",
    ]

    def mock_upstream_stream(request: httpx.Request) -> httpx.Response:
        raw_sse = "".join(sse_lines).encode("utf-8")
        return httpx.Response(
            200,
            content=raw_sse,
            headers={"content-type": "text/event-stream"},
        )

    transport = httpx.MockTransport(mock_upstream_stream)
    async_mock_client = httpx.AsyncClient(transport=transport)

    app = create_proxy_app(
        vault=vault,
        upstream_base_url="https://api.openai.com/v1",
        http_client=async_mock_client,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as test_client:
        client_payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "What is my email?"}],
            "stream": True,
        }

        resp = await test_client.post(
            "/v1/chat/completions",
            json=client_payload,
            headers={"X-Session-ID": session_id},
        )

        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]

        # Parse client-received SSE chunks
        emitted_deltas: list[str] = []
        for line in resp.text.split("\n"):
            if line.startswith("data: "):
                payload_str = line[6:].strip()
                if payload_str == "[DONE]":
                    break
                chunk_obj = json.loads(payload_str)
                delta_c = chunk_obj["choices"][0]["delta"].get("content", "")
                if delta_c:
                    emitted_deltas.append(delta_c)

        reconstructed_text = "".join(emitted_deltas)
        assert real_email in reconstructed_text
        assert synth_email not in reconstructed_text
        assert reconstructed_text == f"Your email is {real_email}."

    vault.close()
