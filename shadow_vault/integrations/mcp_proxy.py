"""
Model Context Protocol (MCP) JSON-RPC proxy interceptor for tools/call.
"""

from __future__ import annotations

import json
from typing import Any
from shadow_vault.engine import ShadowVault


class MCPVaultInterceptor:
    """Interceptors for MCP (Model Context Protocol) JSON-RPC tool calls.

    Hydrates incoming tool arguments before they reach an MCP tool server,
    and dehydrates tool response content before returning to the model.
    """

    def __init__(self, vault: ShadowVault) -> None:
        """Initialize MCPVaultInterceptor.

        Args:
            vault: ShadowVault instance managing session PII mappings.
        """
        self.vault = vault

    def intercept_request(
        self,
        request: dict[str, Any],
        session_id: str = "default",
    ) -> dict[str, Any]:
        """Intercept an MCP JSON-RPC request.

        If method is 'tools/call', hydrates the arguments dictionary to restore
        real PII before passing to the tool server (subject to ToolPolicy).

        Args:
            request: MCP JSON-RPC request dictionary.
            session_id: Target session identifier.

        Returns:
            Request dictionary with hydrated tool arguments.
        """
        if not isinstance(request, dict):
            return request

        method = request.get("method")
        if method == "tools/call":
            params = request.get("params")
            if isinstance(params, dict) and "arguments" in params:
                tool_name = params.get("name")
                hydrated_args = self.vault.hydrate(
                    params["arguments"],
                    session_id=session_id,
                    tool_name=tool_name,
                )
                params_copy = dict(params)
                params_copy["arguments"] = hydrated_args
                req_copy = dict(request)
                req_copy["params"] = params_copy
                return req_copy

        return request

    def intercept_response(
        self,
        response: dict[str, Any],
        session_id: str = "default",
    ) -> dict[str, Any]:
        """Intercept an MCP JSON-RPC response.

        Dehydrates result content (text, JSON blobs) before it reaches the model.

        Args:
            response: MCP JSON-RPC response dictionary.
            session_id: Target session identifier.

        Returns:
            Response dictionary with dehydrated content blocks.
        """
        if not isinstance(response, dict):
            return response

        result = response.get("result")
        if isinstance(result, dict) and "content" in result:
            content = result["content"]
            result_copy = dict(result)

            if isinstance(content, list):
                result_copy["content"] = [
                    self._dehydrate_content_block(block, session_id) for block in content
                ]
            else:
                result_copy["content"] = self.vault.dehydrate(content, session_id=session_id)

            resp_copy = dict(response)
            resp_copy["result"] = result_copy
            return resp_copy

        return response

    def _dehydrate_content_block(self, block: Any, session_id: str) -> Any:
        """Dehydrate a single MCP content block (e.g. text or resource)."""
        if isinstance(block, dict):
            block_copy = dict(block)
            b_type = block_copy.get("type")
            if b_type == "text" and "text" in block_copy:
                block_copy["text"] = self.vault.dehydrate(block_copy["text"], session_id=session_id)
                return block_copy
            elif b_type == "resource" and "resource" in block_copy:
                block_copy["resource"] = self.vault.dehydrate(
                    block_copy["resource"], session_id=session_id
                )
                return block_copy
            else:
                return self.vault.dehydrate(block_copy, session_id=session_id)

        return self.vault.dehydrate(block, session_id=session_id)

    def intercept_message(
        self,
        message: dict[str, Any],
        session_id: str = "default",
    ) -> dict[str, Any]:
        """Intercept an arbitrary MCP JSON-RPC message (auto-routing request vs response)."""
        if "method" in message:
            return self.intercept_request(message, session_id=session_id)
        elif "result" in message:
            return self.intercept_response(message, session_id=session_id)
        return message

    def intercept_json(self, json_str: str, session_id: str = "default") -> str:
        """Intercept a JSON string message and return the modified JSON string."""
        data = json.loads(json_str)
        modified = self.intercept_message(data, session_id=session_id)
        return json.dumps(modified)


import subprocess
import sys
import threading
from typing import TextIO


def run_mcp_stdio_proxy(
    downstream_command: list[str],
    vault: ShadowVault | None = None,
    session_id: str = "default",
    stdin_stream: TextIO | None = None,
    stdout_stream: TextIO | None = None,
    stderr_stream: TextIO | None = None,
) -> int:
    """Run a transparent Model Context Protocol (MCP) stdio gateway.

    Spawns downstream MCP server command as a subprocess, intercepting JSON-RPC
    stdio communication:
    - Client -> Downstream: restores real PII for 'tools/call' arguments.
    - Downstream -> Client: dehydrates results before sending back to LLM agent.

    Args:
        downstream_command: Command line arguments to spawn the real MCP server.
        vault: Optional ShadowVault instance (creates default instance if omitted).
        session_id: Session identifier for scoping PII mappings.
        stdin_stream: Stream providing client JSON-RPC input (defaults to sys.stdin).
        stdout_stream: Stream sending responses to client (defaults to sys.stdout).
        stderr_stream: Stream forwarding downstream error logs (defaults to sys.stderr).

    Returns:
        Process exit code of the downstream MCP server.
    """
    if vault is None:
        vault = ShadowVault()

    interceptor = MCPVaultInterceptor(vault)
    in_stream = stdin_stream or sys.stdin
    out_stream = stdout_stream or sys.stdout
    err_stream = stderr_stream or sys.stderr

    process = subprocess.Popen(
        downstream_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # Line buffered
    )

    def forward_stdin() -> None:
        try:
            for line in iter(in_stream.readline, ""):
                if not line:
                    break
                trimmed = line.strip()
                if trimmed:
                    try:
                        modified_line = interceptor.intercept_json(trimmed, session_id=session_id)
                        process.stdin.write(modified_line + "\n")  # type: ignore[union-attr]
                    except Exception:
                        process.stdin.write(line)  # type: ignore[union-attr]
                else:
                    process.stdin.write(line)  # type: ignore[union-attr]
                process.stdin.flush()  # type: ignore[union-attr]
        except Exception:
            pass
        finally:
            try:
                process.stdin.close()  # type: ignore[union-attr]
            except Exception:
                pass

    def forward_stdout() -> None:
        try:
            for line in iter(process.stdout.readline, ""):  # type: ignore[union-attr]
                if not line:
                    break
                trimmed = line.strip()
                if trimmed:
                    try:
                        modified_line = interceptor.intercept_json(trimmed, session_id=session_id)
                        out_stream.write(modified_line + "\n")
                    except Exception as exc:
                        if vault.fail_closed:
                            err_resp = {
                                "jsonrpc": "2.0",
                                "id": None,
                                "error": {
                                    "code": -32603,
                                    "message": f"ShadowVault fail-closed policy blocked response: {exc}",
                                },
                            }
                            out_stream.write(json.dumps(err_resp) + "\n")
                        else:
                            out_stream.write(line)
                else:
                    out_stream.write(line)
                out_stream.flush()
        except Exception:
            pass

    def forward_stderr() -> None:
        try:
            for line in iter(process.stderr.readline, ""):  # type: ignore[union-attr]
                if not line:
                    break
                err_stream.write(line)
                err_stream.flush()
        except Exception:
            pass

    t_in = threading.Thread(target=forward_stdin, daemon=True)
    t_out = threading.Thread(target=forward_stdout, daemon=True)
    t_err = threading.Thread(target=forward_stderr, daemon=True)

    t_in.start()
    t_out.start()
    t_err.start()

    exit_code = process.wait()
    t_out.join(timeout=1.0)
    t_err.join(timeout=1.0)

    return exit_code

