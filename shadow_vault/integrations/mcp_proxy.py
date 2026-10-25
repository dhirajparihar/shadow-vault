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
        real PII before passing to the tool server.

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
                hydrated_args = self.vault.hydrate(params["arguments"], session_id=session_id)
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
