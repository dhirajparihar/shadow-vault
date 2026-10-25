"""
Unit tests for MCPVaultInterceptor (Model Context Protocol JSON-RPC).
"""

from __future__ import annotations

import json
import pytest

from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.mcp_proxy import MCPVaultInterceptor
from shadow_vault.synthesizer import is_synthetic


def test_mcp_intercept_tool_call_request() -> None:
    """Test intercepting MCP tools/call request hydrates arguments."""
    vault = ShadowVault()
    session_id = "sess_mcp"

    real_email = "alice@example.com"
    synth_email = vault.dehydrate(real_email, session_id=session_id)
    assert is_synthetic(synth_email)

    interceptor = MCPVaultInterceptor(vault=vault)

    mcp_request = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {
            "name": "lookup_account",
            "arguments": {
                "account_email": synth_email,
                "scope": "read",
            },
        },
    }

    modified_req = interceptor.intercept_request(mcp_request, session_id=session_id)

    # Arguments must be hydrated to real email before tool server execution
    assert modified_req["params"]["arguments"]["account_email"] == real_email
    assert modified_req["params"]["arguments"]["scope"] == "read"
    assert modified_req["id"] == "req-1"

    vault.close()


def test_mcp_intercept_tool_call_response() -> None:
    """Test intercepting MCP tool call response dehydrates content blocks."""
    vault = ShadowVault()
    session_id = "sess_mcp_resp"

    interceptor = MCPVaultInterceptor(vault=vault)

    mcp_response = {
        "jsonrpc": "2.0",
        "id": "resp-1",
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "Found record for bob@example.com. Card on file: 4532 0151 1283 0366.",
                }
            ],
            "isError": False,
        },
    }

    modified_resp = interceptor.intercept_response(mcp_response, session_id=session_id)

    content_text = modified_resp["result"]["content"][0]["text"]
    assert "bob@example.com" not in content_text
    assert "4532 0151 1283 0366" not in content_text
    assert "@shadow.vault" in content_text
    assert "400000999" in content_text

    # Verify hydration restores exact original content
    restored = vault.hydrate(content_text, session_id=session_id)
    assert restored == "Found record for bob@example.com. Card on file: 4532 0151 1283 0366."

    vault.close()


def test_mcp_intercept_non_tool_call_passthrough() -> None:
    """Test non-tool-call MCP messages pass through without modification."""
    vault = ShadowVault()
    interceptor = MCPVaultInterceptor(vault=vault)

    init_req = {
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {"clientInfo": {"name": "test-client", "version": "1.0"}},
    }
    assert interceptor.intercept_request(init_req) == init_req

    tools_list = {
        "jsonrpc": "2.0",
        "id": "list-1",
        "result": {"tools": [{"name": "calculator"}]},
    }
    assert interceptor.intercept_response(tools_list) == tools_list

    vault.close()


def test_mcp_intercept_json_string() -> None:
    """Test intercept_json handles serialized JSON-RPC strings."""
    vault = ShadowVault()
    session_id = "sess_json"

    real_phone = "+91 9876543210"
    synth_phone = vault.dehydrate(real_phone, session_id=session_id)

    interceptor = MCPVaultInterceptor(vault=vault)

    req_str = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "send_sms",
                "arguments": {"target": synth_phone},
            },
        }
    )

    modified_json = interceptor.intercept_json(req_str, session_id=session_id)
    data = json.loads(modified_json)
    assert data["params"]["arguments"]["target"] == real_phone

    vault.close()
