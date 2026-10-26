"""
End-to-end integration tests for transparent MCP stdio proxy.
"""

from __future__ import annotations

import io
import json
import sys
import pytest

from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.mcp_proxy import run_mcp_stdio_proxy


def test_mcp_stdio_proxy_round_trip() -> None:
    """Test full MCP stdio proxy with real subprocess execution and bidirectional conversion."""
    vault = ShadowVault()
    session_id = "sess_mcp_stdio_test"

    real_card = "4532 0151 1283 0366"
    real_email = "alice@example.com"

    # Pre-register real card in session mappings
    synthetic_card = vault.dehydrate(real_card, session_id=session_id)
    assert synthetic_card != real_card

    # Python child script acting as downstream MCP tool server
    # It verifies it receives the REAL card, and returns a receipt containing the REAL email
    child_script = (
        "import sys, json\n"
        "line = sys.stdin.readline()\n"
        "req = json.loads(line)\n"
        "args = req['params']['arguments']\n"
        "# Verify downstream received hydrated REAL card\n"
        "assert '4532' in args['card'], f'Expected real card, got {args[\"card\"]}'\n"
        "resp = {\n"
        "    'jsonrpc': '2.0',\n"
        "    'id': req['id'],\n"
        "    'result': {\n"
        "        'content': [{'type': 'text', 'text': f'Charged {args[\"card\"]} for user alice@example.com'}]\n"
        "    }\n"
        "}\n"
        "sys.stdout.write(json.dumps(resp) + '\\n')\n"
        "sys.stdout.flush()\n"
    )

    client_mcp_request = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {
            "name": "charge_customer",
            "arguments": {
                "card": synthetic_card,
            },
        },
    }

    stdin_buf = io.StringIO(json.dumps(client_mcp_request) + "\n")
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    exit_code = run_mcp_stdio_proxy(
        downstream_command=[sys.executable, "-c", child_script],
        vault=vault,
        session_id=session_id,
        stdin_stream=stdin_buf,
        stdout_stream=stdout_buf,
        stderr_stream=stderr_buf,
    )

    assert exit_code == 0, f"Child failed with stderr: {stderr_buf.getvalue()}"

    # Verify client received response where alice@example.com has been DEHYDRATED to synthetic token
    output_lines = stdout_buf.getvalue().strip().split("\n")
    assert len(output_lines) == 1

    resp = json.loads(output_lines[0])
    text_result = resp["result"]["content"][0]["text"]

    assert "alice@example.com" not in text_result
    assert "@shadow.vault" in text_result
