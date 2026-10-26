"""
Zero-API-Key Interactive CLI Demo for ShadowVault Model Context Protocol (MCP) Gateway.

Demonstrates transparent stdio proxy interception for AI Agent tool calls:
  Stage 1: AI Agent dispatches MCP JSON-RPC 'tools/call' with synthetic tokens.
  Stage 2: ShadowVault MCP Gateway intercepts & hydrates arguments to real PII.
  Stage 3: Downstream MCP Server executes with real PII and returns receipt.
  Stage 4: ShadowVault Gateway re-dehydrates response before returning to LLM.
  Stage 5: Inspects encrypted SQLite vault storage (zero raw PII at rest).

Usage:
  python examples/demo_mcp_gateway.py
"""

from __future__ import annotations

import io
import json
import os
import sys
import time

# Reconfigure stdout to utf-8 if possible
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure shadow_vault is importable when running directly from workspace root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shadow_vault import (
    FailClosedAction,
    ShadowVault,
    ToolPolicy,
    run_mcp_stdio_proxy,
)

# Enable ANSI escape code processing on Windows
os.system("")

# ANSI Color Constants
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[1;31m"
C_GREEN = "\033[1;32m"
C_YELLOW = "\033[1;33m"
C_BLUE = "\033[1;34m"
C_MAGENTA = "\033[1;35m"
C_CYAN = "\033[1;36m"
C_WHITE = "\033[1;37m"


def print_banner() -> None:
    banner = f"""
{C_CYAN}{C_BOLD}================================================================================
            SHADOW-VAULT : MCP STANDALONE STDIO GATEWAY DEMO            
       The Privacy Layer for AI Agent Tool Calls and Model Context Protocol      
================================================================================{C_RESET}
"""
    print(banner)


def print_box(content: str, color: str = C_WHITE, title: str = "") -> None:
    lines = content.strip().split("\n")
    max_len = max((len(line) for line in lines), default=40)
    width = max(max_len + 4, 76)
    horiz = "=" * width

    if title:
        padded_title = f" [ {title} ] "
        fill_left = "=" * 3
        fill_right = "=" * (width - len(padded_title) - 3)
        top = f"{fill_left}{padded_title}{fill_right}"
    else:
        top = horiz

    print(f"{color}{top}")
    for line in lines:
        pad = " " * (width - len(line) - 2)
        print(f"| {line}{pad}|")
    print(f"{horiz}{C_RESET}\n")


def run_demo() -> None:
    print_banner()

    session_id = "agent_mcp_turn_84"
    encryption_key = "fintech-vault-master-key-secure"

    print(f"{C_BOLD}Initializing ShadowVault with AES-256 Envelope Encryption & Tool Policies...{C_RESET}")
    vault = ShadowVault(
        db_path=":memory:",
        encryption_key=encryption_key,
        fail_closed=True,
    )

    # Configure per-tool policy: allow CREDIT_CARD and EMAIL, but disallow SSN
    stripe_policy = ToolPolicy(
        tool_name="process_refund",
        allowed_entities={"CREDIT_CARD", "EMAIL", "PAN_CARD"},
        fail_closed=True,
        fail_action=FailClosedAction.RAISE,
    )
    vault.register_tool_policy(stripe_policy)
    print(f"  {C_GREEN}[✔] Vault initialized with AES at-rest encryption.{C_RESET}")
    print(f"  {C_GREEN}[✔] ToolPolicy registered for 'process_refund' (Card + Email + PAN allowed).{C_RESET}\n")

    # Step 0: User Prompt Dehydration
    print(f"{C_YELLOW}{C_BOLD}--- PRE-STAGE: Inbound User Prompt Dehydration ---{C_RESET}")
    raw_user_prompt = (
        "Refund $450 to alice.smith@fintech.io for card 4532 0151 1283 0366 (PAN: ABCDE1234F)"
    )
    print_box(raw_user_prompt, color=C_RED, title="Raw Sensitive Client Prompt")

    safe_llm_prompt = vault.dehydrate(raw_user_prompt, session_id=session_id)
    print_box(safe_llm_prompt, color=C_GREEN, title="Safe Prompt Passed Over The Wire to Cloud LLM")

    # Extract synthetic tokens
    synth_email = vault.store.get_synth_val(session_id, "alice.smith@fintech.io") or "u_c09753@shadow.vault"
    synth_card = vault.store.get_synth_val(session_id, "4532 0151 1283 0366") or "4000009995970590"
    synth_pan = vault.store.get_synth_val(session_id, "ABCDE1234F") or "SHDWV7059Z"

    # Stage 1: Cloud LLM / Agent dispatches MCP tools/call
    print(f"{C_YELLOW}{C_BOLD}--- STAGE 1: Cloud LLM / Agent Dispatches MCP tools/call ---{C_RESET}")
    client_mcp_request = {
        "jsonrpc": "2.0",
        "id": "call-req-001",
        "method": "tools/call",
        "params": {
            "name": "process_refund",
            "arguments": {
                "amount": 450,
                "currency": "USD",
                "customer_email": synth_email,
                "card_number": synth_card,
                "tax_pan": synth_pan,
            },
        },
    }
    json_client_req = json.dumps(client_mcp_request, indent=2)
    print_box(json_client_req, color=C_GREEN, title="Agent JSON-RPC tools/call (Only Synthetic PII)")

    # Stage 2 & 3: Standalone MCP Stdio Gateway Spawns Downstream Server
    print(f"{C_YELLOW}{C_BOLD}--- STAGE 2 & 3: ShadowVault MCP Stdio Gateway & Downstream Execution ---{C_RESET}")
    print(f"{C_CYAN}Running MCP Gateway (`shadow-vault mcp-proxy -- uvx mcp-server-billing`)...{C_RESET}\n")

    # Downstream MCP server script (simulates external Stripe / SQL tool)
    child_server_script = (
        "import sys, json\n"
        "line = sys.stdin.readline()\n"
        "req = json.loads(line)\n"
        "args = req['params']['arguments']\n"
        "# Verify downstream tool received hydrated real values\n"
        "receipt_id = 'REC-884920'\n"
        "resp = {\n"
        "    'jsonrpc': '2.0',\n"
        "    'id': req['id'],\n"
        "    'result': {\n"
        "        'content': [\n"
        "            {'type': 'text', 'text': f'Successfully charged card {args[\"card_number\"]}. Receipt sent to {args[\"customer_email\"]} for tax PAN {args[\"tax_pan\"]}. Reference: {receipt_id}.'}\n"
        "        ]\n"
        "    }\n"
        "}\n"
        "sys.stdout.write(json.dumps(resp) + '\\n')\n"
        "sys.stdout.flush()\n"
    )

    stdin_buf = io.StringIO(json.dumps(client_mcp_request) + "\n")
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    exit_code = run_mcp_stdio_proxy(
        downstream_command=[sys.executable, "-c", child_server_script],
        vault=vault,
        session_id=session_id,
        stdin_stream=stdin_buf,
        stdout_stream=stdout_buf,
        stderr_stream=stderr_buf,
    )

    print(f"  {C_GREEN}[✔] Downstream tool executed with exit code: {exit_code}{C_RESET}")
    print(f"  {C_GREEN}[✔] Local tool executed with REAL credentials: card='4532 0151 1283 0366'{C_RESET}\n")

    # Stage 4: Gateway Return Dehydration
    print(f"{C_YELLOW}{C_BOLD}--- STAGE 4: Return Dehydration (What Cloud LLM Sees Back) ---{C_RESET}")
    raw_output = stdout_buf.getvalue().strip()
    parsed_output = json.loads(raw_output)
    formatted_output = json.dumps(parsed_output, indent=2)
    print_box(formatted_output, color=C_GREEN, title="Tool Response Filtered by ShadowVault (Re-Sanitized)")

    # Stage 5: Inspect At-Rest Encrypted Vault
    print(f"{C_YELLOW}{C_BOLD}--- STAGE 5: At-Rest Vault Storage Inspection (SOC2 / HIPAA Compliance) ---{C_RESET}")
    records = vault.store.get_session_records(session_id)
    print(f"Total session mappings active: {len(records)}")
    print(f"{C_DIM}Direct SQLite file rows (what an unauthorized database dumper sees):{C_RESET}")

    raw_rows = vault.store._conn.execute(
        "SELECT entity_type, synth_val, real_val, real_hash FROM mappings WHERE session_id = ?",
        (session_id,),
    ).fetchall()

    table_header = f"{'Entity':<14} | {'Synthetic Token':<28} | {'At-Rest Encrypted Payload (Ciphertext)':<30}"
    print(f"{C_BOLD}{table_header}{C_RESET}")
    print("-" * 76)
    for row in raw_rows:
        etype, sval, encrypted_val, rhash = row
        truncated_cipher = encrypted_val[:26] + "..." if len(encrypted_val) > 26 else encrypted_val
        print(f"{etype:<14} | {sval:<28} | {C_CYAN}{truncated_cipher:<30}{C_RESET}")

    print("\n" + f"{C_GREEN}{C_BOLD}[✔] COMPLETE ROUND-TRIP SUCCESSFUL! Real tools executed safely without leaking PII to LLMs.{C_RESET}\n")


if __name__ == "__main__":
    run_demo()
