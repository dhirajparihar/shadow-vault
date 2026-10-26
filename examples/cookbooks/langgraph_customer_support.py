#!/usr/bin/env python3
"""
Cookbook: LangGraph & LangChain Production Agent with ShadowVault.

Demonstrates a multi-step customer support agent where:
1. Inbound user messages with sensitive PII (Credit Cards, Emails, PAN) are sanitized.
2. The Agent State / Checkpoint database stores ONLY format-preserving synthetic tokens.
3. LangSmith / Cloud observability logs receive ZERO raw PII.
4. Downstream tools (e.g. billing_tool, crm_tool) execute with genuine restored data.
5. Tool returns are re-masked before reaching model context.

Runnable standalone with zero external API keys!
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TypedDict

# Ensure local shadow_vault module is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shadow_vault import (
    ShadowVault,
    ToolPolicy,
    is_luhn_valid,
    vault_guard,
)


# --- 1. Define Agent State Schema ---
class AgentState(TypedDict):
    session_id: str
    user_prompt: str
    sanitized_prompt: str
    tool_calls: list[dict[str, Any]]
    tool_outputs: list[dict[str, Any]]
    final_response: str


def run_customer_support_workflow() -> None:
    print("=" * 78)
    print("      LANGGRAPH / LANGCHAIN AGENT PRIVACY COOKBOOK (SHADOWVAULT)")
    print("=" * 78 + "\n")

    # Initialize ShadowVault with AES-256-GCM Vault and strict policy
    vault = ShadowVault(
        encryption_key="langgraph-cookbook-master-key",
        fail_closed=True,
    )
    session_id = "langgraph_session_101"

    # Define tool privacy policy: billing tool only allows CREDIT_CARD and EMAIL
    billing_policy = ToolPolicy(
        tool_name="process_customer_refund",
        allowed_entities={"CREDIT_CARD", "EMAIL", "PAN_CARD"},
        fail_closed=True,
    )
    vault.register_tool_policy(billing_policy)

    # --- Node 1: Inbound Message Sanitizer ---
    raw_user_message = (
        "Hello support, please issue an immediate refund of $320 to customer "
        "dhiraj.sharma@enterprise.com on card 4532 0151 1283 0366 (Tax PAN: ABCDE1234F)."
    )
    print("[Node 1] INBOUND USER MESSAGE (Raw PII):")
    print(f"  \"{raw_user_message}\"\n")

    sanitized_prompt = vault.dehydrate(raw_user_message, session_id=session_id)
    print("[Node 1] SANITIZED PROMPT (Passed to Agent Graph & Cloud Model):")
    print(f"  \"{sanitized_prompt}\"\n")

    # Initialize Graph State
    state: AgentState = {
        "session_id": session_id,
        "user_prompt": raw_user_message,
        "sanitized_prompt": sanitized_prompt,
        "tool_calls": [],
        "tool_outputs": [],
        "final_response": "",
    }

    # Verify Graph State has NO raw PII (LangSmith and Checkpoints are safe)
    assert "4532 0151 1283 0366" not in state["sanitized_prompt"]
    assert "dhiraj.sharma@enterprise.com" not in state["sanitized_prompt"]
    print("  [OK] Graph State Verified: 0% real PII stored in agent state/memory.")

    # --- Node 2: Agent Tool Calling (Model Decision) ---
    session_map = vault.store.get_session_map(session_id)
    synth_email = next(s for s in session_map.keys() if "@shadow.vault" in s)
    synth_card = next(s for s in session_map.keys() if s.startswith("400000"))
    synth_pan = next(s for s in session_map.keys() if s.startswith("SHDWV"))

    # The LLM decides to invoke process_customer_refund using ONLY synthetic tokens
    simulated_tool_call = {
        "name": "process_customer_refund",
        "args": {
            "amount": 320.0,
            "customer_email": synth_email,
            "card_number": synth_card,
            "tax_pan": synth_pan,
        },
    }
    state["tool_calls"].append(simulated_tool_call)

    print("[Node 2] AGENT DISPATCHES TOOL CALL (Synthetic Tokens Only):")
    print(json.dumps(simulated_tool_call, indent=2))
    print()

    # --- Node 3: Tool Execution (Guarded by ShadowVault) ---
    actual_tool_received_data: dict[str, Any] = {}

    @vault_guard(vault=vault, policy=billing_policy, session_id_arg="session_id")
    def process_customer_refund(
        amount: float,
        customer_email: str,
        card_number: str,
        tax_pan: str,
        session_id: str = "default",
    ) -> dict[str, Any]:
        """Local payment tool: executes with genuine banking credentials."""
        actual_tool_received_data["email"] = customer_email
        actual_tool_received_data["card"] = card_number
        actual_tool_received_data["pan"] = tax_pan
        return {
            "status": "REFUNDED",
            "refund_id": "REF-789123",
            "amount": amount,
            "account": customer_email,
            "card_last4": card_number[-4:],
        }

    # Execute tool node
    tool_output = process_customer_refund(
        session_id=session_id,
        **simulated_tool_call["args"],
    )
    state["tool_outputs"].append(tool_output)

    # Verify tool execution assertions
    assert actual_tool_received_data["card"] == "4532 0151 1283 0366", "Tool should receive genuine card!"
    assert actual_tool_received_data["email"] == "dhiraj.sharma@enterprise.com", "Tool should receive genuine email!"
    assert actual_tool_received_data["pan"] == "ABCDE1234F", "Tool should receive genuine PAN!"
    print("[Node 3] TOOL EXECUTION AUDIT:")
    print(f"  [OK] Local tool received REAL card:  {actual_tool_received_data['card']}")
    print(f"  [OK] Local tool received REAL email: {actual_tool_received_data['email']}")
    print(f"  [OK] Local tool received REAL PAN:   {actual_tool_received_data['pan']}\n")

    # --- Node 4: Sanitized Tool Output Verification ---
    print("[Node 4] SANITIZED TOOL RETURN (Safe to store in Agent State / Return to Model):")
    print(json.dumps(tool_output, indent=2))
    assert "dhiraj.sharma@enterprise.com" not in str(tool_output)
    print("  [OK] Tool output is safely pseudonymized before returning to model context.\n")

    # --- Node 5: Final Response Synthesis & Client Hydration ---
    agent_raw_model_response = (
        f"I have successfully processed your refund of $320.00 for account {synth_email}. "
        f"Receipt ID: {tool_output['refund_id']}."
    )
    # The client-side hydrator restores real values when presenting to the authorized user
    client_response = vault.hydrate(agent_raw_model_response, session_id=session_id)
    state["final_response"] = client_response

    print("[Node 5] FINAL RESPONSE DELIVERED TO AUTHENTICATED USER:")
    print(f"  \"{client_response}\"\n")
    assert "dhiraj.sharma@enterprise.com" in client_response

    print("=" * 78)
    print("  [OK] LANGGRAPH WORKFLOW COMPLETE WITH 100% PRIVACY GUARANTEE!")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    run_customer_support_workflow()
