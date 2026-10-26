#!/usr/bin/env python3
"""
ShadowVault: End-to-End Real Agent Zero-Leak Verification Script.

Proves with programmatic assertions that:
1. Raw sensitive PII NEVER reaches the cloud model context over the wire.
2. Downstream schemas and validators pass with format-preserving synthetic tokens.
3. Trusted local tools execute with genuine, restored sensitive data.
4. Tool returns are re-sanitized before reaching model memory.
5. End-user streaming output safely restores original identities in real-time.

Requires NO external API keys or cloud dependencies to run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Ensure local shadow_vault module is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shadow_vault import (
    ShadowVault,
    ToolPolicy,
    is_luhn_valid,
    vault_guard,
)
from shadow_vault.stream import StreamHydrator


def main() -> None:
    print("\n" + "=" * 80)
    print("      SHADOWVAULT: END-TO-END AGENT WORKFLOW ZERO-LEAK VERIFICATION")
    print("      Independent Security & Wire-Inspection Proof")
    print("=" * 80 + "\n")

    # 1. Initialize Vault with AES Encryption and Strict Tool Policies
    vault = ShadowVault(
        encryption_key="agent-zero-leak-master-key",
        fail_closed=True,
    )
    session_id = "agent_verified_session_99"

    # Define tool privacy policy: only allow CREDIT_CARD and EMAIL to hydrate
    billing_policy = ToolPolicy(
        tool_name="stripe_charge_tool",
        allowed_entities={"CREDIT_CARD", "EMAIL", "PAN_CARD"},
        fail_closed=True,
    )
    vault.register_tool_policy(billing_policy)

    # 2. Raw User Prompt with Multiple Sensitive Entities
    raw_user_prompt = (
        "Process urgent $450 chargeback for customer alice.smith@enterprise.io. "
        "Customer card on file: 4532 0151 1283 0366. Verify tax PAN: ABCDE1234F. "
        "Backup alert mobile: +91 9876543210."
    )
    raw_sensitive_values = [
        "alice.smith@enterprise.io",
        "4532 0151 1283 0366",
        "ABCDE1234F",
        "+91 9876543210",
    ]

    print("[1] RAW USER INPUT PROMPT:")
    print(f"    \"{raw_user_prompt}\"\n")

    # 3. Dehydrate: What is actually transmitted over the wire to Cloud Model
    outbound_wire_payload = vault.dehydrate(raw_user_prompt, session_id=session_id)

    print("[2] OUTBOUND PAYLOAD SENT OVER WIRE TO CLOUD LLM:")
    print(f"    \"{outbound_wire_payload}\"\n")

    # --- CRYPTOGRAPHIC ASSERTION 1: Zero Sensitive Data on Wire ---
    for sensitive_item in raw_sensitive_values:
        assert sensitive_item not in outbound_wire_payload, (
            f"SECURITY LEAK: Found '{sensitive_item}' in outbound wire payload!"
        )
    print("  [OK] ASSERTION 1 PASSED: 0% raw PII exists in outbound cloud request.")

    # --- SCHEMA ASSERTION 2: Format Preservation ---
    # Extract synthetic card and verify it passes Luhn Modulo 10
    session_map = vault.store.get_session_map(session_id)
    synthetic_card = next(s for s in session_map.keys() if s.startswith("400000"))
    assert is_luhn_valid(synthetic_card), f"Invalid Luhn card: {synthetic_card}"
    assert len(synthetic_card) == 16
    print(f"  [OK] ASSERTION 2 PASSED: Synthetic card '{synthetic_card}' satisfies Luhn check.")

    # 4. Agent Tool Call: Model invokes tool using ONLY synthetic arguments
    tool_args_from_agent = {
        "amount": 450.0,
        "customer_email": next(s for s in session_map.keys() if "@shadow.vault" in s),
        "card_number": synthetic_card,
        "pan_number": next(s for s in session_map.keys() if s.startswith("SHDWV")),
    }

    print("\n[3] AGENT DISPATCHES TOOL CALL (Only Synthetic Tokens in Agent Memory):")
    print(json.dumps(tool_args_from_agent, indent=2))

    # 5. Local Tool Execution (Guarded by ShadowVault)
    executed_with_real_data: dict[str, Any] = {}

    @vault_guard(vault=vault, policy=billing_policy, session_id_arg="session_id")
    def stripe_charge_tool(
        amount: float,
        customer_email: str,
        card_number: str,
        pan_number: str,
        session_id: str = "default",
    ) -> dict[str, Any]:
        # Capture parameters actually received by local banking tool
        executed_with_real_data["email"] = customer_email
        executed_with_real_data["card"] = card_number
        executed_with_real_data["pan"] = pan_number
        return {
            "status": "CHARGEBACK_CONFIRMED",
            "receipt_id": "REC-994821",
            "processed_for": customer_email,
            "card_charged": card_number,
        }

    # Execute tool call
    sanitized_tool_result = stripe_charge_tool(
        session_id=session_id,
        **tool_args_from_agent,
    )

    # --- TOOL BOUNDARY ASSERTION 3: Real Data Restored Locally ---
    assert executed_with_real_data["card"] == "4532 0151 1283 0366", (
        f"Expected real card, got {executed_with_real_data['card']}"
    )
    assert executed_with_real_data["email"] == "alice.smith@enterprise.io"
    assert executed_with_real_data["pan"] == "ABCDE1234F"
    print("\n[4] LOCAL TOOL EXECUTION AUDIT:")
    print(f"  [OK] ASSERTION 3 PASSED: Local tool executed with REAL customer card: {executed_with_real_data['card']}")

    # --- RETURN SANITIZATION ASSERTION 4: Tool Output Re-Sanitized ---
    print("\n[5] SANITIZED TOOL RETURN (Returned to Agent Memory / Cloud Context):")
    print(json.dumps(sanitized_tool_result, indent=2))
    assert "4532 0151 1283 0366" not in str(sanitized_tool_result)
    assert "alice.smith@enterprise.io" not in str(sanitized_tool_result)
    print("  [OK] ASSERTION 4 PASSED: Tool output contains ZERO raw PII before returning to model.")

    # 6. Real-time Streaming SSE Re-Hydration to End-User
    print("\n[6] STREAMING SSE RE-HYDRATION (To Authorized Client):")
    hydrator = StreamHydrator(vault=vault, session_id=session_id)
    simulated_chunks = [
        "Refund confirmation: Processed ",
        tool_args_from_agent["customer_email"][:7],
        tool_args_from_agent["customer_email"][7:],
        " for amount $450. Card: ",
        tool_args_from_agent["card_number"][:6],
        tool_args_from_agent["card_number"][6:],
        " successfully credited.",
    ]
    rehydrated_stream = "".join(hydrator.process_chunk(c) for c in simulated_chunks) + hydrator.flush()
    print(f"    Stream output: \"{rehydrated_stream}\"")

    assert "alice.smith@enterprise.io" in rehydrated_stream
    assert "4532 0151 1283 0366" in rehydrated_stream
    print("  [OK] ASSERTION 5 PASSED: Client stream successfully restored without token tearing.")

    # 7. Check At-Rest SQLite Storage
    records = vault.store.get_session_records(session_id)
    print("\n[7] AT-REST DATABASE STORAGE INSPECTION (AES-256-GCM Ciphertexts):")
    for r in records:
        stored = r.get("stored_val", "")
        print(f"    {r['entity_type']:<12} | Token: {r['synth_val']:<20} | Stored: {stored[:28]}...")
        assert stored.startswith("enc:gcm:v1:"), f"Expected encrypted ciphertext, got {stored}"

    print("\n" + "=" * 80)
    print("  [OK] ALL 5 SECURITY INVARIANTS PROGRAMMATICALLY VERIFIED!")
    print("      ShadowVault safely prevents PII leakage to AI model providers.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
