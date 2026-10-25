"""
Phase 4 End-to-End Test Suite for shadow-vault:
1. Format-Preserving & Checksum Validation
2. Coreference Consistency & Idempotency
3. Bi-Directional Tool Call Round-Trip (@vault_guard & protect_tool)
4. Adversarial Chunked SSE Streaming (StreamHydrator)
"""

from __future__ import annotations

import re
import pytest
from langchain_core.tools import tool

from shadow_vault import (
    ShadowVault,
    StreamHydrator,
    is_luhn_valid,
    is_synthetic,
    is_verhoeff_valid,
    protect_tool,
    vault_guard,
)
from shadow_vault.detectors import calculate_verhoeff


# ============================================================================
# 1. Format-Preserving & Checksum Validation
# ============================================================================


def test_format_preserving_and_checksum_validation() -> None:
    """Verify detection, format-preserving substitution, and checksum validity."""
    vault = ShadowVault()
    session_id = "test_sess_format"

    # Known valid test entities
    real_email = "dhiraj@example.com"
    real_pan = "ABCDE1234F"
    real_upi = "dhiraj@okicici"
    real_card = "4532 0151 1283 0366"  # Valid Luhn card
    base_aadhaar = "36759834601"
    aadhaar_cd = calculate_verhoeff(base_aadhaar)  # 6
    real_aadhaar = f"{base_aadhaar[:4]} {base_aadhaar[4:8]} {base_aadhaar[8:]}{aadhaar_cd}"
    real_ssn = "219-45-7890"  # Valid US SSN
    real_phone = "+91 9876543210"
    real_api_key = "sk-abcdef1234567890abcdef123456"

    # Random 16-digit number with invalid Luhn check digit
    invalid_luhn_number = "4532 0151 1283 0367"
    assert not is_luhn_valid(invalid_luhn_number)

    raw_text = (
        f"Email: {real_email}\n"
        f"PAN: {real_pan}\n"
        f"UPI: {real_upi}\n"
        f"Card: {real_card}\n"
        f"Aadhaar: {real_aadhaar}\n"
        f"SSN: {real_ssn}\n"
        f"Phone: {real_phone}\n"
        f"Key: {real_api_key}\n"
        f"Order Ref: {invalid_luhn_number}\n"
    )

    dehydrated = vault.dehydrate(raw_text, session_id=session_id)

    # 1. Assert all real PII items are completely removed
    assert real_email not in dehydrated
    assert real_pan not in dehydrated
    assert real_upi not in dehydrated
    assert real_card not in dehydrated
    assert real_aadhaar not in dehydrated
    assert real_ssn not in dehydrated
    assert real_phone not in dehydrated
    assert real_api_key not in dehydrated

    # 2. Assert random 16-digit number failing Luhn check is NOT falsely redacted
    assert invalid_luhn_number in dehydrated

    # 3. Retrieve synthetic tokens from session map
    session_map = vault.get_session_map(session_id)
    assert len(session_map) == 8  # 8 valid entities mapped

    synth_email = vault.store.get_synth_val(session_id, real_email)
    synth_pan = vault.store.get_synth_val(session_id, real_pan)
    synth_upi = vault.store.get_synth_val(session_id, real_upi)
    synth_card = vault.store.get_synth_val(session_id, real_card)
    synth_aadhaar = vault.store.get_synth_val(session_id, real_aadhaar)
    synth_ssn = vault.store.get_synth_val(session_id, real_ssn)
    synth_phone = vault.store.get_synth_val(session_id, real_phone)
    synth_key = vault.store.get_synth_val(session_id, real_api_key)

    # 4. Assert format preservation and checksum validity on synthetic values
    # Email format
    assert synth_email.startswith("u_") and synth_email.endswith("@shadow.vault")
    # UPI format
    assert synth_upi.startswith("u_") and synth_upi.endswith("@okshadow")
    # PAN format: 5 letters, 4 digits, 1 letter
    assert re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$", synth_pan)
    # Credit Card: 16 digits, starts with 400000999, PASSES Luhn algorithm!
    assert len(synth_card) == 16 and synth_card.isdigit()
    assert is_luhn_valid(synth_card)
    # Aadhaar: 12 digits, starts with 99990, PASSES Verhoeff algorithm!
    assert len(synth_aadhaar) == 12 and synth_aadhaar.isdigit()
    assert is_verhoeff_valid(synth_aadhaar)
    # SSN format: 900-99-xxxx
    assert re.match(r"^900-99-\d{4}$", synth_ssn)
    # Phone format: +919000xxxxxx (10-digit mobile)
    assert re.match(r"^\+91[6-9]\d{9}$", synth_phone)
    # API key format
    assert synth_key.startswith("sk-sv-shadow-")

    # 5. Full round-trip hydration restores identical original text
    hydrated = vault.hydrate(dehydrated, session_id=session_id)
    assert hydrated == raw_text

    vault.close()


# ============================================================================
# 2. Coreference Consistency & Idempotency
# ============================================================================


def test_coreference_consistency_and_idempotency() -> None:
    """Verify identical PII values map to the exact same synthetic token consistently."""
    vault = ShadowVault()
    session_id = "chat_1"

    text = (
        "Contact dhiraj@example.com in the morning. "
        "Also cc dhiraj@example.com on the report. "
        "Invoices must be routed to dhiraj@example.com."
    )

    dehydrated = vault.dehydrate(text, session_id=session_id)

    # Ensure real email is removed
    assert "dhiraj@example.com" not in dehydrated

    # Find synthetic email token
    synth_email = vault.store.get_synth_val(session_id, "dhiraj@example.com")
    assert synth_email is not None

    # The exact same synthetic token must appear exactly 3 times
    assert dehydrated.count(synth_email) == 3

    # Session map should have only 1 unique mapping for this email
    session_map = vault.get_session_map(session_id)
    assert len(session_map) == 1
    assert session_map[synth_email] == "dhiraj@example.com"

    # Idempotency check: Dehydrating an already-dehydrated string is a strict no-op
    dehydrated_again = vault.dehydrate(dehydrated, session_id=session_id)
    assert dehydrated_again == dehydrated

    # Full hydration restores the original string with all 3 occurrences
    hydrated = vault.hydrate(dehydrated_again, session_id=session_id)
    assert hydrated == text

    vault.close()


# ============================================================================
# 3. Bi-Directional Tool Call Round-Trip (@vault_guard & protect_tool)
# ============================================================================


def test_bidirectional_tool_call_round_trip() -> None:
    """Simulate complete agent flow with @vault_guard and protect_tool."""
    vault = ShadowVault()
    session_id = "agent_session_invoice"

    # 1. User prompt with sensitive email and PAN card
    user_prompt = "Send invoice to dhiraj@example.com for PAN ABCDE1234F"
    dehydrated_prompt = vault.dehydrate(user_prompt, session_id=session_id)

    # 2. Assert real PII does NOT exist in the dehydrated prompt
    assert "dhiraj@example.com" not in dehydrated_prompt
    assert "ABCDE1234F" not in dehydrated_prompt

    synth_email = vault.store.get_synth_val(session_id, "dhiraj@example.com")
    synth_pan = vault.store.get_synth_val(session_id, "ABCDE1234F")
    assert synth_email is not None
    assert synth_pan is not None

    # ------------------------------------------------------------------------
    # Part A: Test with @vault_guard decorator
    # ------------------------------------------------------------------------
    received_guard_email = None
    received_guard_pan = None

    @vault_guard(vault=vault, session_id_arg="session_id")
    def send_invoice_guard(email: str, pan: str, session_id: str = "default") -> dict[str, str]:
        nonlocal received_guard_email, received_guard_pan
        received_guard_email = email
        received_guard_pan = pan
        # Backend execution returns sensitive real phone number
        return {
            "status": "sent",
            "customer_phone": "+91 9876543210",
        }

    # Simulate LLM tool execution using synthetic arguments
    guard_output = send_invoice_guard(
        email=synth_email, pan=synth_pan, session_id=session_id
    )

    # Assert function received REAL values inside
    assert received_guard_email == "dhiraj@example.com"
    assert received_guard_pan == "ABCDE1234F"

    # Assert output dict has customer_phone automatically dehydrated
    assert guard_output["status"] == "sent"
    assert "+91 9876543210" not in guard_output["customer_phone"]
    assert is_synthetic(guard_output["customer_phone"])

    # ------------------------------------------------------------------------
    # Part B: Test with LangChain protect_tool
    # ------------------------------------------------------------------------
    received_lc_email = None
    received_lc_pan = None

    @tool
    def send_invoice_tool(email: str, pan: str) -> dict[str, str]:
        """Tool to dispatch invoice to a customer."""
        nonlocal received_lc_email, received_lc_pan
        received_lc_email = email
        received_lc_pan = pan
        return {
            "status": "sent",
            "customer_phone": "+91 9876543210",
        }

    safe_tool = protect_tool(send_invoice_tool, vault=vault, session_id=session_id)

    # Agent invokes tool with synthetic arguments
    lc_output = safe_tool.invoke({"email": synth_email, "pan": synth_pan})

    # Assert tool executed with REAL values
    assert received_lc_email == "dhiraj@example.com"
    assert received_lc_pan == "ABCDE1234F"

    # Assert result returned to LangGraph/agent is dehydrated
    assert lc_output["status"] == "sent"
    assert "+91 9876543210" not in lc_output["customer_phone"]
    assert is_synthetic(lc_output["customer_phone"])

    vault.close()


# ============================================================================
# 4. Adversarial Chunked SSE Streaming (StreamHydrator)
# ============================================================================


def test_adversarial_chunked_sse_streaming() -> None:
    """Verify StreamHydrator buffers and restores tokens across adversarial 2-char slices."""
    vault = ShadowVault()
    session_id = "sess_adversarial_sse"

    real_email = "dhiraj@example.com"
    real_phone = "+91 9876543210"
    real_pan = "ABCDE1234F"

    full_original_text = (
        f"Confirmation: Invoice sent to {real_email}. "
        f"Registered phone is {real_phone} and PAN on record is {real_pan}."
    )

    dehydrated_text = vault.dehydrate(full_original_text, session_id=session_id)

    # Verify dehydration succeeded
    assert real_email not in dehydrated_text
    assert real_phone not in dehydrated_text
    assert real_pan not in dehydrated_text

    # Slicing into tiny 2-character chunks deliberately splits synthetic tokens
    # e.g., 'u_', 'c0', '97', '53', '@s', 'ha', 'do', 'w.', 'va', 'ul', 't'
    chunk_size = 2
    chunks = [
        dehydrated_text[i : i + chunk_size]
        for i in range(0, len(dehydrated_text), chunk_size)
    ]

    hydrator = vault.stream(session_id=session_id)
    emitted_chunks: list[str] = []

    for chunk in chunks:
        out = hydrator.process_chunk(chunk)
        if out:
            emitted_chunks.append(out)

    flushed = hydrator.flush()
    if flushed:
        emitted_chunks.append(flushed)

    # Reconstruct the stream
    reconstructed_text = "".join(emitted_chunks)

    # 1. Assert the reconstructed output 100% matches the original text
    assert reconstructed_text == full_original_text

    # 2. Assert zero leaked synthetic tokens in the final output
    assert "@shadow.vault" not in reconstructed_text
    assert "@okshadow" not in reconstructed_text
    assert "SHDWV" not in reconstructed_text
    assert "+919000" not in reconstructed_text

    vault.close()
