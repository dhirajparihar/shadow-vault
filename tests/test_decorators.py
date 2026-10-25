"""
Unit tests for @vault_guard Python function decorator.
"""

from __future__ import annotations

import pytest

from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.decorators import vault_guard
from shadow_vault.synthesizer import is_synthetic


def test_vault_guard_sync_function() -> None:
    """Test @vault_guard wraps synchronous functions with bi-directional PII conversion."""
    vault = ShadowVault()
    session_id = "sess_sync_guard"

    real_email = "alice@example.com"
    synth_email = vault.dehydrate(real_email, session_id=session_id)
    assert is_synthetic(synth_email)

    received_args: list[str] = []

    @vault_guard(vault=vault, session_id_arg="sess_id")
    def charge_customer(email: str, sess_id: str = "default") -> dict[str, str]:
        received_args.append(email)
        # Function interacts with internal backend and returns sensitive real PII
        return {
            "account_email": email,
            "card_on_file": "4532 0151 1283 0366",
            "status": "CHARGED",
        }

    # Caller (AI agent) passes synthetic token
    agent_result = charge_customer(email=synth_email, sess_id=session_id)

    # 1. Inside the function, the email was hydrated to the real email
    assert len(received_args) == 1
    assert received_args[0] == real_email

    # 2. Outside the function, the returned card on file was dehydrated to a synthetic token
    assert is_synthetic(agent_result["card_on_file"])
    assert "4532 0151 1283 0366" not in agent_result["card_on_file"]
    assert agent_result["account_email"] == synth_email
    assert agent_result["status"] == "CHARGED"

    vault.close()


@pytest.mark.asyncio
async def test_vault_guard_async_function() -> None:
    """Test @vault_guard wraps asynchronous functions."""
    vault = ShadowVault()
    session_id = "sess_async_guard"

    real_phone = "+91 9876543210"
    synth_phone = vault.dehydrate(real_phone, session_id=session_id)
    assert is_synthetic(synth_phone)

    received_phone: str = ""

    @vault_guard(vault=vault)
    async def send_sms(phone: str, session_id: str = "default") -> str:
        nonlocal received_phone
        received_phone = phone
        return f"OTP sent to {phone}. Verification card: 4532 0151 1283 0366"

    # Agent calls async function with synthetic phone
    result = await send_sms(phone=synth_phone, session_id=session_id)

    # The function body received real phone
    assert received_phone == real_phone

    # The returned string has both phone and card dehydrated
    assert is_synthetic(synth_phone)
    assert "+91 9876543210" not in result
    assert "4532 0151 1283 0366" not in result

    # Hydrate restores full message
    restored = vault.hydrate(result, session_id=session_id)
    assert restored == f"OTP sent to {real_phone}. Verification card: 4532 0151 1283 0366"

    vault.close()
