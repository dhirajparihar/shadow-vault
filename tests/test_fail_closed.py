"""
Tests for Fail-Closed Privacy Protection and safe failure behavior.
"""

from __future__ import annotations

import pytest
from shadow_vault.engine import ShadowVault
from shadow_vault.policy import (
    FailClosedAction,
    PIILeakBlockedError,
    ToolPolicy,
    UnmappedTokenError,
)


def test_fail_closed_raises_on_unmapped_token() -> None:
    """Test that fail-closed mode raises UnmappedTokenError on unmapped synthetic tokens."""
    vault = ShadowVault(fail_closed=True)
    session_id = "test_fail_closed_sess"

    # Synthetic token that was never registered in this session
    unknown_token = "u_999999@shadow.vault"
    payload = {"message": f"Please process refund for {unknown_token}"}

    # Should raise UnmappedTokenError
    with pytest.raises(UnmappedTokenError) as exc_info:
        vault.hydrate(payload, session_id=session_id)

    assert "u_999999@shadow.vault" in str(exc_info.value)
    assert exc_info.value.token == unknown_token


def test_fail_closed_redacts_on_unmapped_token() -> None:
    """Test that fail-closed mode redacts unmapped tokens when action is REDACT."""
    vault = ShadowVault()
    session_id = "test_redact_sess"

    policy = ToolPolicy(
        tool_name="stripe_refund",
        fail_closed=True,
        fail_action=FailClosedAction.REDACT,
    )

    unmapped_email = "u_deadbeef@shadow.vault"
    unmapped_card = "4000009990001112"
    payload = f"Refund user {unmapped_email} on card {unmapped_card}"

    result = vault.hydrate(payload, session_id=session_id, policy=policy)
    assert unmapped_email not in result
    assert unmapped_card not in result
    assert result == "Refund user [UNRESOLVED_TOKEN] on card [UNRESOLVED_TOKEN]"


def test_permissive_mode_leaves_unmapped_token_intact() -> None:
    """Test that default permissive mode does not raise on unmapped tokens."""
    vault = ShadowVault(fail_closed=False)
    session_id = "test_permissive_sess"

    unmapped_email = "u_123456@shadow.vault"
    payload = f"Hello {unmapped_email}"

    result = vault.hydrate(payload, session_id=session_id)
    assert result == payload


def test_fail_closed_blocks_outbound_pii_leak() -> None:
    """Test that dehydrate in fail-closed mode blocks outbound leaks if unmasked PII is present."""
    vault = ShadowVault(fail_closed=True)

    # Valid dehydration proceeds normally
    safe_text = vault.dehydrate("Contact alice@example.com")
    assert "alice@example.com" not in safe_text
    assert "@shadow.vault" in safe_text
