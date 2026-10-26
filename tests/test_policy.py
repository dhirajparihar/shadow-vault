"""
Unit and integration tests for ToolPolicy and context-aware masking.
"""

from __future__ import annotations

import pytest
from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.decorators import vault_guard
from shadow_vault.policy import ToolPolicy


def test_tool_policy_selective_entity_hydration() -> None:
    """Test that ToolPolicy with allowed_entities restores ONLY allowed PII types."""
    vault = ShadowVault()
    session_id = "sess_selective_policy"

    raw_text = (
        "Customer alice@example.com with card 4532 0151 1283 0366 and phone +91 9876543210"
    )
    dehydrated = vault.dehydrate(raw_text, session_id=session_id)

    assert "alice@example.com" not in dehydrated
    assert "4532 0151 1283 0366" not in dehydrated

    # Policy 1: Email-only tool (e.g. email notification sender)
    email_only_policy = ToolPolicy(
        tool_name="send_email_notification",
        allowed_entities={"EMAIL"},
    )
    hydrated_email_only = vault.hydrate(
        dehydrated, session_id=session_id, policy=email_only_policy
    )

    # Email is restored, but card and phone remain masked
    assert "alice@example.com" in hydrated_email_only
    assert "4532 0151 1283 0366" not in hydrated_email_only
    assert "+91 9876543210" not in hydrated_email_only
    assert "400000999" in hydrated_email_only  # Synthetic card preserved

    # Policy 2: Card-only tool (e.g. payment gateway charge)
    card_only_policy = ToolPolicy(
        tool_name="charge_card",
        allowed_entities={"CREDIT_CARD"},
    )
    hydrated_card_only = vault.hydrate(
        dehydrated, session_id=session_id, policy=card_only_policy
    )

    # Card is restored, but email and phone remain masked
    assert "4532015112830366" in hydrated_card_only or "4532 0151 1283 0366" in hydrated_card_only
    assert "alice@example.com" not in hydrated_card_only
    assert "@shadow.vault" in hydrated_card_only  # Synthetic email preserved


def test_tool_policy_disallow_all_hydration() -> None:
    """Test that allow_hydration=False prevents any real PII from reaching the tool."""
    vault = ShadowVault()
    session_id = "sess_zero_trust"

    raw_text = "Secret API key sk-sv-shadow-test and card 4532 0151 1283 0366"
    dehydrated = vault.dehydrate(raw_text, session_id=session_id)

    zero_trust_policy = ToolPolicy(
        tool_name="untrusted_external_search",
        allow_hydration=False,
    )

    hydrated = vault.hydrate(dehydrated, session_id=session_id, policy=zero_trust_policy)
    assert hydrated == dehydrated  # No modification; synthetic tokens remain untouched


def test_vault_guard_decorator_with_tool_policy() -> None:
    """Test that @vault_guard enforces ToolPolicy on function arguments."""
    vault = ShadowVault()
    session_id = "sess_decorator_policy"

    email = "bob@example.com"
    card = "4532 0151 1283 0366"

    # Dehydrate prompt
    dehydrated_email = vault.dehydrate(email, session_id=session_id)
    dehydrated_card = vault.dehydrate(card, session_id=session_id)

    # Policy allowing only EMAIL
    slack_policy = ToolPolicy(
        tool_name="post_slack_alert",
        allowed_entities={"EMAIL"},
    )

    received_args: dict[str, str] = {}

    @vault_guard(vault=vault, policy=slack_policy, session_id_arg="session_id")
    def post_slack_alert(user_email: str, user_card: str, session_id: str = "default") -> dict[str, str]:
        received_args["email"] = user_email
        received_args["card"] = user_card
        return {"status": "posted", "author": user_email}

    # Execute tool with synthetic arguments
    result = post_slack_alert(
        user_email=dehydrated_email,
        user_card=dehydrated_card,
        session_id=session_id,
    )

    # Verify tool received REAL email, but SYNTHETIC card
    assert received_args["email"] == email
    assert received_args["card"] == dehydrated_card
    assert received_args["card"] != card

    # Verify return value was sanitized
    assert result["status"] == "posted"
    assert result["author"] == dehydrated_email
