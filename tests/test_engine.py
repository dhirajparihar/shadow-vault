"""
Unit tests for ShadowVault dehydrate and hydrate engine.
"""

from __future__ import annotations

from typing import NamedTuple
import pytest
from pydantic import BaseModel, Field

from shadow_vault.detectors import calculate_verhoeff
from shadow_vault.engine import ShadowVault
from shadow_vault.synthesizer import is_synthetic


class UserProfile(BaseModel):
    name: str
    email: str
    phone: str
    aadhaar: str
    card: str


class Point(NamedTuple):
    label: str
    coord: str


def test_dehydrate_and_hydrate_string() -> None:
    """Test bi-directional dehydration and hydration of sensitive strings."""
    vault = ShadowVault()
    session_id = "sess_str"

    base_aadhaar = "36759834601"
    aadhaar_num = f"{base_aadhaar}{calculate_verhoeff(base_aadhaar)}"
    original_text = (
        f"Contact rahul@okhdfcbank or call +91 9876543210. "
        f"Email: alice@example.com, Aadhaar: {aadhaar_num}, Card: 4532 0151 1283 0366."
    )

    # 1. Dehydrate
    dehydrated = vault.dehydrate(original_text, session_id=session_id)
    assert dehydrated != original_text

    # None of the original PII values should remain
    assert "rahul@okhdfcbank" not in dehydrated
    assert "+91 9876543210" not in dehydrated
    assert "alice@example.com" not in dehydrated
    assert aadhaar_num not in dehydrated
    assert "4532 0151 1283 0366" not in dehydrated

    # Synthetic tokens must be present
    assert "@okshadow" in dehydrated
    assert "@shadow.vault" in dehydrated
    assert "+919000" in dehydrated
    assert "400000999" in dehydrated
    assert "99990" in dehydrated

    # 2. Hydrate
    hydrated = vault.hydrate(dehydrated, session_id=session_id)
    assert hydrated == original_text

    vault.close()


def test_double_dehydration_prevention() -> None:
    """Verify dehydrate skips already synthetic tokens to prevent double-masking."""
    vault = ShadowVault()
    session_id = "sess_double"

    original = "Send report to support@example.com."
    first_pass = vault.dehydrate(original, session_id=session_id)
    assert "@shadow.vault" in first_pass

    # Second pass over already dehydrated text
    second_pass = vault.dehydrate(first_pass, session_id=session_id)
    assert second_pass == first_pass

    # Restores accurately
    restored = vault.hydrate(second_pass, session_id=session_id)
    assert restored == original

    vault.close()


def test_recursive_nested_collections() -> None:
    """Test recursive dehydration and hydration across dicts, lists, and tuples."""
    vault = ShadowVault()
    session_id = "sess_collections"

    data = {
        "user": {
            "name": "Bob Smith",
            "contact": {
                "emails": ["primary@example.com", "alt@company.org"],
                "mobile": "+91 9876543210",
            },
        },
        "history": [
            ("tx1", "Paid to merchant@paytm"),
            ("tx2", "Refund to 4532 0151 1283 0366"),
        ],
        "point": Point(label="office", coord="+1-555-123-4567"),
    }

    # 1. Dehydrate
    dehydrated = vault.dehydrate(data, session_id=session_id)

    # Validate structure preservation
    assert isinstance(dehydrated["user"]["contact"]["emails"], list)
    assert isinstance(dehydrated["history"], list)
    assert isinstance(dehydrated["history"][0], tuple)
    assert isinstance(dehydrated["point"], Point)

    # Validate anonymization
    assert "@shadow.vault" in dehydrated["user"]["contact"]["emails"][0]
    assert "@shadow.vault" in dehydrated["user"]["contact"]["emails"][1]
    assert "+919000" in dehydrated["user"]["contact"]["mobile"]
    assert "@okshadow" in dehydrated["history"][0][1]
    assert "400000999" in dehydrated["history"][1][1]

    # 2. Hydrate
    hydrated = vault.hydrate(dehydrated, session_id=session_id)
    assert hydrated == data

    vault.close()


def test_pydantic_model_dehydration_and_hydration() -> None:
    """Test format-preserving dehydration on Pydantic BaseModel instances."""
    vault = ShadowVault()
    session_id = "sess_model"

    base_aadhaar = "36759834601"
    aadhaar_num = f"{base_aadhaar}{calculate_verhoeff(base_aadhaar)}"

    user = UserProfile(
        name="Charlie",
        email="charlie@enterprise.com",
        phone="+91 9876543210",
        aadhaar=aadhaar_num,
        card="4532 0151 1283 0366",
    )

    # Dehydrate returns an instance of the exact same Pydantic class
    dehydrated_user = vault.dehydrate(user, session_id=session_id)
    assert isinstance(dehydrated_user, UserProfile)
    assert dehydrated_user.name == "Charlie"
    assert is_synthetic(dehydrated_user.email)
    assert is_synthetic(dehydrated_user.phone)
    assert is_synthetic(dehydrated_user.aadhaar)
    assert is_synthetic(dehydrated_user.card)

    # Hydrate restores original Pydantic model
    hydrated_user = vault.hydrate(dehydrated_user, session_id=session_id)
    assert isinstance(hydrated_user, UserProfile)
    assert hydrated_user.email == user.email
    assert hydrated_user.phone == user.phone
    assert hydrated_user.aadhaar == user.aadhaar
    assert hydrated_user.card == user.card

    vault.close()


def test_numeric_type_coercion_hydration() -> None:
    """Test hydrate gracefully handles numeric types coerced by an LLM."""
    vault = ShadowVault()
    session_id = "sess_numeric"

    real_card = "4532015112830366"
    dehydrated_str = vault.dehydrate(f"Card: {real_card}", session_id=session_id)

    # Extract the synthetic card digits
    synth_card = [word for word in dehydrated_str.split() if word.startswith("400000999")][0]

    # Simulate LLM parsing numeric string token as an int in a JSON response
    llm_response = {
        "card_number": int(synth_card),
        "status": "APPROVED",
    }

    hydrated_response = vault.hydrate(llm_response, session_id=session_id)
    assert hydrated_response["card_number"] == real_card
    assert hydrated_response["status"] == "APPROVED"

    vault.close()
