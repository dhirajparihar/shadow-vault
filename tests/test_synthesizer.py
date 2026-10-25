"""
Unit tests for format-preserving token synthesizer.
"""

from __future__ import annotations

import re
import pytest

from shadow_vault.detectors import (
    EntityType,
    is_luhn_valid,
    is_verhoeff_valid,
)
from shadow_vault.synthesizer import (
    calculate_luhn_check_digit,
    is_synthetic,
    synthesize_token,
)


def test_synthesize_all_entity_types() -> None:
    """Test format-preserving token generation across all entity types."""
    short_hash = "c09753"

    # 1. EMAIL
    synth_email = synthesize_token(EntityType.EMAIL, short_hash)
    assert synth_email == f"u_{short_hash}@shadow.vault"
    assert is_synthetic(synth_email)

    # 2. UPI_ID
    synth_upi = synthesize_token(EntityType.UPI_ID, short_hash)
    assert synth_upi == f"u_{short_hash}@okshadow"
    assert is_synthetic(synth_upi)

    # 3. PHONE
    synth_phone = synthesize_token(EntityType.PHONE, short_hash)
    assert synth_phone.startswith("+919000")
    assert len(synth_phone) == 13  # +91 (3 chars) + 10 digits
    assert re.match(r"^\+91[6-9]\d{9}$", synth_phone)
    assert is_synthetic(synth_phone)

    # 4. PAN_CARD
    synth_pan = synthesize_token(EntityType.PAN_CARD, short_hash)
    assert synth_pan.startswith("SHDWV")
    assert synth_pan.endswith("Z")
    assert len(synth_pan) == 10
    assert re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$", synth_pan)
    assert is_synthetic(synth_pan)

    # 5. CREDIT_CARD
    synth_card = synthesize_token(EntityType.CREDIT_CARD, short_hash)
    assert synth_card.startswith("400000999")
    assert len(synth_card) == 16
    assert synth_card.isdigit()
    assert is_luhn_valid(synth_card)
    assert is_synthetic(synth_card)

    # 6. AADHAAR
    synth_aadhaar = synthesize_token(EntityType.AADHAAR, short_hash)
    assert synth_aadhaar.startswith("99990")
    assert len(synth_aadhaar) == 12
    assert synth_aadhaar.isdigit()
    assert is_verhoeff_valid(synth_aadhaar)
    assert is_synthetic(synth_aadhaar)

    # 7. API_KEY
    synth_key = synthesize_token(EntityType.API_KEY, short_hash)
    assert synth_key == f"sk-sv-shadow-{short_hash}00000000000000"
    assert len(synth_key) >= 20
    assert is_synthetic(synth_key)

    # 8. SSN
    synth_ssn = synthesize_token(EntityType.SSN, short_hash)
    assert synth_ssn.startswith("900-99-")
    assert len(synth_ssn) == 11
    assert is_synthetic(synth_ssn)

    # 9. Fallback custom type
    synth_custom = synthesize_token("PASSPORT", short_hash)
    assert synth_custom == f"synth_passport_{short_hash}"
    assert is_synthetic(synth_custom)


def test_is_synthetic_negative_cases() -> None:
    """Verify is_synthetic returns False on real PII and arbitrary strings."""
    assert not is_synthetic("alice@example.com")
    assert not is_synthetic("user@okhdfcbank")
    assert not is_synthetic("+91 9876543210")
    assert not is_synthetic("ABCDE1234F")
    assert not is_synthetic("4532 0151 1283 0366")
    assert not is_synthetic("3675 9834 6016")
    assert not is_synthetic("sk-realopenai1234567890abcdef")
    assert not is_synthetic("123-45-6789")
    assert not is_synthetic("")
    assert not is_synthetic(None)  # type: ignore[arg-type]


def test_calculate_luhn_check_digit() -> None:
    """Test calculate_luhn_check_digit generates valid 16-digit cards."""
    prefixes = [
        "400000999000000",
        "400000999123456",
        "400000999999999",
        "400000999597059",
    ]
    for p in prefixes:
        cd = calculate_luhn_check_digit(p)
        full_card = f"{p}{cd}"
        assert is_luhn_valid(full_card), f"Failed for prefix {p} with check digit {cd}"
