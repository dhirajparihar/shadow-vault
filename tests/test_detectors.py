"""
Unit tests for zero-dependency regex and mathematical checksum PII detectors.
"""

from __future__ import annotations

import pytest

from shadow_vault.detectors import (
    DetectedEntity,
    EntityType,
    calculate_verhoeff,
    detect_aadhaar,
    detect_api_keys,
    detect_credit_cards,
    detect_emails,
    detect_entities,
    detect_pan_cards,
    detect_phones,
    detect_ssns,
    detect_upi_ids,
    is_luhn_valid,
    is_verhoeff_valid,
)


# ============================================================================
# Checksum Algorithm Tests: Luhn & Verhoeff
# ============================================================================


def test_luhn_valid_cards() -> None:
    """Test Luhn checksum validation with valid credit cards."""
    # 16-digit Visa
    assert is_luhn_valid("4532 0151 1283 0366")
    assert is_luhn_valid("4532-0151-1283-0366")
    assert is_luhn_valid("4532015112830366")

    # 15-digit Amex
    assert is_luhn_valid("3782 822463 10005")
    assert is_luhn_valid("3782-822463-10005")
    assert is_luhn_valid("378282246310005")

    # 14-digit Diners Club
    assert is_luhn_valid("3056 789012 3450")


def test_luhn_invalid_cards() -> None:
    """Test Luhn algorithm rejects invalid or non-card numbers."""
    # Single digit alteration from valid 4532 0151 1283 0366
    assert not is_luhn_valid("4532 0151 1283 0367")
    # All zeros
    assert not is_luhn_valid("0000 0000 0000 0000")
    # Starting with 0
    assert not is_luhn_valid("0532 0151 1283 0366")
    # Too short (<13 digits)
    assert not is_luhn_valid("1234 5678 9012")
    # Too long (>19 digits)
    assert not is_luhn_valid("1234 5678 9012 3456 7890")
    # All identical digits
    assert not is_luhn_valid("1111 1111 1111 1111")


def test_verhoeff_checksum_test_vectors() -> None:
    """Test Verhoeff check digit generation and validation against standard vectors."""
    # 236 -> check digit 3
    assert calculate_verhoeff("236") == 3
    assert is_verhoeff_valid("2363")

    # 142857 -> check digit 0
    assert calculate_verhoeff("142857") == 0
    assert is_verhoeff_valid("1428570")

    # Base Aadhaar prefixes
    base_aadhaar = "36759834601"
    cd = calculate_verhoeff(base_aadhaar)
    valid_aadhaar = base_aadhaar + str(cd)
    assert is_verhoeff_valid(valid_aadhaar)
    assert is_verhoeff_valid(f"{valid_aadhaar[:4]} {valid_aadhaar[4:8]} {valid_aadhaar[8:]}")
    assert is_verhoeff_valid(f"{valid_aadhaar[:4]}-{valid_aadhaar[4:8]}-{valid_aadhaar[8:]}")


def test_verhoeff_error_detection() -> None:
    """Test that Verhoeff detects all single-character and adjacent transposition errors."""
    valid_num = "367598346016"  # Valid Verhoeff number
    assert is_verhoeff_valid(valid_num)

    # Single-character substitution error
    for i in range(10):
        if i != 6:
            mutated = valid_num[:-1] + str(i)
            assert not is_verhoeff_valid(mutated), f"Failed to reject single error {mutated}"

    # Adjacent transposition error (swap 6 and 7 -> 376598346016)
    transposed = "376598346016"
    assert not is_verhoeff_valid(transposed)


# ============================================================================
# Individual Entity Detector Tests
# ============================================================================


def test_detect_upi_ids() -> None:
    """Test Indian UPI ID detection across various banking and app handles."""
    text = (
        "Pay me at rahul@okhdfcbank or merchant-99@paytm or user.name@ybl. "
        "Also test anish@oksbi, shop_123@okaxis, friend@apl, and donate@upi. "
        "Do NOT match john@paytm.com as UPI."
    )
    entities = detect_upi_ids(text)
    values = [e.value for e in entities]

    assert "rahul@okhdfcbank" in values
    assert "merchant-99@paytm" in values
    assert "user.name@ybl" in values
    assert "anish@oksbi" in values
    assert "shop_123@okaxis" in values
    assert "friend@apl" in values
    assert "donate@upi" in values
    assert "john@paytm.com" not in values


def test_detect_emails_with_exclusions() -> None:
    """Test email detector ignores @shadow.vault and known UPI handles."""
    text = (
        "Contact alice@example.com or bob.smith@company.org. "
        "Ignore synthetic token test_c09753@shadow.vault and sub@internal.shadow.vault. "
        "Ignore UPI handle user@okhdfcbank in email detector."
    )
    entities = detect_emails(text)
    values = [e.value for e in entities]

    assert "alice@example.com" in values
    assert "bob.smith@company.org" in values
    assert "test_c09753@shadow.vault" not in values
    assert "sub@internal.shadow.vault" not in values
    assert "user@okhdfcbank" not in values


def test_detect_credit_cards() -> None:
    """Test credit card detector matches valid cards and ignores random numbers."""
    text = (
        "Primary card: 4532 0151 1283 0366, backup: 3782-822463-10005. "
        "Ignore invalid card 4532 0151 1283 0367 and random digits 9876 5432 1098 7654."
    )
    entities = detect_credit_cards(text)
    values = [e.value for e in entities]

    assert "4532 0151 1283 0366" in values
    assert "3782-822463-10005" in values
    assert "4532 0151 1283 0367" not in values
    assert "9876 5432 1098 7654" not in values


def test_detect_aadhaar() -> None:
    """Test Aadhaar detector matches 12-digit Verhoeff-valid numbers."""
    base = "36759834601"
    cd = calculate_verhoeff(base)
    valid_aadhaar_space = f"{base[:4]} {base[4:8]} {base[8:]}{cd}"
    valid_aadhaar_dash = f"{base[:4]}-{base[4:8]}-{base[8:]}{cd}"
    valid_aadhaar_raw = f"{base}{cd}"

    text = (
        f"Aadhaar 1: {valid_aadhaar_space}, Aadhaar 2: {valid_aadhaar_dash}, "
        f"Aadhaar 3: {valid_aadhaar_raw}. "
        "Ignore invalid checksum 3675 9834 6019 and starting with 0/1: 1234 5678 9012."
    )
    entities = detect_aadhaar(text)
    values = [e.value for e in entities]

    assert valid_aadhaar_space in values
    assert valid_aadhaar_dash in values
    assert valid_aadhaar_raw in values
    assert "3675 9834 6019" not in values
    assert "1234 5678 9012" not in values


def test_detect_pan_cards() -> None:
    """Test Indian PAN card detector."""
    text = "User PAN is ABCDE1234F and company PAN is bczpk9876m. Ignore ABCD1234F or ABCDE12345."
    entities = detect_pan_cards(text)
    values = [e.value.upper() for e in entities]

    assert "ABCDE1234F" in values
    assert "BCZPK9876M" in values
    assert len(entities) == 2


def test_detect_phones_collision_avoidance() -> None:
    """Test phone detection and collision avoidance against Aadhaar and Credit Cards."""
    base_aadhaar = "36759834601"
    aadhaar_num = f"{base_aadhaar[:4]} {base_aadhaar[4:8]} {base_aadhaar[8:]}{calculate_verhoeff(base_aadhaar)}"
    credit_card = "4532 0151 1283 0366"

    text = (
        f"Call me at +91 9876543210 or 9876543210 or +1-555-123-4567. "
        f"Office is +44 20 7946 0958. "
        f"Aadhaar {aadhaar_num} and Card {credit_card} must NOT be flagged as phones."
    )
    entities = detect_phones(text)
    values = [e.value for e in entities]

    assert "+91 9876543210" in values or "9876543210" in values
    assert "+1-555-123-4567" in values
    assert "+44 20 7946 0958" in values
    assert aadhaar_num not in values
    assert credit_card not in values


def test_detect_api_keys() -> None:
    """Test API key detector for OpenAI, GitHub, Google AIza, and Bearer tokens."""
    openai_key = "sk-abcdef1234567890abcdef123456"
    github_pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    google_key = "AIzaSyB1234567890abcdefghijklmnopqrst12"
    bearer_tok = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

    text = (
        f"Headers:\n"
        f"Authorization: {bearer_tok}\n"
        f"OPENAI_API_KEY={openai_key}\n"
        f"GITHUB_TOKEN={github_pat}\n"
        f"GEMINI_API_KEY={google_key}\n"
    )
    entities = detect_api_keys(text)
    values = [e.value for e in entities]

    assert openai_key in values
    assert github_pat in values
    assert google_key in values
    assert bearer_tok in values


def test_detect_ssns() -> None:
    """Test US Social Security Number detector."""
    text = (
        "Valid SSN: 123-45-6789 and 219-45-7890. "
        "Invalid SSNs: 000-45-6789, 666-45-6789, 900-45-6789, 123-00-6789, 123-45-0000."
    )
    entities = detect_ssns(text)
    values = [e.value for e in entities]

    assert "123-45-6789" in values
    assert "219-45-7890" in values
    assert len(entities) == 2


# ============================================================================
# Unified Pipeline & Overlap Resolution Tests
# ============================================================================


def test_unified_detect_entities_non_overlapping_and_sorted() -> None:
    """Test unified detect_entities returns strictly non-overlapping, start-sorted entities."""
    base_aadhaar = "36759834601"
    aadhaar_str = f"{base_aadhaar[:4]} {base_aadhaar[4:8]} {base_aadhaar[8:]}{calculate_verhoeff(base_aadhaar)}"
    card_str = "4532 0151 1283 0366"

    text = (
        f"User details: contact rahul@okhdfcbank or call +91 9876543210. "
        f"Email is dev@company.org. Aadhaar: {aadhaar_str}. "
        f"Card: {card_str}. PAN: ABCDE1234F. SSN: 123-45-6789. "
        f"Token: sk-abcdef1234567890abcdef123456."
    )

    entities = detect_entities(text)
    assert len(entities) > 0

    # 1. Verify strict sorting by start index
    for i in range(len(entities) - 1):
        assert entities[i].start <= entities[i + 1].start
        # 2. Verify absolutely no overlapping spans
        assert entities[i].end <= entities[i + 1].start, (
            f"Overlap detected between {entities[i]} and {entities[i + 1]}"
        )

    types_found = {e.entity_type for e in entities}
    assert EntityType.UPI_ID.value in types_found
    assert EntityType.PHONE.value in types_found
    assert EntityType.EMAIL.value in types_found
    assert EntityType.AADHAAR.value in types_found
    assert EntityType.CREDIT_CARD.value in types_found
    assert EntityType.PAN_CARD.value in types_found
    assert EntityType.SSN.value in types_found
    assert EntityType.API_KEY.value in types_found


def test_upi_precedence_over_email() -> None:
    """Verify UPI_ID is preferred over EMAIL for Indian UPI handles."""
    text = "Send 100 INR to merchant@paytm immediately."
    entities = detect_entities(text)
    assert len(entities) == 1
    assert entities[0].entity_type == EntityType.UPI_ID.value
    assert entities[0].value == "merchant@paytm"


def test_enabled_types_filter() -> None:
    """Test filtering detected entities by enabled_types."""
    text = "Email: test@example.com, Phone: +91 9876543210, PAN: ABCDE1234F"
    entities = detect_entities(text, enabled_types=[EntityType.EMAIL, EntityType.PAN_CARD])
    types = {e.entity_type for e in entities}
    assert types == {EntityType.EMAIL.value, EntityType.PAN_CARD.value}
    assert EntityType.PHONE.value not in types
