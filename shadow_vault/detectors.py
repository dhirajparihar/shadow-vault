"""
Zero-dependency regex and mathematical checksum PII detectors.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Final, Iterable
from pydantic import BaseModel, ConfigDict, Field


class EntityType(str, Enum):
    """Supported sensitive PII entity types."""

    UPI_ID = "UPI_ID"
    EMAIL = "EMAIL"
    CREDIT_CARD = "CREDIT_CARD"
    AADHAAR = "AADHAAR"
    PAN_CARD = "PAN_CARD"
    PHONE = "PHONE"
    API_KEY = "API_KEY"
    SSN = "SSN"


class DetectedEntity(BaseModel):
    """Immutable representation of an identified PII entity span."""

    model_config = ConfigDict(frozen=True)

    entity_type: str
    value: str
    start: int
    end: int
    score: float = Field(default=1.0, ge=0.0, le=1.0)


# ============================================================================
# Mathematical Checksum Validation: Luhn Algorithm (Credit Cards)
# ============================================================================


def is_luhn_valid(num_str: str) -> bool:
    """Validate string using the standard Luhn (mod 10) algorithm.

    Credit card numbers range from 13 to 19 digits. First digit cannot be 0.
    """
    digits = [int(c) for c in num_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Standard major industry identifiers (MII) are 1-9
    if digits[0] == 0:
        return False

    # All-identical digits (e.g., 000...000 or 111...111) that might trivially pass
    # are rejected if length is purely monotonous without diversity
    if len(set(digits)) == 1:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit

    return checksum % 10 == 0


# ============================================================================
# Mathematical Checksum Validation: Verhoeff Algorithm (Indian Aadhaar)
# ============================================================================

# Multiplication table d (dihedral group D5)
VERHOEFF_D: Final[list[list[int]]] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

# Permutation table p
VERHOEFF_P: Final[list[list[int]]] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

# Inverse table inv
VERHOEFF_INV: Final[list[int]] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def calculate_verhoeff(num_str: str) -> int:
    """Calculate the Verhoeff check digit for a string of digits."""
    digits = [int(c) for c in num_str if c.isdigit()]
    c = 0
    for idx, digit in enumerate(reversed(digits)):
        c = VERHOEFF_D[c][VERHOEFF_P[(idx + 1) % 8][digit]]
    return VERHOEFF_INV[c]


def is_verhoeff_valid(num_str: str) -> bool:
    """Validate string using the dihedral group D5 Verhoeff checksum algorithm.

    Detects 100% of single-digit substitution errors and adjacent transposition errors.
    """
    digits = [int(c) for c in num_str if c.isdigit()]
    if not digits:
        return False

    c = 0
    for idx, digit in enumerate(reversed(digits)):
        c = VERHOEFF_D[c][VERHOEFF_P[idx % 8][digit]]

    return c == 0


# ============================================================================
# Regular Expression Patterns & Known Constants
# ============================================================================

# Known Indian UPI handles (evaluated strictly before Email)
UPI_HANDLES: Final[frozenset[str]] = frozenset(
    {
        "okaxis",
        "okhdfcbank",
        "okicici",
        "oksbi",
        "ybl",
        "ibl",
        "axl",
        "paytm",
        "apl",
        "upi",
    }
)

# UPI regex matching user specification with negative lookahead to prevent matching standard email domains
UPI_REGEX = re.compile(
    r"\b[a-zA-Z0-9.\-_]{2,256}@(?:okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|paytm|apl|upi)\b(?!\.[a-zA-Z])",
    re.IGNORECASE,
)

# Practical RFC-5322 compliant email regex
EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b"
)

# Credit card regex: matches formatted (4-4-4-4, 4-6-5, 4-6-4) or contiguous 13-19 digits
CREDIT_CARD_REGEX = re.compile(
    r"\b(?<!\d)(?:[1-9]\d{3}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}|[1-9]\d{3}[ -]\d{6}[ -]\d{4,5}|[1-9]\d{12,18})(?!\d)\b"
)

# Indian Aadhaar: 12 digits, first digit [2-9], optional space or dash
AADHAAR_REGEX = re.compile(
    r"\b[2-9]{1}[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b"
)

# Indian PAN: 5 uppercase letters, 4 digits, 1 uppercase letter
PAN_CARD_REGEX = re.compile(
    r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    re.IGNORECASE,
)

# US Social Security Number: matches standard format with negative lookaheads for invalid area/group/serial numbers
SSN_REGEX = re.compile(
    r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
)

# API Keys: OpenAI sk-, GitHub PAT ghp-, Google AIza, and Bearer tokens
API_KEY_PATTERNS = [
    r"\bsk-[a-zA-Z0-9\-_]{20,}\b",
    r"\bghp_[a-zA-Z0-9]{36}\b",
    r"\bAIza[0-9A-Za-z\-_]{35}\b",
    r"\b(?:Bearer\s+)[a-zA-Z0-9_\-\.]{20,}\b",
    r"\bgithub_pat_[a-zA-Z0-9_]{82}\b",
    r"\bAKIA[0-9A-Z]{16}\b",
]
API_KEY_REGEX = re.compile("|".join(f"(?:{p})" for p in API_KEY_PATTERNS))

# Phone patterns: Indian mobile (+91), North American NANP, and International E.164
PHONE_INDIAN_REGEX = re.compile(r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}\b")
PHONE_US_REGEX = re.compile(
    r"(?<!\d)(?:(?:\+?1[\s.-]?)?(?:\([0-9]{3}\)|[0-9]{3})[\s.-]?[0-9]{3}[\s.-]?[0-9]{4})\b"
)
PHONE_E164_REGEX = re.compile(r"(?<!\d)\+[1-9]\d{0,3}[\s.-]?(?:\d[\s.-]?){6,12}\d\b")


# Specificity priorities for overlap resolution (higher value = higher precedence)
SPECIFICITY_PRIORITY: Final[dict[str, int]] = {
    EntityType.API_KEY.value: 100,
    EntityType.AADHAAR.value: 90,
    EntityType.CREDIT_CARD.value: 90,
    EntityType.PAN_CARD.value: 85,
    EntityType.SSN.value: 85,
    EntityType.UPI_ID.value: 80,
    EntityType.EMAIL.value: 70,
    EntityType.PHONE.value: 60,
}


# ============================================================================
# Individual Entity Detector Functions
# ============================================================================


def detect_upi_ids(text: str) -> list[DetectedEntity]:
    """Detect Indian UPI IDs (must run before email)."""
    entities: list[DetectedEntity] = []
    for match in UPI_REGEX.finditer(text):
        entities.append(
            DetectedEntity(
                entity_type=EntityType.UPI_ID.value,
                value=match.group(0),
                start=match.start(),
                end=match.end(),
                score=1.0,
            )
        )
    return entities


def detect_emails(text: str) -> list[DetectedEntity]:
    """Detect RFC-5322 emails, ignoring @shadow.vault and known UPI handles."""
    entities: list[DetectedEntity] = []
    for match in EMAIL_REGEX.finditer(text):
        val = match.group(0)
        parts = val.split("@")
        if len(parts) != 2:
            continue

        domain = parts[1].lower()

        # Ignore shadow-vault synthetic domains to prevent recursive re-masking
        if domain == "shadow.vault" or domain.endswith(".shadow.vault"):
            continue

        # Ignore known UPI handles
        domain_without_tld = domain.split(".")[0]
        if domain in UPI_HANDLES or domain_without_tld in UPI_HANDLES:
            continue

        entities.append(
            DetectedEntity(
                entity_type=EntityType.EMAIL.value,
                value=val,
                start=match.start(),
                end=match.end(),
                score=1.0,
            )
        )
    return entities


def detect_credit_cards(text: str) -> list[DetectedEntity]:
    """Detect 13-19 digit credit card numbers validated by Luhn checksum."""
    entities: list[DetectedEntity] = []
    for match in CREDIT_CARD_REGEX.finditer(text):
        raw_val = match.group(0)
        if is_luhn_valid(raw_val):
            entities.append(
                DetectedEntity(
                    entity_type=EntityType.CREDIT_CARD.value,
                    value=raw_val,
                    start=match.start(),
                    end=match.end(),
                    score=1.0,
                )
            )
    return entities


def detect_aadhaar(text: str) -> list[DetectedEntity]:
    """Detect 12-digit Indian Aadhaar numbers validated by Verhoeff checksum."""
    entities: list[DetectedEntity] = []
    for match in AADHAAR_REGEX.finditer(text):
        raw_val = match.group(0)
        digits = [c for c in raw_val if c.isdigit()]
        if len(digits) == 12 and is_verhoeff_valid(raw_val):
            entities.append(
                DetectedEntity(
                    entity_type=EntityType.AADHAAR.value,
                    value=raw_val,
                    start=match.start(),
                    end=match.end(),
                    score=1.0,
                )
            )
    return entities


def detect_pan_cards(text: str) -> list[DetectedEntity]:
    """Detect Indian PAN cards (5 letters, 4 digits, 1 letter)."""
    entities: list[DetectedEntity] = []
    for match in PAN_CARD_REGEX.finditer(text):
        entities.append(
            DetectedEntity(
                entity_type=EntityType.PAN_CARD.value,
                value=match.group(0),
                start=match.start(),
                end=match.end(),
                score=1.0,
            )
        )
    return entities


def detect_phones(text: str) -> list[DetectedEntity]:
    """Detect phone numbers while strictly avoiding collisions with Aadhaar and Credit Cards."""
    candidates: list[tuple[int, int, str]] = []

    # 1. Indian mobile numbers
    for match in PHONE_INDIAN_REGEX.finditer(text):
        candidates.append((match.start(), match.end(), match.group(0)))

    # 2. US / NANP numbers
    for match in PHONE_US_REGEX.finditer(text):
        candidates.append((match.start(), match.end(), match.group(0)))

    # 3. International E.164 numbers
    for match in PHONE_E164_REGEX.finditer(text):
        candidates.append((match.start(), match.end(), match.group(0)))

    entities: list[DetectedEntity] = []
    for start, end, raw_val in candidates:
        digits = [c for c in raw_val if c.isdigit()]
        digit_count = len(digits)

        # Collision avoidance: Reject if candidate is a 12-digit Verhoeff-valid Aadhaar
        if digit_count == 12 and is_verhoeff_valid(raw_val):
            continue

        # Collision avoidance: Reject if candidate is a 13-19 digit Luhn-valid Credit Card
        if 13 <= digit_count <= 19 and is_luhn_valid(raw_val):
            continue

        # Reject unformatted domestic strings that do not meet mobile criteria
        if not raw_val.startswith("+") and "(" not in raw_val and "-" not in raw_val and " " not in raw_val:
            if digit_count != 10 or digits[0] not in "6789":
                continue

        entities.append(
            DetectedEntity(
                entity_type=EntityType.PHONE.value,
                value=raw_val,
                start=start,
                end=end,
                score=0.9,
            )
        )
    return entities


def detect_api_keys(text: str) -> list[DetectedEntity]:
    """Detect sensitive API keys, tokens, and Bearer authorizations."""
    entities: list[DetectedEntity] = []
    for match in API_KEY_REGEX.finditer(text):
        entities.append(
            DetectedEntity(
                entity_type=EntityType.API_KEY.value,
                value=match.group(0),
                start=match.start(),
                end=match.end(),
                score=1.0,
            )
        )
    return entities


def detect_ssns(text: str) -> list[DetectedEntity]:
    """Detect US Social Security Numbers."""
    entities: list[DetectedEntity] = []
    for match in SSN_REGEX.finditer(text):
        entities.append(
            DetectedEntity(
                entity_type=EntityType.SSN.value,
                value=match.group(0),
                start=match.start(),
                end=match.end(),
                score=1.0,
            )
        )
    return entities


# ============================================================================
# Unified Detection Pipeline with Overlap Resolution
# ============================================================================


def detect_entities(
    text: str,
    enabled_types: Iterable[EntityType | str] | None = None,
) -> list[DetectedEntity]:
    """Detect sensitive PII entities with mathematical checksums and overlap resolution.

    Executes detectors in order of strict specificity (UPI before Email), accumulates
    candidates, and resolves overlapping character spans by prioritizing higher
    specificity and longer span lengths.

    Args:
        text: The input text to scan.
        enabled_types: Optional subset of entity types to detect. Defaults to all.

    Returns:
        List of DetectedEntity instances sorted strictly by start index ascending.
    """
    if not text:
        return []

    if enabled_types is not None:
        active_types = {t.value if isinstance(t, EntityType) else str(t) for t in enabled_types}
    else:
        active_types = {e.value for e in EntityType}

    candidates: list[DetectedEntity] = []

    # 1. API Keys (high specificity tokens)
    if EntityType.API_KEY.value in active_types:
        candidates.extend(detect_api_keys(text))

    # 2. Aadhaar (12-digit Indian national ID with Verhoeff checksum)
    if EntityType.AADHAAR.value in active_types:
        candidates.extend(detect_aadhaar(text))

    # 3. Credit Card (13-19 digit card numbers with Luhn checksum)
    if EntityType.CREDIT_CARD.value in active_types:
        candidates.extend(detect_credit_cards(text))

    # 4. PAN Card (Indian tax identity)
    if EntityType.PAN_CARD.value in active_types:
        candidates.extend(detect_pan_cards(text))

    # 5. SSN (US Social Security Number)
    if EntityType.SSN.value in active_types:
        candidates.extend(detect_ssns(text))

    # 6. UPI_ID: MUST run BEFORE EMAIL as required by specification
    if EntityType.UPI_ID.value in active_types:
        candidates.extend(detect_upi_ids(text))

    # 7. EMAIL: RFC-5322 regex ignoring @shadow.vault and UPI handles
    if EntityType.EMAIL.value in active_types:
        candidates.extend(detect_emails(text))

    # 8. PHONE: Domestic and international mobile numbers
    if EntityType.PHONE.value in active_types:
        candidates.extend(detect_phones(text))

    # Overlap Resolution Strategy:
    # Sort candidates by:
    #   1. Higher specificity priority descending
    #   2. Longer span length (end - start) descending
    #   3. Earlier start index ascending
    sorted_candidates = sorted(
        candidates,
        key=lambda entity: (
            -SPECIFICITY_PRIORITY.get(entity.entity_type, 0),
            -(entity.end - entity.start),
            entity.start,
        ),
    )

    accepted_entities: list[DetectedEntity] = []
    for cand in sorted_candidates:
        # Check for any character-level overlap with already accepted entities
        has_overlap = any(
            max(cand.start, acc.start) < min(cand.end, acc.end)
            for acc in accepted_entities
        )
        if not has_overlap:
            accepted_entities.append(cand)

    # Return final non-overlapping entities ordered by start index ascending
    accepted_entities.sort(key=lambda entity: entity.start)
    return accepted_entities
