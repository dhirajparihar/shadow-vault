"""
Format-preserving synthetic token generator and validation markers.
"""

from __future__ import annotations

from typing import Final
from shadow_vault.detectors import EntityType, calculate_verhoeff


# Known prefixes used by synthetic tokens for streaming holdback and identification
SYNTHETIC_PREFIXES: Final[tuple[str, ...]] = (
    "u_",
    "SHDWV",
    "+919000",
    "400000999",
    "99990",
    "sk-sv-shadow-",
    "900-99-",
    "synth_",
)


def calculate_luhn_check_digit(prefix: str) -> int:
    """Calculate the Luhn check digit for a credit card prefix.

    For a 15-digit prefix (becoming a 16-digit card), the check digit sits at
    the rightmost position (index 0, weight 1), so the last digit of the prefix
    gets multiplied by 2 (weight 2).
    """
    digits = [int(c) for c in prefix if c.isdigit()]
    checksum = 0
    for idx, digit in enumerate(reversed(digits)):
        if idx % 2 == 0:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return (10 - (checksum % 10)) % 10


def synthesize_token(entity_type: str | EntityType, short_hash: str) -> str:
    """Generate a format-preserving synthetic token from entity type and hash.

    Synthetic values pass standard format validators (emails, Luhn cards,
    Verhoeff Aadhaar, PAN format, etc.) and carry distinctive prefixes for detection.

    Args:
        entity_type: Categorical PII entity type.
        short_hash: Deterministic 6-character hex hash (e.g. 'c09753').

    Returns:
        A format-preserving synthetic string token.
    """
    type_str = entity_type.value if isinstance(entity_type, EntityType) else str(entity_type).upper()
    int_val = int(short_hash, 16) if short_hash else 0

    if type_str == EntityType.EMAIL.value:
        return f"u_{short_hash}@shadow.vault"

    elif type_str == EntityType.UPI_ID.value:
        return f"u_{short_hash}@okshadow"

    elif type_str == EntityType.PHONE.value:
        d6 = f"{int_val % 1_000_000:06d}"
        return f"+919000{d6}"

    elif type_str == EntityType.PAN_CARD.value:
        d4 = f"{int_val % 10_000:04d}"
        return f"SHDWV{d4}Z"

    elif type_str == EntityType.CREDIT_CARD.value:
        d6 = f"{int_val % 1_000_000:06d}"
        prefix = f"400000999{d6}"
        cd = calculate_luhn_check_digit(prefix)
        return f"{prefix}{cd}"

    elif type_str == EntityType.AADHAAR.value:
        d6 = f"{int_val % 1_000_000:06d}"
        prefix = f"99990{d6}"
        cd = calculate_verhoeff(prefix)
        return f"{prefix}{cd}"

    elif type_str == EntityType.API_KEY.value:
        return f"sk-sv-shadow-{short_hash}00000000000000"

    elif type_str == EntityType.SSN.value:
        d4 = f"{int_val % 10_000:04d}"
        return f"900-99-{d4}"

    else:
        # Fallback for arbitrary entity types
        return f"synth_{type_str.lower()}_{short_hash}"


def is_synthetic(val: str) -> bool:
    """Return True if the given string is an already generated synthetic token.

    Prevents double-dehydration when processing data recursively or across pipeline steps.
    """
    if not isinstance(val, str) or not val:
        return False

    # Email
    if val.endswith("@shadow.vault") or "@shadow.vault" in val:
        return True

    # UPI
    if val.endswith("@okshadow"):
        return True

    # Phone
    if val.startswith("+919000") or val.startswith("919000"):
        return True

    # PAN Card
    if val.startswith("SHDWV") and val.endswith("Z") and len(val) == 10:
        return True

    # Credit Card
    if val.startswith("400000999") and len(val) == 16 and val.isdigit():
        return True

    # Aadhaar
    if val.startswith("99990") and len(val) == 12 and val.isdigit():
        return True

    # API Key
    if val.startswith("sk-sv-shadow-"):
        return True

    # SSN
    if val.startswith("900-99-") and len(val) == 11:
        return True

    # Fallback generic synthetic prefix
    if val.startswith("synth_"):
        return True

    return False
