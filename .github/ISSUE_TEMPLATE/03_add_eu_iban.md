---
name: "[Good First Issue] Add EU / International IBAN Detector"
about: Add a detector for International Bank Account Numbers (IBAN) with ISO 7064 MOD-97 checksum validation.
title: "[Detector Request]: Add EU / International IBAN Detector (MOD-97)"
labels: ["enhancement", "good first issue", "detectors", "help wanted"]
assignees: []
---

## Summary
Add support for detecting and de-identifying **International Bank Account Numbers (IBAN)** across European and global financial systems using regex pattern matching verified by the official **ISO 7064 MOD 97-10** checksum algorithm.

## Background & Specifications
- **Format**: Up to 34 alphanumeric characters (standard EU IBANs are typically 15–31 characters, e.g., Germany `DE89 3704 0044 0532 0130 00`, France `FR14 2004 1010 0505 0001 3M02 606`).
- **Structure**:
  1. 2-letter ISO 3166-1 country code (e.g., `DE`, `FR`, `GB`, `ES`, `IT`).
  2. 2 check digits (values `02` through `98`).
  3. Up to 30 alphanumeric Basic Bank Account Number (BBAN) characters.
- **Validation Algorithm (ISO 7064 MOD 97-10)**:
  1. Remove spaces and convert to uppercase.
  2. Move the first 4 characters (country code + 2 check digits) to the end of the string.
  3. Replace each letter with two digits (`A` -> `10`, `B` -> `11`, ..., `Z` -> `35`).
  4. Interpret the string as a decimal integer: compute `int(digits) % 97`.
  5. The IBAN is valid if and only if `remainder == 1`.
- **Synthetic Token Format**:
  - Must preserve format: e.g. `f"DE99SHDW{short_hash[:10]}00"` with valid ISO MOD-97 check digits so banking APIs accept it.

## Implementation Checklist
- [ ] Add `EntityType.IBAN = "IBAN"` to `shadow_vault/detectors.py`
- [ ] Implement `is_iban_valid(iban_str: str) -> bool` using the ISO 7064 MOD 97-10 algorithm
- [ ] Implement `detect_iban(text: str) -> list[PIIEntity]` with compiled regex and length validation
- [ ] Register `detect_iban` inside `detect_entities()`
- [ ] Implement format-preserving synthetic token generation in `shadow_vault/synthesizer.py`
- [ ] Add unit tests in `tests/test_detectors.py`:
  - Valid German IBAN with spaces
  - Valid French IBAN without spaces
  - Valid British IBAN
  - Corrupted check digits (must be rejected)
  - Non-IBAN alphanumeric strings (must not produce false positives)
  - Round-trip `dehydrate()` and `hydrate()` test
- [ ] Verify test suite passes: `pytest -v`

## Reference Code
See [CONTRIBUTING.md](https://github.com/dhirajparihar/shadow-vault/blob/main/CONTRIBUTING.md) for how to add a regional detector in under 20 lines of code!

