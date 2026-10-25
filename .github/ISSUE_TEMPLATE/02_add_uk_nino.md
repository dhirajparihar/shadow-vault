---
name: "[Good First Issue] Add UK National Insurance Number (NINO) Detector"
about: Add a regional detector for UK National Insurance Numbers (NINO) with strict prefix and suffix validation.
title: "[Detector Request]: Add UK National Insurance Number (NINO) Detector"
labels: ["enhancement", "good first issue", "detectors", "help wanted"]
assignees: []
---

## Summary
Add support for detecting and de-identifying **UK National Insurance Numbers (NINO)** used in the United Kingdom for taxation, social security, and national healthcare administration.

## Background & Specifications
- **Format**: 9 characters consisting of 2 prefix letters, 6 digits, and 1 suffix letter (e.g., `QQ 12 34 56 A` or `QQ123456A`).
- **Official HMRC Formatting Rules**:
  1. **First letter**: Any letter except `D`, `F`, `I`, `Q`, `U`, `V`.
  2. **Second letter**: Any letter except `D`, `F`, `I`, `O`, `Q`, `U`, `V`.
  3. **Disallowed prefixes**: Combinations `BG`, `GB`, `KN`, `NK`, `NT`, `TN`, `ZZ` are administrative or reserved and not valid citizen NINOs.
  4. **Middle 6 characters**: Digits `0-9`.
  5. **Suffix letter**: Must be `A`, `B`, `C`, `D` (or space in legacy records).
- **Synthetic Token Format**:
  - Must preserve format: e.g., `f"SH {short_hash_digits:06d} Z"` or `f"SV{d6}A"`.

## Implementation Checklist
- [ ] Add `EntityType.UK_NINO = "UK_NINO"` to `shadow_vault/detectors.py`
- [ ] Implement `is_uk_nino_valid(nino_str: str) -> bool` checking HMRC character rules
- [ ] Implement `detect_uk_nino(text: str) -> list[PIIEntity]` with compiled regex
- [ ] Register `detect_uk_nino` inside `detect_entities()`
- [ ] Implement format-preserving synthetic token generation in `shadow_vault/synthesizer.py`
- [ ] Add unit tests in `tests/test_detectors.py`:
  - Valid NINO with spaces: `"QQ 12 34 56 A"`
  - Valid NINO without spaces: `"AB123456C"`
  - Invalid prefix characters (e.g. starting with `D` or `F`)
  - Disallowed combination (e.g. starting with `GB` or `ZZ`)
  - Invalid suffix letter (e.g. ending in `X` or `Z`)
  - Round-trip `dehydrate()` and `hydrate()` test
- [ ] Verify test suite passes: `pytest -v`

## Reference Code
See [CONTRIBUTING.md](https://github.com/dhirajparihar/shadow-vault/blob/main/CONTRIBUTING.md) for how to add a regional detector in under 20 lines of code!

