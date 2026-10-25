---
name: "[Good First Issue] Add Brazilian CPF Detector"
about: Add a regional detector for Brazilian CPF (Cadastro de Pessoas Físicas) with Modulo 11 checksum validation.
title: "[Detector Request]: Add Brazilian CPF Detector (Modulo 11)"
labels: ["enhancement", "good first issue", "detectors", "help wanted"]
assignees: []
---

## Summary
Add support for detecting and de-identifying **Brazilian CPF** (Cadastro de Pessoas Físicas) numbers using regex matching paired with official **Modulo 11** dual check-digit verification.

## Background & Specifications
- **Format**: 11 digits, commonly formatted as `XXX.XXX.XXX-XX` (e.g., `123.456.789-09`) or raw 11 digits `XXXXXXXXXXX`.
- **Validation Algorithm**:
  1. CPF cannot consist of 11 identical digits (e.g., `111.111.111-11` is invalid).
  2. First check digit (10th digit): `sum(d[i] * (10 - i) for i in range(9)) * 10 % 11` (if 10, check digit is 0).
  3. Second check digit (11th digit): `sum(d[i] * (11 - i) for i in range(10)) * 10 % 11` (if 10, check digit is 0).
- **Synthetic Token Format**:
  - Must preserve format: `f"999.888.{num:03d}-{check:02d}"` or deterministic synthetic pattern that passes format checkers and is recognized by `StreamHydrator`.

## Implementation Checklist
- [ ] Add `EntityType.CPF = "CPF"` to `shadow_vault/detectors.py`
- [ ] Implement `is_cpf_valid(cpf_str: str) -> bool` using Modulo 11
- [ ] Implement `detect_cpf(text: str) -> list[PIIEntity]` with compiled regex
- [ ] Register `detect_cpf` inside `detect_entities()`
- [ ] Implement synthetic token generation for `EntityType.CPF` in `shadow_vault/synthesizer.py`
- [ ] Add unit tests in `tests/test_detectors.py`:
  - Valid CPF with dots and dash
  - Valid unformatted CPF (11 digits)
  - Invalid check digits (must be rejected)
  - All identical digits (e.g. `000.000.000-00`, must be rejected)
  - Round-trip `dehydrate()` and `hydrate()` test
- [ ] Verify test suite passes: `pytest -v`

## Reference Code
See [CONTRIBUTING.md](https://github.com/dhirajparihar/shadow-vault/blob/main/CONTRIBUTING.md) for a complete reference implementation in under 20 lines of code!

