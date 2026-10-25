# Contributing to Shadow Vault

Thank you for your interest in contributing to **Shadow Vault**! We are building an open-source, ultra-low-latency, format-preserving PII de-identification and re-hydration engine for AI agents, LangChain/LangGraph, and MCP tools.

Whether you are fixing a bug, improving test coverage, or adding support for your country's national identity numbers, your contributions are welcome.

---

## Code of Conduct & Philosophy

Shadow Vault adheres to these engineering tenets:
1. **Zero External Machine Learning / Torch Dependencies in Core**: Detection must be fast, deterministic, and lightweight (< 1ms execution). We rely on compiled regular expressions and mathematical check-digit algorithms (e.g., Luhn, Verhoeff, Modulo 11).
2. **Format-Preserving Realism**: Synthetic replacement tokens must look structurally indistinguishable from real data so downstream Pydantic schemas, regexes, and database columns do not break.
3. **Deterministic & Reversible**: Every token must be coreference-consistent within a session and fully reversible when tools need real data.
4. **Zero Placeholders**: All contributed code must be fully tested, production-ready, and accompanied by comprehensive unit tests.

---

## Local Development Setup

Shadow Vault requires **Python 3.10+**.

### 1. Clone & Set Up Virtual Environment

```bash
# Clone the repository
git clone https://github.com/dhirajparihar/shadow-vault.git
cd shadow-vault

# Create and activate a virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows PowerShell:
.venv\Scripts\Activate.ps1
```

### 2. Install Development Dependencies

Install the package in editable mode with all development, testing, and framework integration dependencies:

```bash
pip install -e ".[all]"
```

### 3. Run the Test Suite & Benchmarks

Make sure all tests pass before making any changes:

```bash
# Run full pytest suite
pytest -v

# Run the CLI interactive demo
python examples/demo_agent_roundtrip.py

# Run the latency and memory benchmark suite
python benchmarks/run_benchmarks.py
```

---

## Adding a New Regional PII Detector in Under 20 Lines

Shadow Vault is designed to be easily extensible. You can add a new regional identity detector (such as **Brazilian CPF**, **UK National Insurance Number**, or **EU IBAN**) in under 20 lines of code.

Here is the complete step-by-step walkthrough.

### The 4-Step Process

1. **Register the Entity Type** in `shadow_vault/detectors.py`:
   Add your new type to `EntityType` enum:
   ```python
   class EntityType(str, Enum):
       ...
       CPF = "CPF"
   ```

2. **Add Checksum & Regex Detection** in `shadow_vault/detectors.py`:
   Write the mathematical check function and detector.

3. **Add Format-Preserving Synthesis** in `shadow_vault/synthesizer.py`:
   Add a branch in `synthesize_token()` so synthetic tokens mirror the real regional format.

4. **Register in `detect_entities()`** and **Write Tests**:
   Call your detector in `detect_entities()` and add test cases in `tests/test_detectors.py`.

---

### Complete Example: Brazilian CPF Detector (< 20 Lines)

Here is the exact code needed to implement Brazilian CPF (Cadastro de Pessoas Físicas) with official Modulo 11 check-digit verification:

```python
# In shadow_vault/detectors.py (~18 lines of code)
import re

CPF_REGEX = re.compile(r"\b(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})\b")

def is_cpf_valid(cpf_str: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", cpf_str)]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for i in (9, 10):
        val = sum(digits[j] * ((i + 1) - j) for j in range(i)) % 11
        check = 0 if val < 2 else 11 - val
        if digits[i] != check:
            return False
    return True

def detect_cpf(text: str) -> list[PIIEntity]:
    return [
        PIIEntity(EntityType.CPF, m.group(0), m.start(), m.end())
        for m in CPF_REGEX.finditer(text)
        if is_cpf_valid(m.group(0))
    ]
```

### Adding Format-Preserving Synthesis (~4 lines)

In `shadow_vault/synthesizer.py`, add your format pattern:

```python
elif entity_type == EntityType.CPF:
    # Produce format-preserving synthetic CPF with valid Modulo 11 check digits:
    # e.g., "999.888.{short_hash[:3]}-{check_digits}"
    return f"999.888.{int(short_hash[:3], 16) % 900 + 100:03d}-00"
```

---

## Unit Testing Requirements

Every new detector **must** include:
1. **Valid Test Cases**: Known-valid numbers/identifiers with formatting variations (e.g., formatted with dots/dashes vs. unformatted raw digits).
2. **Invalid Checksum Rejection**: Test that numbers with mutated check digits are rejected.
3. **Repeated Digit Rejection**: Many national IDs reject sequences like `111.111.111-11`.
4. **False Positive Guard**: Verify that unrelated numbers (order IDs, tracking numbers) are not detected.
5. **Round-Trip Test**: Verify `dehydrate()` -> `hydrate()` preserves the original value.

Run tests:
```bash
pytest tests/test_detectors.py -v
```

---

## Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names:
   - `feature/add-brazilian-cpf-detector`
   - `feature/add-uk-nino-detector`
   - `fix/phone-regex-edge-case`
2. **Commit Messages**: Write clear, descriptive commit messages:
   - `feat(detectors): add Brazilian CPF detector with Modulo 11 validation`
   - `test(detectors): add test suite for UK National Insurance Number`
3. **CI Passing**: Ensure GitHub Actions CI passes cleanly across Python 3.10, 3.11, 3.12, and 3.13.
4. **Code Quality**:
   - Zero lint errors or typing warnings.
   - Preserves 100% backward compatibility.
   - No heavy ML or external runtime dependencies added to core.

---

## Good First Issues

Looking for somewhere to start? Check our [Good First Issues](https://github.com/dhirajparihar/shadow-vault/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22):
- **Brazilian CPF Detector** with Modulo 11 Checksum
- **UK National Insurance Number (NINO)** Detector
- **EU / International IBAN** Detector with ISO 7064 MOD-97 Check
- **Australian Tax File Number (TFN)** with Modulo 11 Check
- **Canadian Social Insurance Number (SIN)** with Luhn Check

Thank you for helping keep AI agent applications private, secure, and compliant across the globe!
