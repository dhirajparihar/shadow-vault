"""
ShadowVault Reproducible Verification & Security Self-Audit CLI.

Execute via:
    python -m shadow_vault.verify
"""

from __future__ import annotations

import platform
import sys
import time

from shadow_vault.crypto import (
    HAS_CRYPTOGRAPHY,
    blind_index,
    decrypt_value,
    derive_key,
    encrypt_value,
)
from shadow_vault.detectors import (
    calculate_verhoeff,
    detect_entities,
    is_luhn_valid,
    is_verhoeff_valid,
)
from shadow_vault.engine import ShadowVault
from shadow_vault.policy import FailClosedAction, PolicyManager, ToolPolicy, UnmappedTokenError
from shadow_vault.store import VaultStore
from shadow_vault.stream import StreamHydrator
from shadow_vault.synthesizer import calculate_luhn_check_digit


def run_verification() -> bool:
    print("=" * 76)
    print("        SHADOWVAULT INDEPENDENT SECURITY & REPRODUCIBILITY AUDIT")
    print("=" * 76)
    print(f"Platform:      {platform.platform()}")
    print(f"Python:        {sys.version.split()[0]} ({platform.python_implementation()})")
    print(f"Cryptography:  {'AES-256-GCM (OpenSSL)' if HAS_CRYPTOGRAPHY else 'BLAKE2b + HMAC (Stdlib Fallback)'}")
    print(f"Timestamp:     {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("-" * 76)

    passed_count = 0
    total_checks = 6

    # --- Check 1: Cryptographic Envelope & AEAD Integrity ---
    print("\n[Check 1/6] Cryptographic AEAD Roundtrip & Tamper Rejection...", end=" ")
    try:
        key = derive_key("audit-secret-key-0x40")
        plaintext = "Patient EHR Medical Record #998822"
        ciphertext = encrypt_value(plaintext, key)
        assert decrypt_value(ciphertext, key) == plaintext

        # Tamper test
        prefix, b64 = ciphertext.rsplit(":", 1)
        tampered_char = "B" if b64[-2] == "A" else "A"
        tampered_ciphertext = f"{prefix}:{b64[:-2]}{tampered_char}{b64[-1]}"
        try:
            decrypt_value(tampered_ciphertext, key)
            raise AssertionError("Tampered ciphertext was NOT rejected!")
        except ValueError:
            pass  # Expected rejection

        print("PASSED")
        passed_count += 1
    except Exception as exc:
        print(f"FAILED ({exc})")

    # --- Check 2: Blind Index Independence & Session Isolation ---
    print("[Check 2/6] Blind Index Independence & Cross-Session Isolation...", end=" ")
    try:
        key = derive_key("blind-index-key-0x40")
        val = "user.executive@fintech.com"
        idx_a = blind_index(key, "session_alpha", val)
        idx_b = blind_index(key, "session_beta", val)
        assert idx_a != idx_b, "Blind indexes must be isolated across sessions!"
        assert blind_index(key, "session_alpha", val) == idx_a, "Blind index must be deterministic within session!"
        print("PASSED")
        passed_count += 1
    except Exception as exc:
        print(f"FAILED ({exc})")

    # --- Check 3: Mathematical Checksums (Luhn & Verhoeff) ---
    print("[Check 3/6] Checksum Integrity (Luhn Mod 10 & Verhoeff D5)...", end=" ")
    try:
        # Luhn Modulo 10
        card_prefix = "400000123456789"
        check_digit = calculate_luhn_check_digit(card_prefix)
        full_card = f"{card_prefix}{check_digit}"
        assert is_luhn_valid(full_card), "Generated card must pass Luhn!"
        assert not is_luhn_valid("4000001234567891"), "Invalid card must fail Luhn!"

        # Verhoeff Dihedral D5
        aadhaar_base = "99991234567"
        v_check = calculate_verhoeff(aadhaar_base)
        full_aadhaar = f"{aadhaar_base}{v_check}"
        assert is_verhoeff_valid(full_aadhaar), "Generated Aadhaar must pass Verhoeff!"
        assert not is_verhoeff_valid("999912345670"), "Invalid Aadhaar must fail Verhoeff!"
        print("PASSED")
        passed_count += 1
    except Exception as exc:
        print(f"FAILED ({exc})")

    # --- Check 4: Format-Preserving Engine Roundtrip ---
    print("[Check 4/6] Format-Preserving Token Dehydration & Hydration...", end=" ")
    try:
        vault = ShadowVault(encryption_key="roundtrip-key")
        raw_text = "Send receipt to john@corp.io for card 4532 0151 1283 0366 (PAN: ABCDE1234F)"
        dehydrated = vault.dehydrate(raw_text, session_id="v_sess")
        assert "john@corp.io" not in dehydrated
        assert "4532 0151 1283 0366" not in dehydrated
        assert "ABCDE1234F" not in dehydrated

        # Hydrate back
        hydrated = vault.hydrate(dehydrated, session_id="v_sess")
        assert hydrated == raw_text
        print("PASSED")
        passed_count += 1
    except Exception as exc:
        print(f"FAILED ({exc})")

    # --- Check 5: Lookahead Holdback SSE Stream Re-Hydration ---
    print("[Check 5/6] StreamHydrator Lookahead Buffer (Torn Token Reassembly)...", end=" ")
    try:
        vault = ShadowVault()
        sess = "stream_sess"
        token = vault.dehydrate("alice@shadow.vault", session_id=sess)
        # Even if model emits single-character fragments, StreamHydrator reassembles them
        hydrator = StreamHydrator(vault=vault, session_id=sess)
        reconstructed = "".join(hydrator.process_chunk(char) for char in f"Notice sent to {token}.")
        reconstructed += hydrator.flush()
        assert reconstructed == "Notice sent to alice@shadow.vault."
        print("PASSED")
        passed_count += 1
    except Exception as exc:
        print(f"FAILED ({exc})")

    # --- Check 6: Fail-Closed Policy Enforcement ---
    print("[Check 6/6] Fail-Closed Governance & Leak Interception...", end=" ")
    try:
        policy_mgr = PolicyManager(default_fail_closed=True, default_fail_action=FailClosedAction.RAISE)
        strict_vault = ShadowVault(policy_manager=policy_mgr, fail_closed=True)
        # Unmapped synthetic token must raise
        try:
            strict_vault.hydrate("Hello u_c09753@shadow.vault", session_id="unknown_sess")
            raise AssertionError("Unmapped token in fail-closed mode did NOT raise!")
        except UnmappedTokenError:
            pass

        print("PASSED")
        passed_count += 1
    except Exception as exc:
        print(f"FAILED ({exc})")

    print("-" * 76)
    if passed_count == total_checks:
        print(f"AUDIT RESULT: {passed_count}/{total_checks} CHECKS PASSED (100% VERIFIED)")
        print("Status: Verified Ready for Agent Integration & Deployment.")
        print("=" * 76 + "\n")
        return True
    else:
        print(f"AUDIT RESULT: {passed_count}/{total_checks} CHECKS PASSED (FAILURES DETECTED)")
        print("=" * 76 + "\n")
        return False


if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
