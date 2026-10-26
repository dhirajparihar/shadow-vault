"""
Comprehensive Adversarial Security Test Suite for ShadowVault.

Tests cover:
- Cross-tenant / cross-session isolation and boundary enforcement
- Tampered ciphertext rejection across AEAD ciphers
- SQL injection resilience in session IDs, entities, and values
- High-concurrency race condition and collision resilience (50 threads)
- Fail-closed leakage blocking on adversarial tool returns
- Blind index entropy and cross-session correlation resistance
- Enforcement of require_encryption and unencrypted disk storage warnings
"""

from __future__ import annotations

import concurrent.futures
import os
import tempfile
import threading
import pytest

from shadow_vault.crypto import (
    blind_index,
    decrypt_value,
    derive_key,
    encrypt_value,
)
from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.decorators import vault_guard
from shadow_vault.policy import (
    FailClosedAction,
    PIILeakBlockedError,
    PolicyManager,
    ToolPolicy,
    UnmappedTokenError,
)
from shadow_vault.store import VaultStore


def test_adversarial_cross_session_isolation() -> None:
    """Verify that synthetic tokens generated in Session A CANNOT hydrate in Session B."""
    key = "master-key-session-isolation-test"
    vault = ShadowVault(encryption_key=key, fail_closed=True)

    # Session A generates token
    raw_prompt_a = "Contact alice@fintech.io regarding card 4532 0151 1283 0366"
    dehydrated_a = vault.dehydrate(raw_prompt_a, session_id="tenant_alpha")
    assert "alice@fintech.io" not in dehydrated_a
    assert "4532 0151 1283 0366" not in dehydrated_a

    # Attacker in Session B attempts to pass Session A's dehydrated string
    with pytest.raises(UnmappedTokenError):
        vault.hydrate(dehydrated_a, session_id="tenant_beta")

    # In permissive mode, unmapped token is left intact but NEVER resolves to Session A's real value
    vault_permissive = ShadowVault(encryption_key=key, fail_closed=False)
    resolved_b = vault_permissive.hydrate(dehydrated_a, session_id="tenant_beta")
    assert "alice@fintech.io" not in resolved_b
    assert "4532 0151 1283 0366" not in resolved_b


def test_adversarial_tampered_ciphertext_rejection() -> None:
    """Verify that bit-flipping at any position in AEAD payload triggers rejection."""
    key = derive_key("master-tamper-key-42")
    plaintext = "Sensitive KYC Passport: X99887766"
    ciphertext = encrypt_value(plaintext, key)

    prefix, b64_payload = ciphertext.rsplit(":", 1)
    # Flip multiple byte positions in the base64 payload
    for flip_idx in [0, len(b64_payload) // 2, len(b64_payload) - 2]:
        tampered_char = "Z" if b64_payload[flip_idx] != "Z" else "A"
        tampered_b64 = b64_payload[:flip_idx] + tampered_char + b64_payload[flip_idx + 1 :]
        tampered_ciphertext = f"{prefix}:{tampered_b64}"

        with pytest.raises(ValueError, match="verification failed|corrupted|Truncated"):
            decrypt_value(tampered_ciphertext, key)


def test_adversarial_sql_injection_resistance() -> None:
    """Verify parameterized queries prevent SQL injection across all parameters."""
    store = VaultStore(db_path=":memory:", encryption_key="sql-test-key")

    malicious_inputs = [
        "admin' OR '1'='1' --",
        "'; DROP TABLE mappings; --",
        "Robert'); DROP TABLE mappings;--",
        "' UNION SELECT * FROM mappings --",
        "x' AND 1=(SELECT COUNT(*) FROM mappings) --",
    ]

    for malicious_str in malicious_inputs:
        # Attempt injection via session_id
        synth = store.get_or_create(
            session_id=malicious_str,
            entity_type="EMAIL",
            real_val="victim@domain.com",
            generator_fn=lambda et, h: f"u_{h}@shadow.vault",
        )
        assert synth.startswith("u_")

        # Verify mappings table is still intact and queryable
        assert store.count(session_id=malicious_str) == 1
        real = store.get_real_val(malicious_str, synth)
        assert real == "victim@domain.com"

        # Attempt injection via real_val
        synth_inj = store.get_or_create(
            session_id="safe_session",
            entity_type="API_KEY",
            real_val=malicious_str,
            generator_fn=lambda et, h: f"sk-sv-shadow-{h}",
        )
        assert store.get_real_val("safe_session", synth_inj) == malicious_str

    store.close()


def test_adversarial_high_concurrency_race() -> None:
    """Stress test: 50 concurrent threads writing and reading mappings in SQLite simultaneously."""
    store = VaultStore(db_path=":memory:", encryption_key="concurrency-stress-key")
    session_id = "concurrent_stress_session"
    num_threads = 50
    items_per_thread = 20

    errors: list[Exception] = []

    def worker(thread_id: int) -> None:
        try:
            for i in range(items_per_thread):
                val = f"user_{thread_id}_{i}@fintech.io"
                synth = store.get_or_create(
                    session_id=session_id,
                    entity_type="EMAIL",
                    real_val=val,
                    generator_fn=lambda et, h: f"u_{h}@shadow.vault",
                )
                assert synth.endswith("@shadow.vault")
                # Immediately read it back
                resolved = store.get_real_val(session_id, synth)
                assert resolved == val
        except Exception as exc:
            errors.append(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, tid) for tid in range(num_threads)]
        concurrent.futures.wait(futures)

    assert not errors, f"Concurrency errors encountered: {errors}"
    assert store.count(session_id) == num_threads * items_per_thread
    store.close()


def test_adversarial_fail_closed_leak_prevention() -> None:
    """Verify that fail-closed mode actively blocks rogue tools from returning raw unmasked PII."""
    policy_mgr = PolicyManager(default_fail_closed=True, default_fail_action=FailClosedAction.RAISE)
    vault = ShadowVault(policy_manager=policy_mgr, fail_closed=True)

    # 1. Direct engine assertion raises on unmasked PII
    with pytest.raises(PIILeakBlockedError, match="Fail-closed policy violation: Unmasked PII"):
        vault.assert_no_pii_leak({"card": "4532 0151 1283 0366"})

    # 2. Guard with block_leaks=True blocks rogue tool returning raw PII
    @vault_guard(vault=vault, session_id_arg="session_id", block_leaks=True)
    def rogue_tool_leaking_pii(session_id: str = "default") -> dict:
        return {
            "status": "EXFILTRATING",
            "leaked_card": "4532 0151 1283 0366",
        }

    with pytest.raises(PIILeakBlockedError, match="Fail-closed policy violation: Unmasked PII"):
        rogue_tool_leaking_pii(session_id="leak_test_sess")

    # 3. ToolPolicy with block_raw_tool_returns=True also blocks raw PII return
    strict_policy = ToolPolicy(
        tool_name="strict_external_api",
        block_raw_tool_returns=True,
    )
    policy_mgr.register_policy(strict_policy)

    @vault_guard(vault=vault, policy=strict_policy, session_id_arg="session_id")
    def strict_external_api(session_id: str = "default") -> dict:
        return {"account": "admin@secret.org"}

    with pytest.raises(PIILeakBlockedError):
        strict_external_api(session_id="leak_test_sess")


def test_adversarial_blind_index_no_entropy_leak() -> None:
    """Verify blind index values differ across sessions and keys (preventing rainbow correlation)."""
    key1 = derive_key("key-tenant-1")
    key2 = derive_key("key-tenant-2")
    real_val = "secret.employee@enterprise.com"

    idx1_sess1 = blind_index(key1, "session_1", real_val)
    idx1_sess2 = blind_index(key1, "session_2", real_val)
    idx2_sess1 = blind_index(key2, "session_1", real_val)

    # Identical plaintext across different sessions MUST produce different blind indexes
    assert idx1_sess1 != idx1_sess2
    # Identical plaintext across different keys MUST produce different blind indexes
    assert idx1_sess1 != idx2_sess1
    # Repeated call on same key and session MUST be deterministic
    assert blind_index(key1, "session_1", real_val) == idx1_sess1


def test_require_encryption_enforcement() -> None:
    """Verify require_encryption raises ValueError when key is missing, and file storage warns."""
    # 1. require_encryption=True without key raises
    with pytest.raises(ValueError, match="requires an encryption key"):
        VaultStore(db_path=":memory:", require_encryption=True)

    # 2. engine level require_encryption=True raises
    with pytest.raises(ValueError, match="requires an encryption key"):
        ShadowVault(require_encryption=True)

    # 3. Persistent file storage without key raises a UserWarning
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_file = tmp.name

    try:
        with pytest.warns(UserWarning, match="without an encryption key"):
            store = VaultStore(db_path=db_file)
            store.close()
    finally:
        if os.path.exists(db_file):
            os.unlink(db_file)
