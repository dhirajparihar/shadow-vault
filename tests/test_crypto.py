"""
Unit tests for ShadowVault cryptographic envelope encryption and blind indexing.
"""

from __future__ import annotations

import pytest
from shadow_vault.crypto import (
    blind_index,
    decrypt_value,
    derive_key,
    encrypt_value,
)


def test_derive_key_length_and_determinism() -> None:
    """Test PBKDF2 key derivation produces 32-byte deterministic keys."""
    key1 = derive_key("my-secret-vault-password")
    key2 = derive_key("my-secret-vault-password")
    key3 = derive_key("different-password")

    assert len(key1) == 32
    assert key1 == key2
    assert key1 != key3


def test_encrypt_and_decrypt_round_trip() -> None:
    """Test encrypt and decrypt round trip preserves plaintext."""
    key = derive_key("super-secret-key-123")
    plaintext = "Sensitive Patient Record: SSN 900-99-1234, Card 4000 0099 9123 4567"

    ciphertext = encrypt_value(plaintext, key)
    assert ciphertext != plaintext
    assert "enc:" in ciphertext
    assert "900-99-1234" not in ciphertext
    assert "4000 0099 9123 4567" not in ciphertext

    decrypted = decrypt_value(ciphertext, key)
    assert decrypted == plaintext


def test_tampered_ciphertext_rejection() -> None:
    """Test that modifying ciphertext bits causes HMAC verification failure."""
    key = derive_key("encryption-key-abc")
    plaintext = "4532 0151 1283 0366"
    ciphertext = encrypt_value(plaintext, key)

    # Tamper with the base64 payload
    prefix, b64_payload = ciphertext.rsplit(":", 1)
    tampered_b64 = b64_payload[:-2] + ("A" if b64_payload[-2] != "A" else "B") + b64_payload[-1]
    tampered_ciphertext = f"{prefix}:{tampered_b64}"

    with pytest.raises(
        ValueError,
        match="verification failed|corrupted|Truncated",
    ):
        decrypt_value(tampered_ciphertext, key)


def test_wrong_key_rejection() -> None:
    """Test that decrypting with the wrong key is rejected."""
    key_alice = derive_key("alice-secret-key")
    key_bob = derive_key("bob-secret-key")

    ciphertext = encrypt_value("secret-card-data", key_alice)
    with pytest.raises(
        ValueError,
        match="verification failed|corrupted",
    ):
        decrypt_value(ciphertext, key_bob)


def test_blind_index_deterministic_and_irreversible() -> None:
    """Test HMAC blind index is deterministic for matching inputs and distinct across sessions."""
    key = derive_key("master-vault-key")
    session1 = "sess_fintech_1"
    session2 = "sess_fintech_2"
    val = "user@domain.com"

    idx1_a = blind_index(key, session1, val)
    idx1_b = blind_index(key, session1, val)
    idx2 = blind_index(key, session2, val)

    assert idx1_a == idx1_b
    assert idx1_a != idx2
    assert val not in idx1_a


def test_stdlib_fallback_cipher_explicit() -> None:
    """Explicitly verify zero-dependency stdlib keystream fallback cipher."""
    from shadow_vault.crypto import _stdlib_decrypt, _stdlib_encrypt

    key = derive_key("fallback-key-999")
    plaintext = "Fallback Keystream Token: 4532 0151 1283 0366"
    token = _stdlib_encrypt(plaintext.encode("utf-8"), key)

    assert token.startswith("enc:std:v1:")
    decrypted_bytes = _stdlib_decrypt(token, key)
    assert decrypted_bytes.decode("utf-8") == plaintext

    # Tamper test on stdlib token
    tampered = token[:-2] + ("X" if token[-2] != "X" else "Y") + token[-1]
    with pytest.raises(ValueError, match="HMAC verification failed"):
        _stdlib_decrypt(tampered, key)

