"""
Cryptographic envelope encryption and blind indexing for ShadowVault storage.

Supports AES-256-GCM authenticated encryption if `cryptography` is available,
with a secure zero-dependency authenticated keystream fallback (BLAKE2b-CTR + HMAC-SHA256)
to guarantee security even without external C-extensions.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Final

# Prefix identifiers to allow versioning and cipher negotiation
CIPHER_PREFIX_AESGCM: Final[str] = "enc:gcm:v1:"
CIPHER_PREFIX_STDLIB: Final[str] = "enc:std:v1:"

# Check for cryptography library
_HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    AESGCM = None  # type: ignore


def derive_key(secret: str | bytes, salt: bytes = b"shadow-vault-v1-salt") -> bytes:
    """Derive a 256-bit (32-byte) cryptographic key from a secret string or bytes.

    Uses HKDF-like PBKDF2-HMAC-SHA256 derivation.
    """
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    else:
        secret_bytes = secret

    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=secret_bytes,
        salt=salt,
        iterations=100_000,
        dklen=32,
    )


def blind_index(key: bytes, session_id: str, real_val: str) -> str:
    """Compute a cryptographically keyed blind index for fast SQLite lookups.

    Uses HMAC-SHA256 to ensure third parties with read-only access to SQLite
    cannot deduce or brute-force real values from the index.
    """
    data = f"{session_id}:{real_val}".encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _stdlib_encrypt(plaintext_bytes: bytes, key: bytes) -> str:
    """Authenticated encryption using standard library primitives (BLAKE2b-CTR + HMAC)."""
    # 16-byte random IV/nonce
    nonce = secrets.token_bytes(16)

    # Generate keystream blocks using BLAKE2b in counter mode
    ciphertext = bytearray(len(plaintext_bytes))
    block_size = 64
    counter = 0

    for offset in range(0, len(plaintext_bytes), block_size):
        chunk = plaintext_bytes[offset : offset + block_size]
        # Counter block
        ctr_bytes = counter.to_bytes(8, byteorder="big")
        keystream = hashlib.blake2b(
            nonce + ctr_bytes, key=key, digest_size=len(chunk), person=b"sv-keystr"
        ).digest()
        for i in range(len(chunk)):
            ciphertext[offset + i] = chunk[i] ^ keystream[i]
        counter += 1

    # Compute HMAC over nonce + ciphertext for authenticity (Encrypt-then-MAC)
    mac = hmac.new(key, nonce + bytes(ciphertext), hashlib.sha256).digest()

    raw = nonce + mac + bytes(ciphertext)
    b64_str = base64.urlsafe_b64encode(raw).decode("ascii")
    return f"{CIPHER_PREFIX_STDLIB}{b64_str}"


def _stdlib_decrypt(token: str, key: bytes) -> bytes:
    """Decrypt and verify ciphertext produced by `_stdlib_encrypt`."""
    if not token.startswith(CIPHER_PREFIX_STDLIB):
        raise ValueError("Invalid stdlib cipher token format.")

    raw = base64.urlsafe_b64decode(token[len(CIPHER_PREFIX_STDLIB) :])
    if len(raw) < 16 + 32:
        raise ValueError("Ciphertext payload is truncated.")

    nonce = raw[:16]
    expected_mac = raw[16:48]
    ciphertext = raw[48:]

    # Verify MAC first in constant time
    actual_mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, actual_mac):
        raise ValueError("HMAC verification failed. Ciphertext corrupted or key mismatch.")

    # Decrypt
    plaintext = bytearray(len(ciphertext))
    block_size = 64
    counter = 0
    for offset in range(0, len(ciphertext), block_size):
        chunk = ciphertext[offset : offset + block_size]
        ctr_bytes = counter.to_bytes(8, byteorder="big")
        keystream = hashlib.blake2b(
            nonce + ctr_bytes, key=key, digest_size=len(chunk), person=b"sv-keystr"
        ).digest()
        for i in range(len(chunk)):
            plaintext[offset + i] = chunk[i] ^ keystream[i]
        counter += 1

    return bytes(plaintext)


def encrypt_value(plaintext: str, key: bytes | str) -> str:
    """Encrypt a plaintext string with an authenticated cipher.

    Args:
        plaintext: The string to encrypt.
        key: A 32-byte key or secret string.

    Returns:
        A formatted ciphertext string containing nonce, tag, and ciphertext.
    """
    key_bytes = key if isinstance(key, bytes) and len(key) == 32 else derive_key(key)
    plaintext_bytes = plaintext.encode("utf-8")

    if _HAS_CRYPTOGRAPHY and AESGCM is not None:
        aesgcm = AESGCM(key_bytes)
        nonce = secrets.token_bytes(12)  # Standard 96-bit nonce for AES-GCM
        ct = aesgcm.encrypt(nonce, plaintext_bytes, None)
        b64_str = base64.urlsafe_b64encode(nonce + ct).decode("ascii")
        return f"{CIPHER_PREFIX_AESGCM}{b64_str}"

    return _stdlib_encrypt(plaintext_bytes, key_bytes)


def decrypt_value(ciphertext_token: str, key: bytes | str) -> str:
    """Decrypt an authenticated ciphertext token back to plaintext string.

    Args:
        ciphertext_token: Ciphertext string formatted with prefix.
        key: A 32-byte key or secret string.

    Returns:
        The decrypted plaintext string.

    Raises:
        ValueError: If verification fails or format is invalid.
    """
    key_bytes = key if isinstance(key, bytes) and len(key) == 32 else derive_key(key)

    if ciphertext_token.startswith(CIPHER_PREFIX_AESGCM):
        if not _HAS_CRYPTOGRAPHY or AESGCM is None:
            raise RuntimeError(
                "Payload was encrypted with AES-GCM. Please install 'cryptography' library to decrypt."
            )
        raw = base64.urlsafe_b64decode(ciphertext_token[len(CIPHER_PREFIX_AESGCM) :])
        if len(raw) < 12 + 16:
            raise ValueError("Truncated AES-GCM ciphertext.")
        nonce = raw[:12]
        ct = raw[12:]
        aesgcm = AESGCM(key_bytes)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ct, None)
        except Exception as exc:
            raise ValueError(
                "AES-GCM verification failed: ciphertext corrupted or key mismatch."
            ) from exc
        return plaintext_bytes.decode("utf-8")

    elif ciphertext_token.startswith(CIPHER_PREFIX_STDLIB):
        plaintext_bytes = _stdlib_decrypt(ciphertext_token, key_bytes)
        return plaintext_bytes.decode("utf-8")

    else:
        # Fallback for unencrypted legacy or plain data
        return ciphertext_token
