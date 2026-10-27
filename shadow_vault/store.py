"""
SQLite-backed thread-safe store for session PII mappings.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
import warnings
from typing import Callable


from shadow_vault.crypto import blind_index, decrypt_value, derive_key, encrypt_value


DEFAULT_TTL_SECONDS: float = 3600.0  # 1 hour default
_DEFAULT_TTL = object()


class VaultStore:
    """Thread-safe SQLite store for bi-directional session PII mappings.

    Maintains format-preserving synthetic tokens for real PII values with support
    for in-memory and file-based databases, TTL expiration, authenticated encryption at rest,
    and length-ordered reverse maps.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        ttl_seconds: float | None = _DEFAULT_TTL,  # type: ignore[assignment]
        encryption_key: str | bytes | None = None,
        salt: str | bytes | None = None,
        hash_size: int = 3,
        require_encryption: bool = False,
    ) -> None:
        """Initialize a new VaultStore instance.

        Args:
            db_path: Path to SQLite file or ':memory:' for transient storage.
            ttl_seconds: Optional time-to-live in seconds for session mappings (defaults to 3600s / 1 hour).
                Pass None explicitly to disable TTL eviction.
            encryption_key: Optional secret key or password for AES/authenticated at-rest encryption.
                Can also be provided via SHADOW_VAULT_KEY or SHADOW_VAULT_ENCRYPTION_KEY env vars.
            salt: Optional session salt for deterministic token hashing.
            hash_size: Digest size in bytes for short hash generator (default 3 bytes = 6 hex chars).
            require_encryption: If True, raises ValueError if no valid encryption key is supplied.
        """
        self.db_path = db_path
        if ttl_seconds is _DEFAULT_TTL:
            env_ttl = os.environ.get("SHADOW_VAULT_DEFAULT_TTL") or os.environ.get("SHADOW_VAULT_TTL")
            self.ttl_seconds = float(env_ttl) if env_ttl else DEFAULT_TTL_SECONDS
        else:
            self.ttl_seconds = ttl_seconds
        self.hash_size = hash_size
        self._lock = threading.RLock()
        self._is_closed = False

        # Configure encryption key
        raw_key = (
            encryption_key
            or os.environ.get("SHADOW_VAULT_KEY")
            or os.environ.get("SHADOW_VAULT_ENCRYPTION_KEY")
        )
        enforce_crypto = require_encryption or os.environ.get("SHADOW_VAULT_REQUIRE_ENCRYPTION") == "1"
        if enforce_crypto and not raw_key:
            raise ValueError(
                "VaultStore requires an encryption key when require_encryption=True "
                "or SHADOW_VAULT_REQUIRE_ENCRYPTION=1."
            )
        self.require_encryption: bool = enforce_crypto

        if db_path != ":memory:" and not raw_key:
            warnings.warn(
                "VaultStore initialized with a persistent file database without an encryption key! "
                "Sensitive values will be stored unencrypted on disk. "
                "Pass encryption_key or set SHADOW_VAULT_KEY to enable authenticated AES-256-GCM encryption.",
                category=UserWarning,
                stacklevel=2,
            )

        self._enc_key: bytes | None = derive_key(raw_key) if raw_key else None
        self._salt: bytes | None = (
            salt.encode("utf-8") if isinstance(salt, str) else salt
        )

        if db_path != ":memory:":
            abs_dir = os.path.dirname(os.path.abspath(db_path))
            if abs_dir:
                os.makedirs(abs_dir, exist_ok=True)
                if hasattr(os, "chmod") and os.name != "nt":
                    try:
                        os.chmod(abs_dir, 0o700)
                    except OSError:
                        pass

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        if db_path != ":memory:" and hasattr(os, "chmod") and os.name != "nt":
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

        with self._lock:
            if db_path != ":memory:":
                # Optimize concurrent read/write throughput for file-based SQLite
                self._conn.execute("PRAGMA journal_mode = WAL;")
                self._conn.execute("PRAGMA synchronous = NORMAL;")
                self._conn.execute("PRAGMA busy_timeout = 5000;")
            self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema and required indexes."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS mappings (
                session_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                real_val TEXT NOT NULL,
                synth_val TEXT NOT NULL,
                created_at REAL NOT NULL,
                real_hash TEXT,
                PRIMARY KEY (session_id, real_val),
                UNIQUE (session_id, synth_val)
            );
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mappings_session ON mappings(session_id);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mappings_created_at ON mappings(created_at);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_mappings_real_hash ON mappings(session_id, real_hash);"
        )
        self._conn.commit()

    def _compute_real_hash(self, session_id: str, real_val: str) -> str:
        """Compute blind index lookup hash for real_val."""
        if self._enc_key:
            return blind_index(self._enc_key, session_id, real_val)
        return hashlib.sha256(f"{session_id}:{real_val}".encode("utf-8")).hexdigest()

    def _encrypt_if_enabled(self, real_val: str) -> str:
        """Encrypt real_val if encryption_key is set."""
        if self._enc_key:
            return encrypt_value(real_val, self._enc_key)
        return real_val

    def _decrypt_if_enabled(self, stored_val: str) -> str:
        """Decrypt stored real_val if encryption was used, or return as is."""
        if self._enc_key and (
            stored_val.startswith("enc:gcm:v1:") or stored_val.startswith("enc:std:v1:")
        ):
            try:
                return decrypt_value(stored_val, self._enc_key)
            except Exception as exc:
                if self.require_encryption:
                    raise ValueError(
                        f"VaultStore authenticated decryption failed: {exc}. Ciphertext corrupted or key mismatch."
                    ) from exc
                warnings.warn(
                    f"VaultStore decryption failed: {exc}. Ciphertext corrupted or key mismatch.",
                    category=UserWarning,
                    stacklevel=3,
                )
                return stored_val
        return stored_val

    def _check_open(self) -> None:
        """Ensure connection has not been closed."""
        if self._is_closed or self._conn is None:
            raise RuntimeError("VaultStore connection is closed.")

    def get_or_create(
        self,
        session_id: str,
        entity_type: str,
        real_val: str,
        generator_fn: Callable[[str, str], str],
    ) -> str:
        """Retrieve existing synthetic value or generate and persist a new one.

        Args:
            session_id: Scoped session identifier.
            entity_type: Categorical PII entity type (e.g., 'EMAIL', 'CREDIT_CARD').
            real_val: Original sensitive string value.
            generator_fn: Callable receiving (entity_type, short_hash) returning synthetic token.

        Returns:
            The synthetic representation mapped to the real value.
        """
        with self._lock:
            self._check_open()
            now = time.time()
            cursor = self._conn.cursor()
            real_hash = self._compute_real_hash(session_id, real_val)

            # Check if mapping already exists for (session_id, real_val / real_hash)
            cursor.execute(
                "SELECT synth_val, created_at, real_val FROM mappings WHERE session_id = ? AND (real_hash = ? OR real_val = ?)",
                (session_id, real_hash, real_val),
            )
            row = cursor.fetchone()

            if row is not None:
                synth_val, created_at, stored_real = row
                if self.ttl_seconds is not None and (now - created_at) > self.ttl_seconds:
                    # Expired: prune stale mapping and regenerate
                    cursor.execute(
                        "DELETE FROM mappings WHERE session_id = ? AND (real_hash = ? OR real_val = ?)",
                        (session_id, real_hash, stored_real),
                    )
                    self._conn.commit()
                else:
                    return synth_val

            # Compute deterministic hex hash using BLAKE2b
            if self._salt is not None:
                short_hash = hashlib.blake2b(
                    f"{session_id}:{real_val}".encode("utf-8"),
                    digest_size=self.hash_size,
                    salt=self._salt[:16].ljust(16, b"\x00"),
                ).hexdigest()
            else:
                short_hash = hashlib.blake2b(
                    f"{session_id}:{real_val}".encode("utf-8"),
                    digest_size=self.hash_size,
                ).hexdigest()

            synth_val = generator_fn(entity_type, short_hash)
            stored_real_val = self._encrypt_if_enabled(real_val)

            # Defensive insert with collision resolution for UNIQUE(session_id, synth_val)
            attempt = 0
            while True:
                try:
                    cursor.execute(
                        "INSERT INTO mappings (session_id, entity_type, real_val, synth_val, created_at, real_hash) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (session_id, entity_type, stored_real_val, synth_val, now, real_hash),
                    )
                    self._conn.commit()
                    return synth_val
                except sqlite3.IntegrityError:
                    # Check if concurrent thread already created the exact mapping
                    cursor.execute(
                        "SELECT synth_val FROM mappings WHERE session_id = ? AND (real_hash = ? OR real_val = ?)",
                        (session_id, real_hash, stored_real_val),
                    )
                    existing = cursor.fetchone()
                    if existing is not None:
                        return existing[0]

                    attempt += 1
                    if attempt > 20:
                        raise RuntimeError(
                            f"Could not resolve synthetic token collision for {session_id}:{real_val}"
                        )

                    # Re-salt hash to generate an alternative unique token
                    alt_hash = hashlib.blake2b(
                        f"{session_id}:{real_val}:retry_{attempt}".encode("utf-8"),
                        digest_size=self.hash_size,
                    ).hexdigest()
                    synth_val = generator_fn(entity_type, alt_hash)

    def get_session_map(
        self,
        session_id: str,
        allowed_entity_types: set[str] | None = None,
    ) -> dict[str, str]:
        """Return {synth_val: real_val} sorted by len(synth_val) descending.

        Sorting by length descending guarantees that longer synthetic tokens
        are substituted prior to shorter substrings during de-anonymization.

        Args:
            session_id: Target session identifier.
            allowed_entity_types: Optional set of entity types to restrict hydration to.

        Returns:
            Dictionary of {synthetic_value: real_value} sorted by length descending.
        """
        with self._lock:
            self._check_open()
            now = time.time()
            cursor = self._conn.cursor()

            if self.ttl_seconds is not None:
                cutoff = now - self.ttl_seconds
                cursor.execute(
                    "DELETE FROM mappings WHERE session_id = ? AND created_at < ?",
                    (session_id, cutoff),
                )
                self._conn.commit()

            cursor.execute(
                "SELECT synth_val, real_val, entity_type FROM mappings WHERE session_id = ?",
                (session_id,),
            )
            rows = cursor.fetchall()

            if allowed_entity_types is not None:
                allowed_upper = {e.upper() for e in allowed_entity_types}
                rows = [r for r in rows if r[2].upper() in allowed_upper]

            # Decrypt stored values if encrypted, then sort descending by length
            decrypted_rows = [
                (synth, self._decrypt_if_enabled(real)) for synth, real, _ in rows
            ]
            sorted_entries = sorted(decrypted_rows, key=lambda pair: len(pair[0]), reverse=True)
            return {synth: real for synth, real in sorted_entries}

    def clear_session(self, session_id: str) -> None:
        """Purge all mappings associated with the specified session.

        Args:
            session_id: Session identifier to purge.
        """
        with self._lock:
            self._check_open()
            cursor = self._conn.cursor()
            cursor.execute("DELETE FROM mappings WHERE session_id = ?", (session_id,))
            self._conn.commit()

    def cleanup_expired(self, session_id: str | None = None) -> int:
        """Delete all expired records older than ttl_seconds.

        Args:
            session_id: Optional session filter. If omitted, cleans all expired sessions.

        Returns:
            Number of rows deleted.
        """
        if self.ttl_seconds is None:
            return 0

        with self._lock:
            self._check_open()
            cutoff = time.time() - self.ttl_seconds
            cursor = self._conn.cursor()
            if session_id is not None:
                cursor.execute(
                    "DELETE FROM mappings WHERE session_id = ? AND created_at < ?",
                    (session_id, cutoff),
                )
            else:
                cursor.execute(
                    "DELETE FROM mappings WHERE created_at < ?",
                    (cutoff,),
                )
            deleted_count = cursor.rowcount
            self._conn.commit()
            return max(0, deleted_count)

    def get_real_val(self, session_id: str, synth_val: str) -> str | None:
        """Lookup real value by synthetic value in a session.

        Args:
            session_id: Target session identifier.
            synth_val: Synthetic token.

        Returns:
            The original real value or None if not found/expired.
        """
        with self._lock:
            self._check_open()
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT real_val, created_at FROM mappings WHERE session_id = ? AND synth_val = ?",
                (session_id, synth_val),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            real_val, created_at = row
            if self.ttl_seconds is not None and (time.time() - created_at) > self.ttl_seconds:
                cursor.execute(
                    "DELETE FROM mappings WHERE session_id = ? AND synth_val = ?",
                    (session_id, synth_val),
                )
                self._conn.commit()
                return None
            return self._decrypt_if_enabled(real_val)

    def get_synth_val(self, session_id: str, real_val: str) -> str | None:
        """Lookup synthetic value by real value in a session.

        Args:
            session_id: Target session identifier.
            real_val: Real PII value.

        Returns:
            The synthetic token or None if not found/expired.
        """
        with self._lock:
            self._check_open()
            real_hash = self._compute_real_hash(session_id, real_val)
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT synth_val, created_at FROM mappings WHERE session_id = ? AND (real_hash = ? OR real_val = ?)",
                (session_id, real_hash, real_val),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            synth_val, created_at = row
            if self.ttl_seconds is not None and (time.time() - created_at) > self.ttl_seconds:
                cursor.execute(
                    "DELETE FROM mappings WHERE session_id = ? AND (real_hash = ? OR real_val = ?)",
                    (session_id, real_hash, real_val),
                )
                self._conn.commit()
                return None
            return synth_val

    def count(self, session_id: str | None = None) -> int:
        """Return total active mapping count, optionally filtered by session."""
        with self._lock:
            self._check_open()
            cursor = self._conn.cursor()
            if session_id is not None:
                cursor.execute(
                    "SELECT COUNT(*) FROM mappings WHERE session_id = ?",
                    (session_id,),
                )
            else:
                cursor.execute("SELECT COUNT(*) FROM mappings")
            return cursor.fetchone()[0]

    def list_sessions(self) -> list[str]:
        """Return list of distinct active session identifiers."""
        with self._lock:
            self._check_open()
            cursor = self._conn.cursor()
            cursor.execute("SELECT DISTINCT session_id FROM mappings ORDER BY session_id")
            return [row[0] for row in cursor.fetchall()]

    def get_session_records(self, session_id: str) -> list[dict[str, Any]]:
        """Return all mapping records for a session as dictionaries.

        Args:
            session_id: Target session identifier.

        Returns:
            List of dictionaries with record metadata.
        """
        with self._lock:
            self._check_open()
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT session_id, entity_type, real_val, synth_val, created_at "
                "FROM mappings WHERE session_id = ? ORDER BY created_at ASC",
                (session_id,),
            )
            return [
                {
                    "session_id": row[0],
                    "entity_type": row[1],
                    "real_val": self._decrypt_if_enabled(row[2]),
                    "stored_val": row[2],
                    "synth_val": row[3],
                    "created_at": row[4],
                }
                for row in cursor.fetchall()
            ]

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            if not self._is_closed and self._conn is not None:
                self._conn.close()
                self._conn = None
                self._is_closed = True

    @property
    def is_closed(self) -> bool:
        """Return True if store connection is closed."""
        return self._is_closed

    def __enter__(self) -> VaultStore:
        return self

    def __exit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: object | None) -> None:
        self.close()
