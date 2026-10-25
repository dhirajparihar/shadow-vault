"""
SQLite-backed thread-safe store for session PII mappings.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from typing import Callable


class VaultStore:
    """Thread-safe SQLite store for bi-directional session PII mappings.

    Maintains format-preserving synthetic tokens for real PII values with support
    for in-memory and file-based databases, TTL expiration, and length-ordered reverse maps.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        ttl_seconds: float | None = None,
    ) -> None:
        """Initialize a new VaultStore instance.

        Args:
            db_path: Path to SQLite file or ':memory:' for transient storage.
            ttl_seconds: Optional time-to-live in seconds for session mappings.
        """
        self.db_path = db_path
        self.ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        self._is_closed = False

        if db_path != ":memory:":
            abs_dir = os.path.dirname(os.path.abspath(db_path))
            if abs_dir:
                os.makedirs(abs_dir, exist_ok=True)

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)

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
        self._conn.commit()

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

            # Check if mapping already exists for (session_id, real_val)
            cursor.execute(
                "SELECT synth_val, created_at FROM mappings WHERE session_id = ? AND real_val = ?",
                (session_id, real_val),
            )
            row = cursor.fetchone()

            if row is not None:
                synth_val, created_at = row
                if self.ttl_seconds is not None and (now - created_at) > self.ttl_seconds:
                    # Expired: prune stale mapping and regenerate
                    cursor.execute(
                        "DELETE FROM mappings WHERE session_id = ? AND real_val = ?",
                        (session_id, real_val),
                    )
                    self._conn.commit()
                else:
                    return synth_val

            # Compute deterministic 6-character hex hash using BLAKE2b (3 bytes = 6 hex chars)
            short_hash = hashlib.blake2b(
                f"{session_id}:{real_val}".encode("utf-8"),
                digest_size=3,
            ).hexdigest()

            synth_val = generator_fn(entity_type, short_hash)

            # Defensive insert with collision resolution for UNIQUE(session_id, synth_val)
            attempt = 0
            while True:
                try:
                    cursor.execute(
                        "INSERT INTO mappings (session_id, entity_type, real_val, synth_val, created_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (session_id, entity_type, real_val, synth_val, now),
                    )
                    self._conn.commit()
                    return synth_val
                except sqlite3.IntegrityError:
                    # Check if concurrent thread already created the exact mapping
                    cursor.execute(
                        "SELECT synth_val FROM mappings WHERE session_id = ? AND real_val = ?",
                        (session_id, real_val),
                    )
                    existing = cursor.fetchone()
                    if existing is not None:
                        return existing[0]

                    attempt += 1
                    if attempt > 10:
                        raise RuntimeError(
                            f"Could not resolve synthetic token collision for {session_id}:{real_val}"
                        )

                    # Re-salt hash to generate an alternative unique token
                    alt_hash = hashlib.blake2b(
                        f"{session_id}:{real_val}:{attempt}".encode("utf-8"),
                        digest_size=3,
                    ).hexdigest()
                    synth_val = generator_fn(entity_type, alt_hash)

    def get_session_map(self, session_id: str) -> dict[str, str]:
        """Return {synth_val: real_val} sorted by len(synth_val) descending.

        Sorting by length descending guarantees that longer synthetic tokens
        are substituted prior to shorter substrings during de-anonymization.

        Args:
            session_id: Target session identifier.

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
                "SELECT synth_val, real_val FROM mappings WHERE session_id = ?",
                (session_id,),
            )
            rows = cursor.fetchall()

            # Sort descending by length of synthetic token
            sorted_entries = sorted(rows, key=lambda pair: len(pair[0]), reverse=True)
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
            return real_val

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
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT synth_val, created_at FROM mappings WHERE session_id = ? AND real_val = ?",
                (session_id, real_val),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            synth_val, created_at = row
            if self.ttl_seconds is not None and (time.time() - created_at) > self.ttl_seconds:
                cursor.execute(
                    "DELETE FROM mappings WHERE session_id = ? AND real_val = ?",
                    (session_id, real_val),
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
