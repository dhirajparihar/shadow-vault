"""
Unit and integration tests for VaultStore.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import time
import pytest

from shadow_vault.store import VaultStore


def test_vault_store_default_in_memory() -> None:
    """Test default in-memory initialization and schema verification."""
    store = VaultStore()
    assert store.db_path == ":memory:"
    assert store.count() == 0

    cursor = store._conn.cursor()
    cursor.execute("PRAGMA table_info(mappings)")
    columns = {col[1]: col[2] for col in cursor.fetchall()}
    assert "session_id" in columns
    assert "entity_type" in columns
    assert "real_val" in columns
    assert "synth_val" in columns
    assert "created_at" in columns
    store.close()


def test_get_or_create_deterministic_hashing() -> None:
    """Test deterministic 6-character hex hash calculation and caching."""
    store = VaultStore()
    session_id = "sess_test_1"
    real_val = "secret_user@example.com"
    entity_type = "EMAIL"

    expected_hash = hashlib.blake2b(
        f"{session_id}:{real_val}".encode("utf-8"),
        digest_size=3,
    ).hexdigest()
    assert len(expected_hash) == 6

    calls: list[tuple[str, str]] = []

    def generator(e_type: str, short_h: str) -> str:
        calls.append((e_type, short_h))
        return f"synth_{e_type.lower()}_{short_h}@shadow.vault"

    # First call: invokes generator_fn
    synth1 = store.get_or_create(session_id, entity_type, real_val, generator)
    assert synth1 == f"synth_email_{expected_hash}@shadow.vault"
    assert len(calls) == 1
    assert calls[0] == (entity_type, expected_hash)

    # Second call: returns cached synth_val without invoking generator_fn again
    synth2 = store.get_or_create(session_id, entity_type, real_val, generator)
    assert synth2 == synth1
    assert len(calls) == 1

    # Different session with same real value generates different hash
    session_id_2 = "sess_test_2"
    expected_hash_2 = hashlib.blake2b(
        f"{session_id_2}:{real_val}".encode("utf-8"),
        digest_size=3,
    ).hexdigest()
    synth_sess_2 = store.get_or_create(session_id_2, entity_type, real_val, generator)
    assert synth_sess_2 == f"synth_email_{expected_hash_2}@shadow.vault"
    assert synth_sess_2 != synth1
    assert len(calls) == 2

    store.close()


def test_get_session_map_order_by_length_descending() -> None:
    """Test get_session_map returns {synth: real} sorted by length descending."""
    store = VaultStore()
    session_id = "sess_ordering"

    # Insert values with synthetic tokens of varying lengths
    tokens = [
        ("short", "short_synth"),                       # len 11
        ("very_long_val", "extremely_long_synthetic_token_12345"),  # len 36
        ("medium_val", "medium_length_synth_token"),     # len 25
        ("tiny", "tiny"),                               # len 4
    ]

    for real_v, synth_v in tokens:
        store.get_or_create(session_id, "CUSTOM", real_v, lambda et, h, s=synth_v: s)

    session_map = store.get_session_map(session_id)

    synth_keys = list(session_map.keys())
    # Verify that each key's length is >= the subsequent key's length
    for i in range(len(synth_keys) - 1):
        assert len(synth_keys[i]) >= len(synth_keys[i + 1]), (
            f"Key '{synth_keys[i]}' (len {len(synth_keys[i])}) must be longer than "
            f"'{synth_keys[i + 1]}' (len {len(synth_keys[i + 1])})"
        )

    assert synth_keys[0] == "extremely_long_synthetic_token_12345"
    assert synth_keys[-1] == "tiny"
    assert session_map["extremely_long_synthetic_token_12345"] == "very_long_val"
    assert session_map["tiny"] == "tiny"

    store.close()


def test_clear_session() -> None:
    """Test clearing session mappings without affecting other sessions."""
    store = VaultStore()
    s1 = "session_1"
    s2 = "session_2"

    def gen(et: str, h: str) -> str:
        return f"synth_{h}"

    store.get_or_create(s1, "EMAIL", "a@example.com", gen)
    store.get_or_create(s1, "EMAIL", "b@example.com", gen)
    store.get_or_create(s2, "EMAIL", "c@example.com", gen)

    assert store.count(s1) == 2
    assert store.count(s2) == 1
    assert store.count() == 3

    store.clear_session(s1)

    assert store.count(s1) == 0
    assert store.get_session_map(s1) == {}
    assert store.count(s2) == 1
    assert len(store.get_session_map(s2)) == 1

    store.close()


def test_ttl_expiration() -> None:
    """Test TTL expiration and cleanup of expired mappings."""
    ttl = 0.15  # 150ms
    store = VaultStore(ttl_seconds=ttl)
    session_id = "sess_ttl"

    call_count = 0

    def gen(et: str, h: str) -> str:
        nonlocal call_count
        call_count += 1
        return f"synth_{h}_{call_count}"

    val1 = store.get_or_create(session_id, "EMAIL", "test@example.com", gen)
    assert call_count == 1

    # Immediate query within TTL should return cached value
    val2 = store.get_or_create(session_id, "EMAIL", "test@example.com", gen)
    assert val2 == val1
    assert call_count == 1
    assert len(store.get_session_map(session_id)) == 1

    # Sleep past TTL
    time.sleep(0.20)

    # get_session_map should prune expired records
    assert store.get_session_map(session_id) == {}

    # get_or_create should now regenerate a fresh mapping
    val3 = store.get_or_create(session_id, "EMAIL", "test@example.com", gen)
    assert call_count == 2
    assert val3 != val1

    store.close()


def test_file_based_sqlite_persistence() -> None:
    """Test file-based SQLite database creation, WAL mode, and persistence."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "vault_test.db")

        def gen(et: str, h: str) -> str:
            return f"val_{h}"

        # Instance 1 writes
        with VaultStore(db_path=db_path) as store1:
            store1.get_or_create("s1", "EMAIL", "user1@example.com", gen)
            store1.get_or_create("s1", "EMAIL", "user2@example.com", gen)
            assert store1.count() == 2

        # Instance 2 reads from the same persistent file
        with VaultStore(db_path=db_path) as store2:
            assert store2.count() == 2
            s_map = store2.get_session_map("s1")
            assert len(s_map) == 2
            assert "user1@example.com" in s_map.values()
            assert "user2@example.com" in s_map.values()


def test_multithreaded_concurrency() -> None:
    """Test concurrent read/write thread-safety with 10 threads."""
    store = VaultStore()
    num_threads = 10
    items_per_thread = 25

    def worker(t_idx: int) -> None:
        session_id = f"thread_session_{t_idx % 2}"
        for i in range(items_per_thread):
            real_val = f"user_{t_idx}_{i}@domain.com"
            synth = store.get_or_create(
                session_id,
                "EMAIL",
                real_val,
                lambda et, h: f"tok_{et}_{h}",
            )
            assert synth.startswith("tok_EMAIL_")
            # Intermittent reads
            if i % 5 == 0:
                _ = store.get_session_map(session_id)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_expected = num_threads * items_per_thread
    assert store.count() == total_expected
    store.close()


def test_collision_retry_handling() -> None:
    """Test collision handling when generator produces duplicate synth values."""
    store = VaultStore()
    session_id = "sess_collide"

    counter = 0

    def colliding_generator(et: str, h: str) -> str:
        nonlocal counter
        counter += 1
        # Intentionally produce a collision on attempt 0
        if counter <= 2:
            return "duplicate_token"
        return f"unique_token_{h}_{counter}"

    val1 = store.get_or_create(session_id, "EMAIL", "user1@test.com", colliding_generator)
    assert val1 == "duplicate_token"

    # Second user triggers UNIQUE(session_id, synth_val) collision and retries with salted hash
    val2 = store.get_or_create(session_id, "EMAIL", "user2@test.com", colliding_generator)
    assert val2 != val1
    assert val2.startswith("unique_token_")

    s_map = store.get_session_map(session_id)
    assert len(s_map) == 2
    store.close()


def test_close_and_context_manager() -> None:
    """Test store close method and context manager lifecycle."""
    store = VaultStore()
    assert not store.is_closed

    with store:
        pass

    assert store.is_closed
    with pytest.raises(RuntimeError, match="closed"):
        store.get_session_map("any")


def test_get_session_records() -> None:
    """Test retrieving session records with metadata."""
    store = VaultStore()
    sess = "records_test"

    store.get_or_create(sess, "EMAIL", "alice@example.com", lambda et, h: f"u_{h}@shadow.vault")
    store.get_or_create(sess, "PHONE", "+15551234567", lambda et, h: f"+19000{h[:5]}")

    records = store.get_session_records(sess)
    assert len(records) == 2
    assert records[0]["session_id"] == sess
    assert records[0]["entity_type"] == "EMAIL"
    assert records[0]["real_val"] == "alice@example.com"
    assert "shadow.vault" in records[0]["synth_val"]
    assert "created_at" in records[0]

    assert records[1]["entity_type"] == "PHONE"
    assert records[1]["real_val"] == "+15551234567"
    store.close()

