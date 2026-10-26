"""
Integration tests for VaultStore authenticated at-rest encryption and blind indexing.
"""

from __future__ import annotations

import sqlite3
import tempfile
import pytest

from shadow_vault.store import VaultStore
from shadow_vault.synthesizer import synthesize_token


def test_vault_store_at_rest_encryption_in_sqlite() -> None:
    """Test that SQLite file contains ONLY ciphertext and no plaintext PII."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    secret_key = "my-super-secret-vault-master-key"
    real_email = "alice.enterprise@confidential-corp.com"
    real_card = "4532 0151 1283 0366"
    session_id = "sess_secure_corp"

    store = VaultStore(
        db_path=db_path,
        encryption_key=secret_key,
    )

    # 1. Store mappings
    synth_email = store.get_or_create(session_id, "EMAIL", real_email, synthesize_token)
    synth_card = store.get_or_create(session_id, "CREDIT_CARD", real_card, synthesize_token)

    assert synth_email.endswith("@shadow.vault")
    assert synth_card.startswith("400000999")

    # 2. Inspect raw SQLite database directly without the VaultStore instance
    raw_conn = sqlite3.connect(db_path)
    cursor = raw_conn.cursor()
    cursor.execute("SELECT real_val, real_hash FROM mappings WHERE session_id = ?", (session_id,))
    rows = cursor.fetchall()
    raw_conn.close()

    assert len(rows) == 2
    for stored_real_val, stored_real_hash in rows:
        # Crucial security assertion: Plaintext PII MUST NOT appear in the database
        assert stored_real_val != real_email
        assert stored_real_val != real_card
        assert real_email not in stored_real_val
        assert real_card not in stored_real_val
        # Must be encrypted with our authenticated cipher prefix
        assert stored_real_val.startswith("enc:")
        # Must have a blind index hash
        assert stored_real_hash is not None and len(stored_real_hash) == 64

    # 3. Transparently decrypt through authorized VaultStore methods
    assert store.get_real_val(session_id, synth_email) == real_email
    assert store.get_real_val(session_id, synth_card) == real_card

    session_map = store.get_session_map(session_id)
    assert session_map[synth_email] == real_email
    assert session_map[synth_card] == real_card

    records = store.get_session_records(session_id)
    assert len(records) == 2
    record_vals = {r["synth_val"]: r["real_val"] for r in records}
    assert record_vals[synth_email] == real_email
    assert record_vals[synth_card] == real_card

    store.close()


def test_vault_store_salt_alters_token_generation() -> None:
    """Test that providing a custom salt alters the token hash deterministically."""
    val = "user@test.org"
    sess = "s1"

    store_unsalted = VaultStore()
    store_salted = VaultStore(salt="enterprise-tenant-alpha-salt")

    synth1 = store_unsalted.get_or_create(sess, "EMAIL", val, synthesize_token)
    synth2 = store_salted.get_or_create(sess, "EMAIL", val, synthesize_token)

    assert synth1 != synth2
    assert synth1.endswith("@shadow.vault")
    assert synth2.endswith("@shadow.vault")

    store_unsalted.close()
    store_salted.close()
