"""
Tests for ephemeral session context managers, default TTL, and logging filters.
"""

from __future__ import annotations

import io
import logging
import os
import time

from shadow_vault import (
    DEFAULT_TTL_SECONDS,
    ShadowVault,
    VaultLogFilter,
    VaultSession,
    VaultStore,
)


def test_default_ttl_assignment():
    """Verify default TTL is 3600 seconds and can be overridden by env or explicit value."""
    # 1. Default should be 3600.0s (1 hour)
    store = VaultStore()
    assert store.ttl_seconds == DEFAULT_TTL_SECONDS
    assert store.ttl_seconds == 3600.0

    # 2. ShadowVault engine forwards default TTL
    vault = ShadowVault()
    assert vault.store.ttl_seconds == 3600.0

    # 3. Explicit None disables TTL
    store_no_ttl = VaultStore(ttl_seconds=None)
    assert store_no_ttl.ttl_seconds is None

    vault_no_ttl = ShadowVault(ttl_seconds=None)
    assert vault_no_ttl.store.ttl_seconds is None

    # 4. Explicit custom TTL
    store_custom = VaultStore(ttl_seconds=120.0)
    assert store_custom.ttl_seconds == 120.0

    # 5. Environment variable override
    os.environ["SHADOW_VAULT_DEFAULT_TTL"] = "7200"
    try:
        store_env = VaultStore()
        assert store_env.ttl_seconds == 7200.0
    finally:
        del os.environ["SHADOW_VAULT_DEFAULT_TTL"]


def test_ephemeral_vault_session_context_manager():
    """Verify that with vault.session(...) automatically purges all mapping data on exit."""
    vault = ShadowVault()
    session_id = "agent_run_alpha"

    # Step 1: Use context manager
    with vault.session(session_id, auto_purge=True) as sess:
        assert isinstance(sess, VaultSession)
        assert sess.session_id == session_id

        # Dehydrate sensitive data
        safe_prompt = sess.dehydrate("Refund alice@corp.com on card 4532 0151 1283 0366")
        assert "alice@corp.com" not in safe_prompt
        assert "4532 0151 1283 0366" not in safe_prompt

        # During run, session map is accessible
        mapping = sess.get_map()
        assert len(mapping) == 2

        # Hydrate back
        hydrated = sess.hydrate(safe_prompt)
        assert "alice@corp.com" in hydrated
        assert "4532 0151 1283 0366" in hydrated

    # Step 2: Context exited -> verify 100% purged
    assert len(vault.get_session_map(session_id)) == 0
    assert vault.store.count(session_id) == 0


def test_vault_session_auto_purge_false():
    """Verify that auto_purge=False preserves session mapping across context exits."""
    vault = ShadowVault()
    session_id = "agent_run_beta"

    with vault.session(session_id, auto_purge=False) as sess:
        safe_prompt = sess.dehydrate("Patient SSN: 219-45-7890")
        assert "219-45-7890" not in safe_prompt

    # After exit, mapping persists
    assert len(vault.get_session_map(session_id)) == 1

    # Manual clear works
    sess.clear()
    assert len(vault.get_session_map(session_id)) == 0


def test_vault_log_filter_scrubs_sensitive_records():
    """Verify VaultLogFilter intercepts log records and scrubs real PII before output."""
    vault = ShadowVault()
    session_id = "logging_session"

    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(levelname)s: %(message)s")
    handler.setFormatter(formatter)

    test_logger = logging.getLogger("test_vault_agent_logger")
    test_logger.setLevel(logging.INFO)
    test_logger.addHandler(handler)

    log_filter = VaultLogFilter(vault=vault, session_id=session_id)
    test_logger.addFilter(log_filter)

    try:
        # 1. Log with format string message
        real_card = "4532 0151 1283 0366"
        real_email = "bob.executive@company.io"
        test_logger.info("Charging card %s for customer %s", real_card, real_email)

        # 2. Log with standard f-string message
        test_logger.info("Backup contact for refund: +91 9876543210 (PAN: ABCDE1234F)")

        handler.flush()
        logged_text = log_stream.getvalue()

        # Assert zero raw PII appears in the logs
        assert real_card not in logged_text
        assert real_email not in logged_text
        assert "+91 9876543210" not in logged_text
        assert "ABCDE1234F" not in logged_text

        # Assert format-preserving tokens are logged instead
        assert "@shadow.vault" in logged_text
        assert "400000" in logged_text
        assert "SHDWV" in logged_text

    finally:
        test_logger.removeFilter(log_filter)
        test_logger.removeHandler(handler)


def test_detect_street_addresses_in_free_text():
    """Verify zero-ML regex address detection, format-preserving synthesis, and round-trip hydration."""
    from shadow_vault import EntityType, detect_addresses, detect_entities

    raw_text = (
        "Please deliver the package to 742 Evergreen Terrace, Springfield, "
        "or forward invoice to 123 Main St before end of month."
    )

    # 1. Direct detector test
    addrs = detect_addresses(raw_text)
    assert len(addrs) == 2
    assert addrs[0].value == "742 Evergreen Terrace"
    assert addrs[0].entity_type == EntityType.LOCATION.value
    assert addrs[1].value == "123 Main St"

    # 2. Unified pipeline test
    detected = detect_entities(raw_text)
    values = [d.value for d in detected]
    assert "742 Evergreen Terrace" in values
    assert "123 Main St" in values

    # 3. Vault dehydration and hydration test
    vault = ShadowVault()
    session_id = "address_test_session"

    dehydrated = vault.dehydrate(raw_text, session_id=session_id)
    assert "742 Evergreen Terrace" not in dehydrated
    assert "123 Main St" not in dehydrated
    assert "Shadow Vault Way" in dehydrated

    # 4. Hydration restores original free-text addresses perfectly
    hydrated = vault.hydrate(dehydrated, session_id=session_id)
    assert hydrated == raw_text


def test_presidio_detector_defaults_and_location():
    """Verify PresidioDetector defaults to PERSON and LOCATION and properly maps location entities."""
    from unittest.mock import MagicMock
    from shadow_vault.integrations.presidio import PresidioDetector

    mock_analyzer = MagicMock()

    class MockRecognizerResult:
        def __init__(self, entity_type, start, end, score):
            self.entity_type = entity_type
            self.start = start
            self.end = end
            self.score = score

    # Verify defaults
    detector = PresidioDetector(analyzer=mock_analyzer)
    assert detector.entities == ["PERSON", "LOCATION"]

    # Verify detection of both person and location in free text
    # "John Doe" is len 8 (0:8)
    # "Paris, France" starts at 27, ends at 40 (27:40)
    mock_analyzer.analyze.return_value = [
        MockRecognizerResult(entity_type="PERSON", start=0, end=8, score=0.95),
        MockRecognizerResult(entity_type="LOCATION", start=27, end=40, score=0.90),
    ]

    text = "John Doe works remotely in Paris, France."
    results = detector(text)
    assert len(results) == 2
    assert results[0].entity_type == "PERSON"
    assert results[0].value == "John Doe"
    assert results[1].entity_type == "LOCATION"
    assert results[1].value == "Paris, France"

