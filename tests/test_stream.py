"""
Unit tests for StreamHydrator lookahead holdback buffer and chunk splitting.
"""

from __future__ import annotations

import pytest

from shadow_vault.engine import ShadowVault
from shadow_vault.stream import StreamHydrator


def test_stream_hydrator_chunk_splitting() -> None:
    """Test resolving the SSE chunk-splitting bug across fragmented tokens."""
    vault = ShadowVault()
    session_id = "sess_stream_1"

    real_email = "alice@example.com"
    # Dehydrate once to register mapping in the vault
    dehydrated_email = vault.dehydrate(real_email, session_id=session_id)
    assert dehydrated_email.startswith("u_")
    assert dehydrated_email.endswith("@shadow.vault")

    # Split synthetic token into fragmented SSE chunks:
    # e.g., 'u_8f9', 'a1b@shadow', '.vault'
    prefix_len = 5
    mid_len = 10
    chunk1 = f"Message to {dehydrated_email[:prefix_len]}"
    chunk2 = dehydrated_email[prefix_len : prefix_len + mid_len]
    chunk3 = f"{dehydrated_email[prefix_len + mid_len:]} completed successfully."

    hydrator = StreamHydrator(vault=vault, session_id=session_id)

    # Process Chunk 1: Should emit 'Message to ' and hold back 'u_...'
    out1 = hydrator.process_chunk(chunk1)
    assert out1 == "Message to "
    assert hydrator.buffer == dehydrated_email[:prefix_len]

    # Process Chunk 2: Still partial, should hold back and emit nothing
    out2 = hydrator.process_chunk(chunk2)
    assert out2 == ""
    assert hydrator.buffer == dehydrated_email[: prefix_len + mid_len]

    # Process Chunk 3: Completes token, hydrates to real email, emits full result
    out3 = hydrator.process_chunk(chunk3)
    assert real_email in out3
    assert out3 == f"{real_email} completed successfully."
    assert hydrator.buffer == ""

    # Flush should be empty
    flush_out = hydrator.flush()
    assert flush_out == ""

    vault.close()


def test_stream_hydrator_non_pii_stream() -> None:
    """Test streaming plain text without synthetic tokens emits with zero lag."""
    vault = ShadowVault()
    hydrator = StreamHydrator(vault=vault)

    chunks = ["The ", "quick ", "brown ", "fox ", "jumps."]
    emitted = [hydrator.process_chunk(c) for c in chunks]
    emitted.append(hydrator.flush())

    result = "".join(emitted)
    assert result == "The quick brown fox jumps."
    vault.close()


def test_stream_hydrator_multiple_tokens_micro_chunks() -> None:
    """Test multiple synthetic tokens split across tiny 2-character chunks."""
    vault = ShadowVault()
    session_id = "sess_micro"

    real_email = "bob@example.com"
    real_phone = "+91 9876543210"
    real_card = "4532 0151 1283 0366"

    full_text = f"Email: {real_email}, Mobile: {real_phone}, Card: {real_card}."
    dehydrated_text = vault.dehydrate(full_text, session_id=session_id)

    # Break into tiny 2-character chunks
    chunk_size = 2
    chunks = [
        dehydrated_text[i : i + chunk_size]
        for i in range(0, len(dehydrated_text), chunk_size)
    ]

    hydrator = vault.stream(session_id=session_id)
    emitted_chunks = []
    for c in chunks:
        out = hydrator.process_chunk(c)
        if out:
            emitted_chunks.append(out)

    flushed = hydrator.flush()
    if flushed:
        emitted_chunks.append(flushed)

    reconstructed = "".join(emitted_chunks)
    assert reconstructed == full_text
    vault.close()


def test_stream_transform_sync_and_async() -> None:
    """Test synchronous and asynchronous stream generators."""
    vault = ShadowVault()
    session_id = "sess_gen"

    real_text = "Notify user at support@example.com."
    dehydrated_text = vault.dehydrate(real_text, session_id=session_id)
    chunks = [dehydrated_text[:10], dehydrated_text[10:22], dehydrated_text[22:]]

    # Synchronous generator
    hydrator_sync = vault.stream(session_id=session_id)
    sync_result = "".join(hydrator_sync.transform(chunks))
    assert sync_result == real_text

    # Asynchronous generator
    async def async_chunk_stream():
        for ch in chunks:
            yield ch

    import asyncio

    async def run_async_test():
        hydrator_async = vault.stream(session_id=session_id)
        parts = []
        async for piece in hydrator_async.transform_async(async_chunk_stream()):
            parts.append(piece)
        return "".join(parts)

    async_result = asyncio.run(run_async_test())
    assert async_result == real_text

    # Test feed alias
    feed_hydrator = StreamHydrator(vault=vault, session_id=session_id)
    feed_result = "".join(feed_hydrator.feed(ch) for ch in chunks) + feed_hydrator.flush()
    assert feed_result == real_text

    vault.close()

