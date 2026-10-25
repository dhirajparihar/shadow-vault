"""
Streaming buffer and token hydrator for Server-Sent Events (SSE) and LLM chunks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, AsyncIterable, AsyncIterator, Iterable, Iterator
from shadow_vault.synthesizer import SYNTHETIC_PREFIXES

if TYPE_CHECKING:
    from shadow_vault.engine import ShadowVault


class StreamHydrator:
    """Solves the SSE chunk-splitting problem when streaming LLM responses.

    Buffers partial synthetic token fragments (e.g., 'u_8f9', 'a1b@shadow', '.vault'),
    reconstructs completed tokens, dehydrates/hydrates them against VaultStore,
    and emits de-anonymized output in real-time.
    """

    def __init__(self, vault: ShadowVault, session_id: str = "default") -> None:
        """Initialize StreamHydrator.

        Args:
            vault: ShadowVault engine instance.
            session_id: Target session identifier for reverse mapping.
        """
        self.vault = vault
        self.session_id = session_id
        self.buffer = ""

    def process_chunk(self, chunk: str) -> str:
        """Process an incoming streaming text chunk and emit safe de-anonymized text.

        Args:
            chunk: Next text chunk received from LLM or SSE stream.

        Returns:
            De-anonymized text safe to emit immediately.
        """
        if not chunk:
            return ""

        # 1. Append incoming chunk to holdback buffer
        self.buffer += chunk

        # 2. Run hydration across current buffer to resolve any completed tokens
        self.buffer = self.vault.hydrate(self.buffer, self.session_id)

        # 3. Retrieve all potential candidate prefixes to hold back
        session_map = self.vault.store.get_session_map(self.session_id)
        candidates = set(session_map.keys()) | set(SYNTHETIC_PREFIXES)

        # 4. Check if any suffix of self.buffer partially matches a prefix of any candidate
        holdback_idx = self._find_holdback_index(self.buffer, candidates)

        # 5. Emit text before the holdback tail; keep the tail in buffer
        emitted = self.buffer[:holdback_idx]
        self.buffer = self.buffer[holdback_idx:]
        return emitted

    def feed(self, chunk: str) -> str:
        """Alias for process_chunk.

        Args:
            chunk: Next text chunk received from LLM or SSE stream.

        Returns:
            De-anonymized text safe to emit immediately.
        """
        return self.process_chunk(chunk)


    def _find_holdback_index(self, text: str, candidates: Iterable[str]) -> int:
        """Find start index of the longest suffix matching a prefix of any candidate.

        Returns len(text) if no candidate matches any suffix.
        """
        if not text or not candidates:
            return len(text)

        max_match_len = 0
        text_len = len(text)

        for cand in candidates:
            if not cand:
                continue
            cand_len = len(cand)
            limit = min(cand_len, text_len)

            # Test from longest possible prefix match down to current max_match_len + 1
            for k in range(limit, max_match_len, -1):
                prefix = cand[:k]
                if text.endswith(prefix):
                    max_match_len = k
                    break

        return text_len - max_match_len

    def flush(self) -> str:
        """Hydrate and flush all remaining buffered text when the stream ends.

        Returns:
            The final de-anonymized string from the buffer.
        """
        if not self.buffer:
            return ""

        final_text = self.vault.hydrate(self.buffer, self.session_id)
        self.buffer = ""
        return final_text

    def transform(self, stream: Iterable[str]) -> Iterator[str]:
        """Synchronously transform an iterable stream of chunks into hydrated chunks."""
        for chunk in stream:
            emitted = self.process_chunk(chunk)
            if emitted:
                yield emitted
        flushed = self.flush()
        if flushed:
            yield flushed

    async def transform_async(self, async_stream: AsyncIterable[str]) -> AsyncIterator[str]:
        """Asynchronously transform an async iterable stream of chunks into hydrated chunks."""
        async for chunk in async_stream:
            emitted = self.process_chunk(chunk)
            if emitted:
                yield emitted
        flushed = self.flush()
        if flushed:
            yield flushed
