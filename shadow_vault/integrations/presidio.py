"""
Microsoft Presidio integration adapter for ShadowVault.

Enables Named-Entity Recognition (NER) for PERSON, LOCATION, and custom entities,
while integrating with ShadowVault's format-preserving synthetic tokens,
at-rest AES envelope encryption, and Model Context Protocol (MCP) gateway.
"""

from __future__ import annotations

from typing import Any, Sequence
from shadow_vault.detectors import DetectedEntity, EntityType


class PresidioDetector:
    """Adapter bridging Microsoft Presidio AnalyzerEngine to ShadowVault."""

    def __init__(
        self,
        analyzer: Any | None = None,
        entities: Sequence[str] | None = None,
        language: str = "en",
        score_threshold: float = 0.6,
    ) -> None:
        """Initialize PresidioDetector.

        Args:
            analyzer: Optional pre-configured presidio_analyzer.AnalyzerEngine instance.
            entities: Optional list of Presidio entity types to detect (e.g. ['PERSON', 'LOCATION']).
                Defaults to ['PERSON'].
            language: Language code for NLP analyzer (default 'en').
            score_threshold: Minimum confidence score (0.0 to 1.0) to accept.
        """
        self.language = language
        self.entities = list(entities) if entities is not None else ["PERSON", "LOCATION"]
        self.score_threshold = score_threshold

        if analyzer is not None:
            self._analyzer = analyzer
        else:
            try:
                from presidio_analyzer import AnalyzerEngine  # type: ignore

                self._analyzer = AnalyzerEngine()
            except ImportError:
                self._analyzer = None

    def __call__(self, text: str) -> list[DetectedEntity]:
        """Detect entities using Presidio AnalyzerEngine."""
        if not text:
            return []

        if self._analyzer is None:
            raise ImportError(
                "Microsoft Presidio Analyzer is not installed.\n"
                "To enable Presidio NER person & location detection, install it with:\n"
                "    pip install 'shadow-vault[presidio]'\n"
                "or:\n"
                "    pip install presidio-analyzer"
            )

        results = self._analyzer.analyze(
            text=text,
            entities=self.entities,
            language=self.language,
            score_threshold=self.score_threshold,
        )

        detected: list[DetectedEntity] = []
        for res in results:
            span_val = text[res.start : res.end]
            if res.entity_type == "PERSON":
                entity_type = EntityType.PERSON.value
            elif res.entity_type == "LOCATION":
                entity_type = EntityType.LOCATION.value
            else:
                entity_type = res.entity_type
            detected.append(
                DetectedEntity(
                    entity_type=entity_type,
                    value=span_val,
                    start=res.start,
                    end=res.end,
                    score=float(res.score),
                )
            )

        return detected
