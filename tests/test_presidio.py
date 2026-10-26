"""
Unit tests for Presidio integration and custom detector pluggability.
"""

from __future__ import annotations

from typing import NamedTuple
import pytest

from shadow_vault.detectors import DetectedEntity, EntityType
from shadow_vault.engine import ShadowVault
from shadow_vault.integrations.presidio import PresidioDetector


class MockRecognizerResult(NamedTuple):
    entity_type: str
    start: int
    end: int
    score: float


class MockAnalyzerEngine:
    def __init__(self, entities: list[MockRecognizerResult]) -> None:
        self._entities = entities

    def analyze(
        self,
        text: str,
        entities: list[str] | None = None,
        language: str = "en",
        score_threshold: float = 0.6,
    ) -> list[MockRecognizerResult]:
        return [e for e in self._entities if e.score >= score_threshold]


def test_custom_detector_person_name_dehydration_and_hydration() -> None:
    """Test custom detector callback allows pluggable entity recognition like person names."""
    vault = ShadowVault()
    session_id = "sess_custom_ner"

    # Custom detector that finds "John Doe" or "Alice Smith"
    def simple_person_detector(text: str) -> list[DetectedEntity]:
        names = ["John Doe", "Alice Smith", "Dr. Gregory House"]
        results: list[DetectedEntity] = []
        for name in names:
            idx = 0
            while True:
                found = text.find(name, idx)
                if found == -1:
                    break
                results.append(
                    DetectedEntity(
                        entity_type=EntityType.PERSON.value,
                        value=name,
                        start=found,
                        end=found + len(name),
                        score=0.99,
                    )
                )
                idx = found + len(name)
        return results

    vault.register_custom_detector(simple_person_detector)

    raw_text = "Referral from Dr. Gregory House for patient John Doe with card 4532 0151 1283 0366"
    dehydrated = vault.dehydrate(raw_text, session_id=session_id)

    # Both person names and credit card should be dehydrated
    assert "Dr. Gregory House" not in dehydrated
    assert "John Doe" not in dehydrated
    assert "4532 0151 1283 0366" not in dehydrated
    assert "Anon_" in dehydrated

    # Reversible hydration restores real names
    hydrated = vault.hydrate(dehydrated, session_id=session_id)
    assert hydrated == raw_text


def test_presidio_detector_adapter_with_mock_analyzer() -> None:
    """Test PresidioDetector converts Presidio AnalyzerEngine results to DetectedEntity."""
    text = "Contact Jane Doe regarding reimbursement."
    # "Jane Doe" is at index 8..16
    mock_results = [
        MockRecognizerResult(entity_type="PERSON", start=8, end=16, score=0.95),
    ]
    mock_analyzer = MockAnalyzerEngine(mock_results)

    detector = PresidioDetector(analyzer=mock_analyzer, score_threshold=0.7)
    entities = detector(text)

    assert len(entities) == 1
    assert entities[0].entity_type == EntityType.PERSON.value
    assert entities[0].value == "Jane Doe"
    assert entities[0].start == 8
    assert entities[0].end == 16
    assert entities[0].score == 0.95


def test_presidio_detector_missing_dependency_message() -> None:
    """Test clear ImportError message when presidio-analyzer is not installed."""
    detector = PresidioDetector()
    detector._analyzer = None  # Simulate missing analyzer

    with pytest.raises(ImportError, match="Microsoft Presidio Analyzer is not installed"):
        detector("Any text")
