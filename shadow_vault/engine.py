"""
Recursive dehydrate (anonymize) and hydrate (de-anonymize) proxy engine.
"""

from __future__ import annotations

from typing import Any, Mapping
from pydantic import BaseModel

from shadow_vault.detectors import detect_entities
from shadow_vault.store import VaultStore
from shadow_vault.synthesizer import is_synthetic, synthesize_token


class ShadowVault:
    """Bi-directional PII proxy engine for AI agents, LangChain/LangGraph, and MCP tools."""

    def __init__(
        self,
        store: VaultStore | None = None,
        db_path: str = ":memory:",
        ttl_seconds: float | None = None,
    ) -> None:
        """Initialize ShadowVault.

        Args:
            store: Optional pre-configured VaultStore instance.
            db_path: Path to SQLite file or ':memory:' if store is not supplied.
            ttl_seconds: Optional TTL expiration in seconds for stored mappings.
        """
        if store is not None:
            self.store = store
        else:
            self.store = VaultStore(db_path=db_path, ttl_seconds=ttl_seconds)

    def dehydrate(self, data: Any, session_id: str = "default", ttl: float | None = None) -> Any:
        """Recursively scan data and substitute real PII with format-preserving synthetic tokens.

        Traverses strings, dictionaries, lists, tuples, and Pydantic BaseModel instances.
        On strings, replaces detected spans from right-to-left to preserve text indices.

        Args:
            data: Arbitrary data structure containing potential PII.
            session_id: Session identifier to scope token mappings.
            ttl: Optional TTL in seconds for session storage.

        Returns:
            Dehydrated data structure with sensitive entities replaced by synthetic tokens.
        """
        if ttl is not None and hasattr(self.store, "ttl_seconds"):
            self.store.ttl_seconds = ttl

        if data is None:
            return None

        # 1. String: Run detection and right-to-left replacement
        if isinstance(data, str):
            return self._dehydrate_string(data, session_id)

        # 2. Pydantic BaseModel: Dehydrate fields and reconstruct
        if isinstance(data, BaseModel):
            return self._dehydrate_model(data, session_id)

        # 3. Dictionary: Preserve keys and dehydrate values
        if isinstance(data, dict):
            return {key: self.dehydrate(val, session_id) for key, val in data.items()}

        # 4. List: Dehydrate all elements
        if isinstance(data, list):
            return [self.dehydrate(item, session_id) for item in data]

        # 5. Tuple / NamedTuple: Dehydrate all elements
        if isinstance(data, tuple):
            if hasattr(data, "_fields"):  # NamedTuple support
                return type(data)(*(self.dehydrate(item, session_id) for item in data))
            return tuple(self.dehydrate(item, session_id) for item in data)

        # 6. Primitive types (int, float, bool, etc.)
        return data

    def _dehydrate_string(self, text: str, session_id: str) -> str:
        """Dehydrate a single text string using right-to-left substitution."""
        if not text:
            return text

        entities = detect_entities(text)
        if not entities:
            return text

        # Right-to-left replacement guarantees that earlier span indices remain intact
        result = text
        for entity in reversed(entities):
            # Skip spans that are already synthetic to prevent double-dehydration
            if is_synthetic(entity.value):
                continue

            synth_val = self.store.get_or_create(
                session_id=session_id,
                entity_type=entity.entity_type,
                real_val=entity.value,
                generator_fn=synthesize_token,
            )
            result = result[: entity.start] + synth_val + result[entity.end :]

        return result

    def _dehydrate_model(self, model: BaseModel, session_id: str) -> BaseModel:
        """Dehydrate fields of a Pydantic model instance."""
        fields_data: dict[str, Any] = {}
        for field_name in model.__class__.model_fields:
            val = getattr(model, field_name)
            fields_data[field_name] = self.dehydrate(val, session_id)

        try:
            return model.__class__(**fields_data)
        except Exception:
            # Fallback to model_copy with field overrides if custom validators reject
            return model.model_copy(update=fields_data)

    def hydrate(self, data: Any, session_id: str = "default") -> Any:
        """Recursively restore original PII values from synthetic tokens.

        Traverses strings, dictionaries, lists, tuples, and Pydantic BaseModel instances.
        Substitutes synthetic tokens ordered by length descending. Handles numeric
        coercion if an LLM returns a numeric string as an int or float.

        Args:
            data: Data structure containing synthetic tokens to de-anonymize.
            session_id: Session identifier to retrieve mappings from.

        Returns:
            Hydrated data structure with original real PII restored.
        """
        session_map = self.store.get_session_map(session_id)
        if not session_map:
            return data

        return self._hydrate_recursive(data, session_map, session_id)

    def _hydrate_recursive(
        self,
        data: Any,
        session_map: Mapping[str, str],
        session_id: str,
    ) -> Any:
        """Recursive traversal helper for hydration."""
        if data is None:
            return None

        # 1. String: Replace synthetic tokens in descending length order
        if isinstance(data, str):
            text = data
            for synth_val, real_val in session_map.items():
                if synth_val in text:
                    text = text.replace(synth_val, real_val)
            return text

        # 2. Numeric type (int/float): Check if an LLM coerced a numeric token
        if isinstance(data, (int, float)) and not isinstance(data, bool):
            str_repr = str(data)
            if str_repr in session_map:
                real_val = session_map[str_repr]
                # Return the original real value
                return real_val
            return data

        # 3. Pydantic BaseModel
        if isinstance(data, BaseModel):
            fields_data: dict[str, Any] = {}
            for field_name in data.__class__.model_fields:
                val = getattr(data, field_name)
                fields_data[field_name] = self._hydrate_recursive(val, session_map, session_id)
            try:
                return data.__class__(**fields_data)
            except Exception:
                return data.model_copy(update=fields_data)

        # 4. Dictionary
        if isinstance(data, dict):
            return {
                key: self._hydrate_recursive(val, session_map, session_id)
                for key, val in data.items()
            }

        # 5. List
        if isinstance(data, list):
            return [self._hydrate_recursive(item, session_map, session_id) for item in data]

        # 6. Tuple / NamedTuple
        if isinstance(data, tuple):
            if hasattr(data, "_fields"):
                return type(data)(
                    *(self._hydrate_recursive(item, session_map, session_id) for item in data)
                )
            return tuple(self._hydrate_recursive(item, session_map, session_id) for item in data)

        return data

    def get_session_map(self, session_id: str = "default") -> dict[str, str]:
        """Return {synth_val: real_val} sorted by length descending for session."""
        return self.store.get_session_map(session_id)

    def clear_session(self, session_id: str = "default") -> None:
        """Purge all mappings for the specified session."""
        self.store.clear_session(session_id)

    def stream(self, session_id: str = "default") -> "StreamHydrator":
        """Return a StreamHydrator configured for the specified session."""
        from shadow_vault.stream import StreamHydrator

        return StreamHydrator(vault=self, session_id=session_id)

    def close(self) -> None:
        """Close underlying VaultStore."""
        self.store.close()

    def __enter__(self) -> ShadowVault:
        return self

    def __exit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: object | None) -> None:
        self.close()
