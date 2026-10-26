"""
Recursive dehydrate (anonymize) and hydrate (de-anonymize) proxy engine.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping
from pydantic import BaseModel

from shadow_vault.detectors import (
    DetectedEntity,
    detect_entities,
    resolve_overlaps,
)
from shadow_vault.policy import (
    FailClosedAction,
    PIILeakBlockedError,
    PolicyManager,
    ToolPolicy,
    UnmappedTokenError,
)
from shadow_vault.store import VaultStore
from shadow_vault.synthesizer import find_synthetic_tokens, is_synthetic, synthesize_token


class ShadowVault:
    """Bi-directional PII proxy engine for AI agents, LangChain/LangGraph, and MCP tools."""

    def __init__(
        self,
        store: VaultStore | None = None,
        db_path: str = ":memory:",
        ttl_seconds: float | None = None,
        encryption_key: str | bytes | None = None,
        salt: str | bytes | None = None,
        fail_closed: bool = False,
        policy_manager: PolicyManager | None = None,
        custom_detectors: Iterable[Callable[[str], list[DetectedEntity]]] | None = None,
        require_encryption: bool = False,
    ) -> None:
        """Initialize ShadowVault.

        Args:
            store: Optional pre-configured VaultStore instance.
            db_path: Path to SQLite file or ':memory:' if store is not supplied.
            ttl_seconds: Optional TTL expiration in seconds for stored mappings.
            encryption_key: Optional key for authenticated AES/keystream encryption at rest.
            salt: Optional session salt for deterministic hashing.
            fail_closed: If True, blocks outbound leaks and enforces strict unmapped token policies.
            policy_manager: Optional PolicyManager for tool-level entity governance.
            custom_detectors: Optional list of custom detector callables (e.g. PresidioDetector).
            require_encryption: If True, enforces that an encryption key must be provided.
        """
        if store is not None:
            self.store = store
        else:
            self.store = VaultStore(
                db_path=db_path,
                ttl_seconds=ttl_seconds,
                encryption_key=encryption_key,
                salt=salt,
                require_encryption=require_encryption,
            )
        self.fail_closed = fail_closed
        self.policy_manager = policy_manager or PolicyManager(default_fail_closed=fail_closed)
        self.custom_detectors: list[Callable[[str], list[DetectedEntity]]] = (
            list(custom_detectors) if custom_detectors else []
        )

    def register_tool_policy(self, policy: ToolPolicy) -> None:
        """Register a privacy policy governing a specific tool."""
        self.policy_manager.register_policy(policy)

    def register_custom_detector(
        self, detector: Callable[[str], list[DetectedEntity]]
    ) -> None:
        """Register an external or custom detector (e.g. PresidioDetector)."""
        self.custom_detectors.append(detector)

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
        result = data

        if self.fail_closed and isinstance(result, str):
            entities = detect_entities(result)
            unmasked = [e for e in entities if not is_synthetic(e.value)]
            if unmasked:
                raise PIILeakBlockedError(
                    entity_type=unmasked[0].entity_type.value,
                    session_id=session_id,
                )

        return result

    def assert_no_pii_leak(self, data: Any, session_id: str = "default") -> None:
        """Scan data structure and raise PIILeakBlockedError if unmasked real PII is detected.

        Useful for asserting that outbound agent payloads, tool returns, or logs do not contain raw PII.
        """
        if isinstance(data, str):
            entities = detect_entities(data)
            if self.custom_detectors:
                for detector in self.custom_detectors:
                    try:
                        entities.extend(detector(data))
                    except Exception:
                        pass
            unmasked = [e for e in entities if not is_synthetic(e.value)]
            if unmasked:
                raw_type = unmasked[0].entity_type
                type_name = getattr(raw_type, "value", str(raw_type))
                raise PIILeakBlockedError(
                    entity_type=type_name,
                    session_id=session_id,
                )
        elif isinstance(data, dict):
            for v in data.values():
                self.assert_no_pii_leak(v, session_id)
        elif isinstance(data, (list, tuple, set)):
            for item in data:
                self.assert_no_pii_leak(item, session_id)
        elif isinstance(data, BaseModel):
            for field_name in data.model_fields:
                self.assert_no_pii_leak(getattr(data, field_name), session_id)

    def _dehydrate_string(self, text: str, session_id: str) -> str:
        """Dehydrate a single text string using right-to-left substitution."""
        if not text:
            return text

        entities = detect_entities(text)
        if self.custom_detectors:
            for custom_detector in self.custom_detectors:
                try:
                    c_entities = custom_detector(text)
                    if c_entities:
                        entities.extend(c_entities)
                except Exception:
                    pass
            entities = resolve_overlaps(entities)

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

    def hydrate(
        self,
        data: Any,
        session_id: str = "default",
        tool_name: str | None = None,
        policy: ToolPolicy | None = None,
        fail_closed: bool | None = None,
    ) -> Any:
        """Recursively restore original PII values from synthetic tokens.

        Traverses strings, dictionaries, lists, tuples, and Pydantic BaseModel instances.
        Substitutes synthetic tokens ordered by length descending. Handles numeric
        coercion if an LLM returns a numeric string as an int or float.

        Args:
            data: Data structure containing synthetic tokens to de-anonymize.
            session_id: Session identifier to retrieve mappings from.
            tool_name: Optional tool name to apply registered ToolPolicy.
            policy: Optional explicit ToolPolicy overriding registered policy.
            fail_closed: Optional override to enforce fail-closed unmapped token checks.

        Returns:
            Hydrated data structure with original real PII restored.
        """
        effective_policy = policy or self.policy_manager.get_policy(tool_name)
        is_fail_closed = (
            fail_closed
            if fail_closed is not None
            else (effective_policy.fail_closed if effective_policy else self.fail_closed)
        )

        # If policy disallows hydration for this tool, return data without restoring real PII
        if effective_policy and not effective_policy.allow_hydration:
            return data

        allowed_entities = effective_policy.allowed_entities if effective_policy else None
        session_map = self.store.get_session_map(
            session_id, allowed_entity_types=allowed_entities
        )

        if not session_map:
            result = data
        else:
            result = self._hydrate_recursive(data, session_map, session_id)

        if is_fail_closed:
            result = self._enforce_fail_closed(result, session_id, effective_policy)

        return result

    def _enforce_fail_closed(
        self,
        data: Any,
        session_id: str,
        policy: ToolPolicy | None,
    ) -> Any:
        """Recursively check for unmapped synthetic tokens in hydrated output."""
        action = policy.fail_action if policy else FailClosedAction.RAISE

        if isinstance(data, str):
            unmapped = find_synthetic_tokens(data)
            if unmapped:
                if action == FailClosedAction.RAISE:
                    raise UnmappedTokenError(token=unmapped[0], session_id=session_id)
                elif action == FailClosedAction.REDACT:
                    redacted = data
                    for token in unmapped:
                        redacted = redacted.replace(token, "[UNRESOLVED_TOKEN]")
                    return redacted
            return data

        if isinstance(data, dict):
            return {
                k: self._enforce_fail_closed(v, session_id, policy)
                for k, v in data.items()
            }

        if isinstance(data, list):
            return [self._enforce_fail_closed(item, session_id, policy) for item in data]

        if isinstance(data, tuple):
            return tuple(self._enforce_fail_closed(item, session_id, policy) for item in data)

        if isinstance(data, BaseModel):
            fields_data = {
                field_name: self._enforce_fail_closed(
                    getattr(data, field_name), session_id, policy
                )
                for field_name in data.__class__.model_fields
            }
            try:
                return data.__class__(**fields_data)
            except Exception:
                return data.model_copy(update=fields_data)

        return data

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
