"""
Privacy policies, tool-specific entity constraints, and fail-closed controls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class FailClosedAction(str, Enum):
    """Behavior when hydration encounters an unmapped or expired synthetic token."""

    PASS_THROUGH = "pass_through"
    RAISE = "raise"
    REDACT = "redact"


class UnmappedTokenError(Exception):
    """Raised when an unmapped or expired synthetic token cannot be hydrated in fail-closed mode."""

    def __init__(self, token: str, session_id: str, message: str | None = None) -> None:
        self.token = token
        self.session_id = session_id
        super().__init__(
            message
            or f"Fail-closed policy violation: Unmapped or expired synthetic token '{token}' in session '{session_id}'."
        )


class PIILeakBlockedError(Exception):
    """Raised when raw PII is blocked from outbound transmission in fail-closed mode."""

    def __init__(self, entity_type: str, session_id: str, message: str | None = None) -> None:
        self.entity_type = entity_type
        self.session_id = session_id
        super().__init__(
            message
            or f"Fail-closed policy violation: Unmasked PII of type '{entity_type}' blocked from outbound payload."
        )


@dataclass
class ToolPolicy:
    """Privacy rule governing tool invocation and entity hydration.

    Attributes:
        tool_name: Name of the tool (e.g. 'charge_card', 'send_slack').
        allow_hydration: If False, tool execution receives synthetic tokens directly (zero real PII).
        allowed_entities: Set of entity types permitted to hydrate (e.g. {'EMAIL', 'CREDIT_CARD'}).
        disallowed_entities: Set of entity types strictly prohibited from hydrating.
        fail_closed: Whether to enforce fail-closed behavior on unmapped tokens.
        fail_action: Action to take on fail-closed violation (RAISE, REDACT, PASS_THROUGH).
    """

    tool_name: str
    allow_hydration: bool = True
    allowed_entities: set[str] | None = None
    disallowed_entities: set[str] = field(default_factory=set)
    fail_closed: bool = False
    fail_action: FailClosedAction = FailClosedAction.RAISE

    def can_hydrate_entity(self, entity_type: str) -> bool:
        """Return True if the specified entity type is allowed to hydrate under this policy."""
        if not self.allow_hydration:
            return False

        type_upper = entity_type.upper()
        if type_upper in {d.upper() for d in self.disallowed_entities}:
            return False

        if self.allowed_entities is not None:
            return type_upper in {a.upper() for a in self.allowed_entities}

        return True


class PolicyManager:
    """Central registry and evaluator for tool-level privacy policies."""

    def __init__(
        self,
        default_fail_closed: bool = False,
        default_fail_action: FailClosedAction | None = None,
    ) -> None:
        self.default_fail_closed = default_fail_closed
        if default_fail_action is not None:
            self.default_fail_action = default_fail_action
        else:
            self.default_fail_action = (
                FailClosedAction.RAISE if default_fail_closed else FailClosedAction.PASS_THROUGH
            )
        self._policies: dict[str, ToolPolicy] = {}

    def register_policy(self, policy: ToolPolicy) -> None:
        """Register a tool-specific policy."""
        self._policies[policy.tool_name] = policy

    def get_policy(self, tool_name: str | None) -> ToolPolicy:
        """Retrieve policy for a tool or return default permissive policy."""
        if tool_name and tool_name in self._policies:
            return self._policies[tool_name]

        return ToolPolicy(
            tool_name=tool_name or "*",
            allow_hydration=True,
            allowed_entities=None,
            disallowed_entities=set(),
            fail_closed=self.default_fail_closed,
            fail_action=self.default_fail_action,
        )
