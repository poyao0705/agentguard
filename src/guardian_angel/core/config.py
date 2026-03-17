from __future__ import annotations

from dataclasses import dataclass, field

from .decision import DecisionStatus


@dataclass(frozen=True, slots=True)
class GuardConfig:
    """Configuration for policy, evaluation, and approval fallback semantics."""

    default_decision: DecisionStatus = DecisionStatus.ALLOW
    on_evaluation_error: DecisionStatus = DecisionStatus.DENY
    on_approval_error: DecisionStatus = DecisionStatus.DENY
    protected_tools: frozenset[str] = field(default_factory=frozenset)
    protected_tool_prefixes: tuple[str, ...] = ()
    protected_no_match_decision: DecisionStatus | None = None
    required_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "protected_tools", frozenset(self._validate_strings("protected_tools", self.protected_tools)))
        object.__setattr__(self, "protected_tool_prefixes", tuple(self._validate_strings("protected_tool_prefixes", self.protected_tool_prefixes)))
        object.__setattr__(self, "required_fields", tuple(self._validate_strings("required_fields", self.required_fields)))

    @staticmethod
    def _validate_strings(field_name: str, values: frozenset[str] | tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must contain only non-empty strings")
            normalized.append(value)
        return tuple(normalized)