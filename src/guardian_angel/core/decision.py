from dataclasses import dataclass
from enum import StrEnum


class DecisionStatus(StrEnum):
    """Enumeration of possible decision statuses."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class DecisionSource(StrEnum):
    """Describes the path that produced a decision."""

    RULE_MATCH = "rule_match"
    NO_MATCH = "no_match"
    EVALUATION_ERROR = "evaluation_error"
    APPROVAL_ERROR = "approval_error"
    CUSTOM = "custom"


@dataclass
class Decision:
    """Result of a policy evaluation."""

    status: DecisionStatus
    reason: str | None = None
    rule_name: str | None = None
    source: DecisionSource = DecisionSource.CUSTOM
    error: str | None = None