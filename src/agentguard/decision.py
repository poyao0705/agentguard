from dataclasses import dataclass

ALLOW = "allow"
DENY = "deny"
REQUIRE_APPROVAL = "require_approval"


@dataclass
class Decision:
    """Result of a policy evaluation."""

    status: str
    reason: str | None = None
    rule_name: str | None = None