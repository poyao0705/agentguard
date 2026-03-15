from dataclasses import dataclass, field


@dataclass
class ActionRequest:
    """Canonical input for policy evaluation."""

    tool: str
    action: str | None = None
    resource: dict | None = None
    attributes: dict = field(default_factory=dict)
    agent_id: str | None = None
    identity: dict | None = None