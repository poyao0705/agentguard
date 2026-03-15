from __future__ import annotations


class AgentGuardError(Exception):
    """Base exception for AgentGuard."""


class PolicyDeniedError(AgentGuardError):
    """Raised when a policy denies an action."""

    def __init__(self, decision):
        self.decision = decision
        super().__init__(decision.reason or "Action denied by policy")


class ApprovalRequiredError(AgentGuardError):
    """Raised when a policy requires approval for an action."""

    def __init__(self, decision):
        self.decision = decision
        super().__init__(decision.reason or "Action requires approval")


class InvalidPolicyError(AgentGuardError):
    """Raised when a policy definition is malformed or invalid."""
