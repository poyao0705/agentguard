from __future__ import annotations


class GuardianAngelError(Exception):
    """Base exception for GuardianAngel."""


class PolicyDeniedError(GuardianAngelError):
    """Raised when a policy denies an action."""

    def __init__(self, decision):
        self.decision = decision
        super().__init__(decision.reason or "Action denied by policy")


class ApprovalRequiredError(GuardianAngelError):
    """Raised when a policy requires approval for an action."""

    def __init__(self, decision):
        self.decision = decision
        super().__init__(decision.reason or "Action requires approval")


class InvalidPolicyError(GuardianAngelError):
    """Raised when a policy definition is malformed or invalid."""
