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


class EvaluationError(GuardianAngelError):
    """Raised when a predicate or rule evaluation cannot be completed safely."""


class ApprovalBackendError(GuardianAngelError):
    """Raised when the approval backend fails and no response is available."""

    def __init__(self, decision, cause: Exception):
        self.decision = decision
        self.cause = cause
        super().__init__(decision.reason or "Approval backend failure")


class RequestValidationError(GuardianAngelError):
    """Raised when request input is malformed."""