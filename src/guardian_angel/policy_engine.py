from .decision import Decision, ALLOW
from .request import ActionRequest
from .rule import Rule


class PolicyEngine:
    """Local policy evaluator using first-match-wins semantics.

    Rules are evaluated top to bottom. The first matching rule determines
    the decision. If no rule matches, the default decision is allow.
    """

    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def evaluate(self, request: ActionRequest) -> Decision:
        for rule in self.rules:
            if rule.matches(request):
                return Decision(
                    status=rule.decision,
                    reason=f"Matched rule: {rule.name}",
                    rule_name=rule.name,
                )

        return Decision(status=ALLOW, reason="No matching rule; default allow")