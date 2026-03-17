from __future__ import annotations

from typing import Protocol, runtime_checkable

from .config import GuardConfig
from .decision import Decision, DecisionSource
from .evaluator import MISSING, resolve_key
from .exceptions import EvaluationError
from .request import ActionRequest
from .rule import Rule


@runtime_checkable
class PolicyEvaluator(Protocol):
    """Interface for policy evaluation.

    Implement this protocol to provide a custom evaluation strategy
    (e.g., remote policy service, different matching semantics).
    """

    def evaluate(self, request: ActionRequest) -> Decision: ...


class PolicyEngine:
    """Local policy evaluator using first-match-wins semantics.

    Rules are evaluated top to bottom. The first matching rule determines
    the decision. If no rule matches, the default decision is allow.
    """

    def __init__(self, rules: list[Rule], *, config: GuardConfig | None = None):
        self.rules = rules
        self.config = config or GuardConfig()
        self.rules_by_tool = self._index_rules(rules)

    @staticmethod
    def _index_rules(rules: list[Rule]) -> dict[str, list[Rule]]:
        rules_by_tool: dict[str, list[Rule]] = {}
        for rule in rules:
            rules_by_tool.setdefault(rule.tool, []).append(rule)
        return rules_by_tool

    def _is_protected_tool(self, tool: str) -> bool:
        if tool in self.config.protected_tools:
            return True
        return any(tool.startswith(prefix) for prefix in self.config.protected_tool_prefixes)

    def _decision_for_no_match(self, request: ActionRequest) -> Decision:
        status = self.config.default_decision
        reason = f"No matching rule for tool {request.tool!r}; defaulting to {status.value}"
        if self._is_protected_tool(request.tool) and self.config.protected_no_match_decision is not None:
            status = self.config.protected_no_match_decision
            reason = (
                f"No matching rule for protected tool {request.tool!r}; "
                f"defaulting to {status.value}"
            )
        return Decision(status=status, reason=reason, source=DecisionSource.NO_MATCH)

    def _decision_for_evaluation_error(self, error: EvaluationError) -> Decision:
        return Decision(
            status=self.config.on_evaluation_error,
            reason=f"Policy evaluation error: {error}",
            source=DecisionSource.EVALUATION_ERROR,
            error=str(error),
        )

    def _validate_required_fields(self, request: ActionRequest) -> EvaluationError | None:
        missing_fields = [
            field_name
            for field_name in self.config.required_fields
            if resolve_key(request, field_name) is MISSING
        ]
        if not missing_fields:
            return None
        return EvaluationError(
            f"Missing required request field(s): {', '.join(sorted(missing_fields))}"
        )

    def evaluate(self, request: ActionRequest) -> Decision:
        required_fields_error = self._validate_required_fields(request)
        if required_fields_error is not None:
            return self._decision_for_evaluation_error(required_fields_error)

        for rule in self.rules_by_tool.get(request.tool, []):
            try:
                matched = rule.matches(request)
            except EvaluationError as exc:
                return self._decision_for_evaluation_error(exc)
            except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
                return self._decision_for_evaluation_error(EvaluationError(str(exc)))

            if matched:
                return Decision(
                    status=rule.decision,
                    reason=f"Matched rule: {rule.name}",
                    rule_name=rule.name,
                    source=DecisionSource.RULE_MATCH,
                )

        return self._decision_for_no_match(request)