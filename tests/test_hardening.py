from __future__ import annotations

import json

import pytest

from guardian_angel import (
    ActionRequest,
    DecisionSource,
    DecisionStatus,
    EvaluationError,
    GuardConfig,
    GuardianAngel,
    InvalidPolicyError,
    RequestValidationError,
    Rule,
)
from guardian_angel.cli.evaluate import load_request
from guardian_angel.core.evaluator import evaluate_condition
from guardian_angel.core.predicates import Condition


def test_no_match_with_default_allow():
    guard = GuardianAngel(rules=[])
    decision = guard.authorize(ActionRequest(tool="read"))
    assert decision.status == DecisionStatus.ALLOW
    assert decision.source == DecisionSource.NO_MATCH


def test_no_match_with_default_deny():
    guard = GuardianAngel(
        rules=[],
        config=GuardConfig(default_decision=DecisionStatus.DENY),
    )
    decision = guard.authorize(ActionRequest(tool="read"))
    assert decision.status == DecisionStatus.DENY


def test_protected_tool_no_match():
    guard = GuardianAngel(
        rules=[],
        config=GuardConfig(
            protected_tool_prefixes=("github.",),
            protected_no_match_decision=DecisionStatus.REQUIRE_APPROVAL,
        ),
    )
    decision = guard.authorize(ActionRequest(tool="github.delete_branch"))
    assert decision.status == DecisionStatus.REQUIRE_APPROVAL


def test_evaluator_type_mismatch_raises_domain_error():
    with pytest.raises(EvaluationError):
        evaluate_condition(
            ActionRequest(tool="deploy", attributes={"count": "oops"}),
            Condition(key="count", op="gt", value=1),
        )


def test_missing_keys_with_exists_and_not_exists():
    request = ActionRequest(tool="deploy")
    assert evaluate_condition(request, Condition(key="subject.id", op="not_exists")) is True
    assert evaluate_condition(request, Condition(key="subject.id", op="exists")) is False


def test_multiple_matching_rules_follow_first_match_wins():
    guard = GuardianAngel(
        rules=[
            Rule(name="allow-first", tool="deploy", decision=DecisionStatus.ALLOW),
            Rule(name="deny-second", tool="deploy", decision=DecisionStatus.DENY),
        ]
    )
    decision = guard.authorize(ActionRequest(tool="deploy"))
    assert decision.status == DecisionStatus.ALLOW
    assert decision.rule_name == "allow-first"


def test_malformed_cli_request_file(tmp_path):
    request_path = tmp_path / "request.json"
    request_path.write_text("{not-json}")
    with pytest.raises(RequestValidationError, match="Malformed JSON"):
        load_request(str(request_path))


def test_unknown_cli_request_fields_rejected(tmp_path):
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps({"tool": "deploy", "extra": True}))
    with pytest.raises(RequestValidationError, match="Unknown request field"):
        load_request(str(request_path))


def test_invalid_policy_schema_rejected(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
rules:
  - name: bad
    tool: deploy
    decision: deny
    when:
      key: subject.id
      op: exists
      value_from: other.field
"""
    )
    with pytest.raises(InvalidPolicyError, match="does not accept"):
        GuardianAngel.from_yaml(str(policy_path))


def test_request_validation_rejects_non_mapping_attributes():
    with pytest.raises(RequestValidationError, match="'attributes' must be a mapping"):
        ActionRequest(tool="deploy", attributes="bad")


def test_evaluation_error_policy_can_require_approval():
    class BrokenRule(Rule):
        def matches(self, request: ActionRequest) -> bool:
            raise EvaluationError("broken")

    guard = GuardianAngel(
        rules=[BrokenRule(name="broken", tool="deploy", decision=DecisionStatus.DENY)],
        config=GuardConfig(on_evaluation_error=DecisionStatus.REQUIRE_APPROVAL),
    )
    decision = guard.authorize(ActionRequest(tool="deploy"))
    assert decision.status == DecisionStatus.REQUIRE_APPROVAL
    assert decision.source == DecisionSource.EVALUATION_ERROR