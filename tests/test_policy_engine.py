from guardian_angel import (
    ALLOW,
    DENY,
    REQUIRE_APPROVAL,
    ActionRequest,
    Decision,
    Rule,
)
from guardian_angel.policy_engine import PolicyEngine


class TestRuleMatching:
    def test_exact_tool_match(self):
        rule = Rule(name="r1", tool="github.merge_pr", decision=DENY)
        request = ActionRequest(tool="github.merge_pr")
        assert rule.matches(request)

    def test_tool_mismatch(self):
        rule = Rule(name="r1", tool="github.merge_pr", decision=DENY)
        request = ActionRequest(tool="github.delete_branch")
        assert not rule.matches(request)

    def test_action_match(self):
        rule = Rule(name="r1", tool="github.pr", action="merge", decision=DENY)
        request = ActionRequest(tool="github.pr", action="merge")
        assert rule.matches(request)

    def test_action_mismatch(self):
        rule = Rule(name="r1", tool="github.pr", action="merge", decision=DENY)
        request = ActionRequest(tool="github.pr", action="close")
        assert not rule.matches(request)

    def test_action_not_specified_in_rule_matches_any(self):
        rule = Rule(name="r1", tool="github.pr", decision=DENY)
        request = ActionRequest(tool="github.pr", action="merge")
        assert rule.matches(request)

    def test_attribute_match(self):
        rule = Rule(
            name="r1", tool="deploy", decision=DENY, attributes={"env": "prod"}
        )
        request = ActionRequest(tool="deploy", attributes={"env": "prod"})
        assert rule.matches(request)

    def test_attribute_mismatch(self):
        rule = Rule(
            name="r1", tool="deploy", decision=DENY, attributes={"env": "prod"}
        )
        request = ActionRequest(tool="deploy", attributes={"env": "staging"})
        assert not rule.matches(request)

    def test_attribute_missing_from_request(self):
        rule = Rule(
            name="r1", tool="deploy", decision=DENY, attributes={"env": "prod"}
        )
        request = ActionRequest(tool="deploy")
        assert not rule.matches(request)

    def test_extra_request_attributes_still_match(self):
        rule = Rule(
            name="r1", tool="deploy", decision=DENY, attributes={"env": "prod"}
        )
        request = ActionRequest(
            tool="deploy", attributes={"env": "prod", "region": "us-east-1"}
        )
        assert rule.matches(request)


class TestPolicyEngine:
    def test_exact_match_returns_decision(self):
        engine = PolicyEngine(
            rules=[Rule(name="block", tool="deploy", decision=DENY)]
        )
        decision = engine.evaluate(ActionRequest(tool="deploy"))
        assert decision.status == DENY
        assert decision.rule_name == "block"

    def test_no_match_defaults_to_allow(self):
        engine = PolicyEngine(
            rules=[Rule(name="block", tool="deploy", decision=DENY)]
        )
        decision = engine.evaluate(ActionRequest(tool="read"))
        assert decision.status == ALLOW
        assert decision.rule_name is None

    def test_empty_rules_defaults_to_allow(self):
        engine = PolicyEngine(rules=[])
        decision = engine.evaluate(ActionRequest(tool="anything"))
        assert decision.status == ALLOW

    def test_first_match_wins(self):
        engine = PolicyEngine(
            rules=[
                Rule(name="deny_first", tool="deploy", decision=DENY),
                Rule(name="allow_second", tool="deploy", decision=ALLOW),
            ]
        )
        decision = engine.evaluate(ActionRequest(tool="deploy"))
        assert decision.status == DENY
        assert decision.rule_name == "deny_first"

    def test_first_match_wins_reversed(self):
        engine = PolicyEngine(
            rules=[
                Rule(name="allow_first", tool="deploy", decision=ALLOW),
                Rule(name="deny_second", tool="deploy", decision=DENY),
            ]
        )
        decision = engine.evaluate(ActionRequest(tool="deploy"))
        assert decision.status == ALLOW
        assert decision.rule_name == "allow_first"

    def test_require_approval_decision(self):
        engine = PolicyEngine(
            rules=[
                Rule(
                    name="approve_prod",
                    tool="deploy",
                    decision=REQUIRE_APPROVAL,
                    attributes={"env": "prod"},
                )
            ]
        )
        decision = engine.evaluate(
            ActionRequest(tool="deploy", attributes={"env": "prod"})
        )
        assert decision.status == REQUIRE_APPROVAL
        assert decision.rule_name == "approve_prod"

    def test_rule_name_populated_in_decision(self):
        engine = PolicyEngine(
            rules=[Rule(name="my_rule", tool="x", decision=DENY)]
        )
        decision = engine.evaluate(ActionRequest(tool="x"))
        assert decision.rule_name == "my_rule"
        assert "my_rule" in decision.reason
