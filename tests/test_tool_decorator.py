import pytest

from guardian_angel import (
    ApprovalRequiredError,
    DecisionStatus,
    GuardConfig,
    GuardianAngel,
    PolicyDeniedError,
    Rule,
)


def _make_guard(*rules):
    return GuardianAngel(rules=list(rules))


class TestToolDecorator:
    def test_allowed_tool_executes(self):
        guard = _make_guard()  # no rules → default allow

        @guard.tool(name="read_file")
        def read_file(path):
            return f"contents of {path}"

        result = read_file("README.md")
        assert result == "contents of README.md"

    def test_denied_tool_raises(self):
        guard = _make_guard(
            Rule(name="block_delete", tool="delete_file", decision=DecisionStatus.DENY)
        )

        @guard.tool(name="delete_file")
        def delete_file(path):
            _ = path
            return "deleted"

        with pytest.raises(PolicyDeniedError) as exc_info:
            delete_file("/etc/passwd")

        assert exc_info.value.decision.status == DecisionStatus.DENY
        assert exc_info.value.decision.rule_name == "block_delete"

    def test_require_approval_raises(self):
        guard = _make_guard(
            Rule(name="approve_deploy", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)
        )

        @guard.tool(name="deploy")
        def deploy(target):
            _ = target
            return "deployed"

        with pytest.raises(ApprovalRequiredError) as exc_info:
            deploy("prod")

        assert exc_info.value.decision.status == DecisionStatus.REQUIRE_APPROVAL
        assert exc_info.value.decision.rule_name == "approve_deploy"

    def test_attributes_from_kwargs_are_used(self):
        guard = _make_guard(
            Rule(
                name="block_prod",
                tool="deploy",
                decision=DecisionStatus.DENY,
                attributes={"resource.environment": "prod"},
            )
        )

        @guard.tool(name="deploy")
        def deploy(target, *, __guard_attributes__=None):
            _ = (target, __guard_attributes__)
            return "deployed"

        # Should be blocked when resource.environment=prod
        with pytest.raises(PolicyDeniedError):
            deploy("app", __guard_attributes__={"resource.environment": "prod"})

        # Should be allowed when resource.environment=staging (no matching rule)
        result = deploy("app", __guard_attributes__={"resource.environment": "staging"})
        assert result == "deployed"

    def test_request_id_is_passed_into_request(self):
        guard = _make_guard(
            Rule(
                name="block_high_risk",
                tool="github.pr",
                decision=DecisionStatus.DENY,
                attributes={"context.risk_level": "high"},
            )
        )

        @guard.tool(name="github.pr")
        def merge_pr(pr_id, *, __guard_attributes__=None, __guard_request_id__=None):
            _ = (pr_id, __guard_attributes__, __guard_request_id__)
            return "merged"

        with pytest.raises(PolicyDeniedError):
            merge_pr(
                "42",
                __guard_request_id__="req-42",
                __guard_attributes__={"context.risk_level": "high"},
            )

    def test_decorator_preserves_function_name(self):
        guard = _make_guard()

        @guard.tool(name="my_tool")
        def my_special_function():
            """My docstring."""
            return True

        assert my_special_function.__name__ == "my_special_function"
        assert my_special_function.__doc__ == "My docstring."

    def test_protected_tool_no_match_can_require_approval(self):
        guard = GuardianAngel(
            rules=[],
            config=GuardConfig(
                protected_tools=frozenset({"delete_file"}),
                protected_no_match_decision=DecisionStatus.REQUIRE_APPROVAL,
            ),
        )

        @guard.tool(name="delete_file")
        def delete_file(path):
            _ = path
            return "deleted"

        with pytest.raises(ApprovalRequiredError):
            delete_file("/tmp/x")

    def test_approval_backend_failure_can_allow_execution(self):
        class BrokenHandler:
            def submit(self, request):
                raise RuntimeError("approval backend down")

        guard = GuardianAngel(
            rules=[Rule(name="approve_deploy", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=BrokenHandler(),
            config=GuardConfig(on_approval_error=DecisionStatus.ALLOW),
        )

        @guard.tool(name="deploy")
        def deploy(target):
            return f"deployed {target}"

        assert deploy("prod") == "deployed prod"
