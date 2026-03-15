import pytest

from guardian_angel import (
    ALLOW,
    DENY,
    REQUIRE_APPROVAL,
    GuardianAngel,
    ApprovalRequiredError,
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
            Rule(name="block_delete", tool="delete_file", decision=DENY)
        )

        @guard.tool(name="delete_file")
        def delete_file(path):
            return "deleted"

        with pytest.raises(PolicyDeniedError) as exc_info:
            delete_file("/etc/passwd")

        assert exc_info.value.decision.status == DENY
        assert exc_info.value.decision.rule_name == "block_delete"

    def test_require_approval_raises(self):
        guard = _make_guard(
            Rule(name="approve_deploy", tool="deploy", decision=REQUIRE_APPROVAL)
        )

        @guard.tool(name="deploy")
        def deploy(target):
            return "deployed"

        with pytest.raises(ApprovalRequiredError) as exc_info:
            deploy("prod")

        assert exc_info.value.decision.status == REQUIRE_APPROVAL
        assert exc_info.value.decision.rule_name == "approve_deploy"

    def test_attributes_from_kwargs_are_used(self):
        guard = _make_guard(
            Rule(
                name="block_prod",
                tool="deploy",
                decision=DENY,
                attributes={"env": "prod"},
            )
        )

        @guard.tool(name="deploy")
        def deploy(target, *, attributes=None):
            return "deployed"

        # Should be blocked when env=prod
        with pytest.raises(PolicyDeniedError):
            deploy("app", attributes={"env": "prod"})

        # Should be allowed when env=staging (no matching rule)
        result = deploy("app", attributes={"env": "staging"})
        assert result == "deployed"

    def test_action_is_passed_through(self):
        guard = _make_guard(
            Rule(
                name="block_merge",
                tool="github.pr",
                action="merge",
                decision=DENY,
            )
        )

        @guard.tool(name="github.pr", action="merge")
        def merge_pr(pr_id):
            return "merged"

        with pytest.raises(PolicyDeniedError):
            merge_pr("42")

    def test_decorator_preserves_function_name(self):
        guard = _make_guard()

        @guard.tool(name="my_tool")
        def my_special_function():
            """My docstring."""
            return True

        assert my_special_function.__name__ == "my_special_function"
        assert my_special_function.__doc__ == "My docstring."
