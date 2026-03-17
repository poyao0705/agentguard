import pytest

from guardian_angel import (
    ApprovalRequiredError,
    DecisionStatus,
    GuardConfig,
    GuardContext,
    GuardianAngel,
    PolicyDeniedError,
    Rule,
)


def _make_guard(*rules):
    return GuardianAngel(rules=list(rules))


class TestInvoke:
    """Tests for guard.invoke() / guard.ainvoke()."""

    def test_invoke_allowed(self):
        guard = _make_guard()  # no rules → default allow

        def read_file(path):
            return f"contents of {path}"

        result = guard.invoke(read_file, "README.md")
        assert result == "contents of README.md"

    def test_invoke_denied(self):
        guard = _make_guard(
            Rule(name="block_delete", tool="resource.delete", decision=DecisionStatus.DENY),
        )

        def delete_resource(rid):
            return "deleted"

        with pytest.raises(PolicyDeniedError) as exc_info:
            guard.invoke(
                delete_resource,
                "doc-1",
                guard_ctx=GuardContext(tool="resource.delete"),
            )
        assert exc_info.value.decision.rule_name == "block_delete"

    def test_invoke_require_approval_no_handler(self):
        guard = _make_guard(
            Rule(name="approve_it", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL),
        )

        def deploy(target):
            return f"deployed {target}"

        with pytest.raises(ApprovalRequiredError):
            guard.invoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy"))

    def test_invoke_uses_function_name_when_no_tool(self):
        guard = _make_guard(
            Rule(name="block_it", tool="my_func", decision=DecisionStatus.DENY),
        )

        def my_func():
            return "ok"

        with pytest.raises(PolicyDeniedError):
            guard.invoke(my_func)

    def test_invoke_forwards_kwargs(self):
        guard = _make_guard()

        def greet(name, *, greeting="hello"):
            return f"{greeting} {name}"

        result = guard.invoke(greet, "world", greeting="hi")
        assert result == "hi world"

    def test_invoke_with_attributes(self):
        guard = _make_guard(
            Rule(
                name="block_prod",
                tool="deploy",
                decision=DecisionStatus.DENY,
                attributes={"resource.environment": "prod"},
            ),
        )

        def deploy(target):
            return f"deployed {target}"

        # blocked
        with pytest.raises(PolicyDeniedError):
            guard.invoke(
                deploy,
                "app",
                guard_ctx=GuardContext(
                    tool="deploy",
                    attributes={"resource.environment": "prod"},
                ),
            )

        # allowed
        result = guard.invoke(
            deploy,
            "app",
            guard_ctx=GuardContext(
                tool="deploy",
                attributes={"resource.environment": "staging"},
            ),
        )
        assert result == "deployed app"

    def test_invoke_approval_backend_failure_allows(self):
        class BrokenHandler:
            def submit(self, request):
                raise RuntimeError("down")

        guard = GuardianAngel(
            rules=[Rule(name="approve", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=BrokenHandler(),
            config=GuardConfig(on_approval_error=DecisionStatus.ALLOW),
        )

        def deploy(target):
            return f"deployed {target}"

        assert guard.invoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy")) == "deployed prod"

    def test_invoke_protected_tool_no_match_requires_approval(self):
        guard = GuardianAngel(
            rules=[],
            config=GuardConfig(
                protected_tools=frozenset({"delete_file"}),
                protected_no_match_decision=DecisionStatus.REQUIRE_APPROVAL,
            ),
        )

        def delete_file(path):
            return "deleted"

        with pytest.raises(ApprovalRequiredError):
            guard.invoke(delete_file, "/tmp/x", guard_ctx=GuardContext(tool="delete_file"))

    def test_invoke_request_id_is_passed(self):
        guard = _make_guard(
            Rule(
                name="block_high_risk",
                tool="github.pr",
                decision=DecisionStatus.DENY,
                attributes={"context.risk_level": "high"},
            )
        )

        def merge_pr(pr_id):
            return "merged"

        with pytest.raises(PolicyDeniedError):
            guard.invoke(
                merge_pr,
                "42",
                guard_ctx=GuardContext(
                    tool="github.pr",
                    request_id="req-42",
                    attributes={"context.risk_level": "high"},
                ),
            )


class TestAInvoke:
    @pytest.mark.asyncio
    async def test_ainvoke_allowed_sync_fn(self):
        guard = _make_guard()

        def read_file(path):
            return f"contents of {path}"

        result = await guard.ainvoke(read_file, "README.md")
        assert result == "contents of README.md"

    @pytest.mark.asyncio
    async def test_ainvoke_allowed_async_fn(self):
        guard = _make_guard()

        async def read_file(path):
            return f"contents of {path}"

        result = await guard.ainvoke(read_file, "README.md")
        assert result == "contents of README.md"

    @pytest.mark.asyncio
    async def test_ainvoke_denied(self):
        guard = _make_guard(
            Rule(name="block", tool="resource.delete", decision=DecisionStatus.DENY),
        )

        async def delete_resource(rid):
            return "deleted"

        with pytest.raises(PolicyDeniedError):
            await guard.ainvoke(
                delete_resource,
                "doc-1",
                guard_ctx=GuardContext(tool="resource.delete"),
            )
