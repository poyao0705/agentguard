from __future__ import annotations

import threading
from datetime import datetime, timezone

import pytest

from guardian_angel import (
    ActionRequest,
    ApprovalHandler,
    ApprovalRequest,
    ApprovalRequiredError,
    ApprovalResponse,
    ApprovalStatus,
    AsyncApprovalHandler,
    DecisionSource,
    DecisionStatus,
    GuardConfig,
    GuardianAngel,
    PolicyDeniedError,
    Rule,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_approval_rules():
    return [Rule(name="approve_deploy", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)]


class _AsyncAutoApproveHandler:
    """Async handler that always approves."""

    async def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.APPROVED,
            approved_by="async-auto",
            responded_at=datetime.now(tz=timezone.utc),
        )


class _AsyncRejectHandler:
    """Async handler that always rejects."""

    async def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.REJECTED,
            approved_by="async-auto",
            reason="rejected by async policy",
            responded_at=datetime.now(tz=timezone.utc),
        )


class _SyncAutoApproveHandler:
    """Sync handler that always approves."""

    def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.APPROVED,
            approved_by="sync-auto",
            responded_at=datetime.now(tz=timezone.utc),
        )


class _BrokenAsyncHandler:
    async def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        raise RuntimeError("approval api failed")


# ---------------------------------------------------------------------------
# AsyncApprovalHandler protocol
# ---------------------------------------------------------------------------


class TestAsyncApprovalHandlerProtocol:
    def test_async_class_satisfies_protocol(self):
        assert isinstance(_AsyncAutoApproveHandler(), AsyncApprovalHandler)

    def test_sync_class_satisfies_sync_protocol(self):
        assert isinstance(_SyncAutoApproveHandler(), ApprovalHandler)

    def test_runtime_distinction_via_inspect(self):
        """Protocol can't distinguish sync/async at runtime; inspect does."""
        import inspect

        assert inspect.iscoroutinefunction(_AsyncAutoApproveHandler().submit)
        assert not inspect.iscoroutinefunction(_SyncAutoApproveHandler().submit)


# ---------------------------------------------------------------------------
# request_approval_async()
# ---------------------------------------------------------------------------


class TestRequestApprovalAsync:
    @pytest.mark.asyncio
    async def test_async_handler_approved(self):
        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=_AsyncAutoApproveHandler(),
        )
        response = await guard.request_approval_async(ActionRequest(tool="deploy"))
        assert response.status == ApprovalStatus.APPROVED
        assert response.approved_by == "async-auto"

    @pytest.mark.asyncio
    async def test_async_handler_rejected(self):
        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=_AsyncRejectHandler(),
        )
        response = await guard.request_approval_async(ActionRequest(tool="deploy"))
        assert response.status == ApprovalStatus.REJECTED

    @pytest.mark.asyncio
    async def test_sync_handler_works_via_async_method(self):
        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=_SyncAutoApproveHandler(),
        )
        response = await guard.request_approval_async(ActionRequest(tool="deploy"))
        assert response.status == ApprovalStatus.APPROVED
        assert response.approved_by == "sync-auto"

    @pytest.mark.asyncio
    async def test_sync_handler_runs_in_worker_thread(self):
        main_thread_id = threading.get_ident()
        seen_thread_ids = []

        class CapturingSyncHandler:
            def submit(self, request: ApprovalRequest) -> ApprovalResponse:
                seen_thread_ids.append(threading.get_ident())
                return ApprovalResponse(
                    approval_id=request.approval_id,
                    status=ApprovalStatus.APPROVED,
                )

        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=CapturingSyncHandler(),
        )
        await guard.request_approval_async(ActionRequest(tool="deploy"))
        assert seen_thread_ids
        assert seen_thread_ids[0] != main_thread_id

    @pytest.mark.asyncio
    async def test_no_handler_raises_approval_required_error(self):
        guard = GuardianAngel(rules=_require_approval_rules())
        with pytest.raises(ApprovalRequiredError):
            await guard.request_approval_async(ActionRequest(tool="deploy"))

    @pytest.mark.asyncio
    async def test_allow_raises_value_error(self):
        guard = GuardianAngel(rules=[])
        with pytest.raises(ValueError, match="already allowed"):
            await guard.request_approval_async(ActionRequest(tool="anything"))

    @pytest.mark.asyncio
    async def test_deny_raises_policy_denied_error(self):
        guard = GuardianAngel(
            rules=[Rule(name="r", tool="nuke", decision=DecisionStatus.DENY)]
        )
        with pytest.raises(PolicyDeniedError):
            await guard.request_approval_async(ActionRequest(tool="nuke"))

    @pytest.mark.asyncio
    async def test_approval_id_propagated(self):
        captured = []

        class CapturingAsyncHandler:
            async def submit(self, request: ApprovalRequest) -> ApprovalResponse:
                captured.append(request)
                return ApprovalResponse(
                    approval_id=request.approval_id,
                    status=ApprovalStatus.APPROVED,
                )

        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=CapturingAsyncHandler(),
        )
        await guard.request_approval_async(
            ActionRequest(tool="deploy", request_id="req-async-1")
        )
        assert captured[0].approval_id
        assert captured[0].action_request.request_id == "req-async-1"

    @pytest.mark.asyncio
    async def test_approval_backend_failure_defaults_to_deny(self):
        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=_BrokenAsyncHandler(),
        )
        with pytest.raises(PolicyDeniedError) as exc_info:
            await guard.request_approval_async(ActionRequest(tool="deploy"))
        assert exc_info.value.decision.source == DecisionSource.APPROVAL_ERROR

    @pytest.mark.asyncio
    async def test_approval_backend_failure_can_fallback_to_require_approval(self):
        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=_BrokenAsyncHandler(),
            config=GuardConfig(on_approval_error=DecisionStatus.REQUIRE_APPROVAL),
        )
        with pytest.raises(ApprovalRequiredError):
            await guard.request_approval_async(ActionRequest(tool="deploy"))


# ---------------------------------------------------------------------------
# Sync request_approval() rejects async handler
# ---------------------------------------------------------------------------


class TestSyncRejectsAsyncHandler:
    def test_sync_method_raises_type_error_for_async_handler(self):
        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=_AsyncAutoApproveHandler(),
        )
        with pytest.raises(TypeError, match="async"):
            guard.request_approval(ActionRequest(tool="deploy"))


# ---------------------------------------------------------------------------
# @guard.async_tool() decorator
# ---------------------------------------------------------------------------


class TestAsyncToolDecorator:
    @pytest.mark.asyncio
    async def test_async_handler_approved_executes_function(self):
        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=_AsyncAutoApproveHandler(),
        )

        @guard.async_tool(name="deploy")
        async def deploy(target):
            return f"deployed {target}"

        result = await deploy("prod")
        assert result == "deployed prod"

    @pytest.mark.asyncio
    async def test_async_handler_rejected_raises(self):
        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=_AsyncRejectHandler(),
        )

        @guard.async_tool(name="deploy")
        async def deploy(target):
            return f"deployed {target}"

        with pytest.raises(PolicyDeniedError):
            await deploy("prod")

    @pytest.mark.asyncio
    async def test_sync_handler_works_via_async_tool(self):
        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=_SyncAutoApproveHandler(),
        )

        @guard.async_tool(name="deploy")
        async def deploy(target):
            return f"deployed {target}"

        result = await deploy("prod")
        assert result == "deployed prod"

    @pytest.mark.asyncio
    async def test_no_handler_raises_approval_required_error(self):
        guard = GuardianAngel(rules=_require_approval_rules())

        @guard.async_tool(name="deploy")
        async def deploy(target):
            return f"deployed {target}"

        with pytest.raises(ApprovalRequiredError):
            await deploy("prod")

    @pytest.mark.asyncio
    async def test_denied_tool_raises(self):
        guard = GuardianAngel(
            rules=[Rule(name="block", tool="delete", decision=DecisionStatus.DENY)]
        )

        @guard.async_tool(name="delete")
        async def delete_resource(resource_id):
            return f"deleted {resource_id}"

        with pytest.raises(PolicyDeniedError):
            await delete_resource("res-1")

    @pytest.mark.asyncio
    async def test_allowed_tool_executes(self):
        guard = GuardianAngel(rules=[])

        @guard.async_tool(name="read")
        async def read_resource(resource_id):
            return f"read {resource_id}"

        result = await read_resource("res-1")
        assert result == "read res-1"

    @pytest.mark.asyncio
    async def test_handler_receives_correct_request_id(self):
        captured = []

        class CapturingAsyncHandler:
            async def submit(self, request: ApprovalRequest) -> ApprovalResponse:
                captured.append(request)
                return ApprovalResponse(
                    approval_id=request.approval_id,
                    status=ApprovalStatus.APPROVED,
                )

        guard = GuardianAngel(
            rules=_require_approval_rules(),
            approval_handler=CapturingAsyncHandler(),
        )

        @guard.async_tool(name="deploy")
        async def deploy(target, *, __guard_request_id__=None):
            return f"deployed {target} {__guard_request_id__}"

        await deploy("prod", __guard_request_id__="async-tool-req-1")
        assert captured[0].approval_id
        assert captured[0].action_request.request_id == "async-tool-req-1"
        assert captured[0].action_request.tool == "deploy"

    @pytest.mark.asyncio
    async def test_decorator_preserves_function_name(self):
        guard = GuardianAngel(rules=[])

        @guard.async_tool(name="my_tool")
        async def my_special_function():
            """My docstring."""
            return True

        assert my_special_function.__name__ == "my_special_function"
        assert my_special_function.__doc__ == "My docstring."
