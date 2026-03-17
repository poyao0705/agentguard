"""Async approval workflow: use an async handler with asyncio."""

import asyncio
import os
from datetime import datetime, timezone

from guardian_angel import (
    ActionRequest,
    ApprovalRequest,
    ApprovalRequiredError,
    ApprovalResponse,
    ApprovalStatus,
    GuardianAngel,
    PolicyDeniedError,
)


# ---------------------------------------------------------------------------
# 1. Define async approval handlers
# ---------------------------------------------------------------------------


class AsyncAutoApproveHandler:
    """Async handler that always approves — simulates an async API call."""

    async def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        # Simulate async I/O (e.g. calling Slack API, querying a database)
        await asyncio.sleep(0.01)
        print(
            f"   [async-approve] approval_id={request.approval_id} "
            f"action_request_id={request.action_request.request_id}"
        )
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.APPROVED,
            approved_by="async-bot",
            responded_at=datetime.now(tz=timezone.utc),
        )


class AsyncRejectHandler:
    """Async handler that always rejects."""

    async def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        await asyncio.sleep(0.01)
        print(
            f"   [async-reject] approval_id={request.approval_id} "
            f"action_request_id={request.action_request.request_id}"
        )
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.REJECTED,
            approved_by="async-bot",
            reason="rejected by async policy",
            responded_at=datetime.now(tz=timezone.utc),
        )


# ---------------------------------------------------------------------------
# 2. Load policy & create guard with an async handler
# ---------------------------------------------------------------------------

policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
guard = GuardianAngel.from_yaml(policy_path, approval_handler=AsyncAutoApproveHandler())
guard_reject = GuardianAngel.from_yaml(policy_path, approval_handler=AsyncRejectHandler())


# ---------------------------------------------------------------------------
# 3. Async examples
# ---------------------------------------------------------------------------


async def main():
    print("=== request_approval_async() examples ===\n")

    # 1. Async approved
    print("1. Require-approval request (async auto-approved):")
    response = await guard.request_approval_async(
        ActionRequest(
            tool="resource.update",
            request_id="req-async-1",
            attributes={
                "resource.environment": "prod",
                "context.change_type": "permissions",
                "context.risk_score": 5,
                "subject.role": "developer",
            },
        )
    )
    print(
        f"   approval_id={response.approval_id} "
        f"status={response.status} approved_by={response.approved_by}\n"
    )

    # 2. Async rejected
    print("2. Require-approval request (async rejected):")
    response = await guard_reject.request_approval_async(
        ActionRequest(
            tool="resource.update",
            request_id="req-async-2",
            attributes={
                "resource.environment": "prod",
                "context.change_type": "schema",
                "context.risk_score": 9,
                "subject.role": "developer",
            },
        )
    )
    print(f"   status={response.status} reason={response.reason}\n")

    # 3. Denied request still raises synchronously
    print("3. Denied request (raises PolicyDeniedError):")
    try:
        await guard.request_approval_async(
            ActionRequest(
                tool="resource.delete",
                request_id="req-async-3",
                attributes={
                    "subject.tenant_id": "acme",
                    "resource.tenant_id": "globex",
                },
            )
        )
    except PolicyDeniedError as e:
        print(f"   PolicyDeniedError: {e}\n")

    # ---------------------------------------------------------------------------
    # 4. @guard.async_tool() decorator
    # ---------------------------------------------------------------------------

    print("=== @guard.async_tool() examples ===\n")

    @guard.async_tool(name="resource.update")
    async def update_resource(resource_id, *, attributes=None, request_id=None):
        # Simulate async work
        await asyncio.sleep(0.01)
        return {"updated": True, "resource_id": resource_id}

    @guard_reject.async_tool(name="resource.update")
    async def update_resource_strict(resource_id, *, attributes=None, request_id=None):
        await asyncio.sleep(0.01)
        return {"updated": True, "resource_id": resource_id}

    approval_attrs = {
        "resource.environment": "prod",
        "context.change_type": "schema",
        "context.risk_score": 8,
        "subject.role": "developer",
    }

    print("4. Async auto-approved → function executes:")
    result = await update_resource("doc-1", request_id="req-async-4", attributes=approval_attrs)
    print(f"   Result: {result}\n")

    print("5. Async rejected → PolicyDeniedError:")
    try:
        await update_resource_strict("doc-2", request_id="req-async-5", attributes=approval_attrs)
    except PolicyDeniedError as e:
        print(f"   PolicyDeniedError: {e}\n")

    # ---------------------------------------------------------------------------
    # 5. No handler → ApprovalRequiredError (same as sync)
    # ---------------------------------------------------------------------------

    print("=== No handler (raises ApprovalRequiredError) ===\n")

    guard_no_handler = GuardianAngel.from_yaml(policy_path)

    @guard_no_handler.async_tool(name="resource.update")
    async def update_no_handler(resource_id, *, attributes=None, request_id=None):
        await asyncio.sleep(0.01)
        return {"updated": True, "resource_id": resource_id}

    print("6. No handler registered:")
    try:
        await update_no_handler("doc-3", request_id="req-async-6", attributes=approval_attrs)
    except ApprovalRequiredError as e:
        print(f"   ApprovalRequiredError: {e}\n")


if __name__ == "__main__":
    asyncio.run(main())
