"""Approval workflow: plug in a custom handler for human-in-the-loop approval."""

import os
from datetime import datetime, timezone

from guardian_angel import (
    ActionRequest,
    ApprovalRequest,
    ApprovalRequiredError,
    ApprovalResponse,
    ApprovalStatus,
    DecisionStatus,
    GuardConfig,
    GuardianAngel,
    PolicyDeniedError,
)


# ---------------------------------------------------------------------------
# 1. Define a custom ApprovalHandler
# ---------------------------------------------------------------------------
# Any class with a `submit(ApprovalRequest) -> ApprovalResponse` method works.
# In production this could call Slack, send an email, or insert a database row.


class ConsoleApprovalHandler:
    """Asks for approval on the terminal (stdin)."""

    def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        print(f"   [approval] tool={request.action_request.tool}")
        print(f"   [approval] approval_id={request.approval_id}")
        print(f"   [approval] action_request_id={request.action_request.request_id}")
        print(f"   [approval] rule={request.decision.rule_name}")
        print(f"   [approval] reason={request.decision.reason}")
        answer = input("   Approve? (y/n): ").strip().lower()
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.APPROVED if answer == "y" else ApprovalStatus.REJECTED,
            approved_by="console-user",
            responded_at=datetime.now(tz=timezone.utc),
        )


class AutoApproveHandler:
    """Always approves — useful for testing."""

    def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        print(
            f"   [auto-approve] approval_id={request.approval_id} "
            f"action_request_id={request.action_request.request_id}"
        )
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.APPROVED,
            approved_by="auto",
            responded_at=datetime.now(tz=timezone.utc),
        )


class AutoRejectHandler:
    """Always rejects — useful for testing."""

    def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        print(
            f"   [auto-reject] approval_id={request.approval_id} "
            f"action_request_id={request.action_request.request_id}"
        )
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.REJECTED,
            approved_by="auto",
            reason="rejected by policy",
            responded_at=datetime.now(tz=timezone.utc),
        )


# ---------------------------------------------------------------------------
# 2. Load policy & create guard with a handler
# ---------------------------------------------------------------------------

policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
guard = GuardianAngel.from_yaml(
    policy_path,
    approval_handler=AutoApproveHandler(),
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
        on_approval_error=DecisionStatus.DENY,
    ),
)


# ---------------------------------------------------------------------------
# 3. Using request_approval() directly
# ---------------------------------------------------------------------------

print("=== request_approval() examples ===\n")

# This request triggers "require_prod_update_approval" in policy.yaml.
req = ActionRequest(
    tool="resource.update",
    request_id="req-301",
    attributes={
        "resource.environment": "prod",
        "context.change_type": "permissions",
        "context.risk_score": 5,
        "subject.role": "developer",
    },
)

print("1. Require-approval request (auto-approved):")
response = guard.request_approval(req)
print(
    f"   approval_id={response.approval_id} "
    f"status={response.status} approved_by={response.approved_by}\n"
)

# Denied requests raise PolicyDeniedError.
print("2. Denied request:")
try:
    guard.request_approval(
        ActionRequest(
            tool="resource.delete",
            request_id="req-302",
            attributes={
                "subject.tenant_id": "acme",
                "resource.tenant_id": "globex",
            },
        )
    )
except PolicyDeniedError as e:
    print(f"   PolicyDeniedError: {e}\n")

# Allowed requests raise ValueError (no approval needed).
print("3. Already-allowed request:")
try:
    guard.request_approval(
        ActionRequest(tool="resource.read", request_id="req-303")
    )
except ValueError as e:
    print(f"   ValueError: {e}\n")

# ---------------------------------------------------------------------------
# 4. Using the @guard.tool() decorator with approval
# ---------------------------------------------------------------------------

print("=== @guard.tool() with approval ===\n")

# Switch to a reject handler to show the denied path.
guard_reject = GuardianAngel.from_yaml(
    policy_path,
    approval_handler=AutoRejectHandler(),
    config=GuardConfig(on_approval_error=DecisionStatus.DENY),
)


@guard.tool(name="resource.update")
def update_resource(resource_id, *, attributes=None, request_id=None):
    return {
        "updated": True,
        "resource_id": resource_id,
        "request_id": request_id,
        "attributes": attributes or {},
    }


@guard_reject.tool(name="resource.update")
def update_resource_strict(resource_id, *, attributes=None, request_id=None):
    return {
        "updated": True,
        "resource_id": resource_id,
        "request_id": request_id,
        "attributes": attributes or {},
    }


approval_attrs = {
    "resource.environment": "prod",
    "context.change_type": "schema",
    "context.risk_score": 8,
    "subject.role": "developer",
}

print("4. Auto-approved → function executes:")
result = update_resource("doc-1", request_id="req-304", attributes=approval_attrs)
print(f"   Result: {result}\n")

print("5. Auto-rejected → PolicyDeniedError:")
try:
    update_resource_strict("doc-2", request_id="req-305", attributes=approval_attrs)
except PolicyDeniedError as e:
    print(f"   PolicyDeniedError: {e}\n")

# ---------------------------------------------------------------------------
# 5. No handler → ApprovalRequiredError (original behaviour)
# ---------------------------------------------------------------------------

print("=== No handler (raises ApprovalRequiredError) ===\n")

guard_no_handler = GuardianAngel.from_yaml(
    policy_path,
    config=GuardConfig(on_evaluation_error=DecisionStatus.DENY),
)


@guard_no_handler.tool(name="resource.update")
def update_no_handler(resource_id, *, attributes=None, request_id=None):
    return {
        "updated": True,
        "resource_id": resource_id,
        "request_id": request_id,
        "attributes": attributes or {},
    }


print("6. No handler registered:")
try:
    update_no_handler("doc-3", request_id="req-306", attributes=approval_attrs)
except ApprovalRequiredError as e:
    print(f"   ApprovalRequiredError: {e}\n")
