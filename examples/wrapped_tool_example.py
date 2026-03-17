"""Use the @guard.tool() decorator with YAML predicates."""

import os
from datetime import datetime, timezone

from guardian_angel import (
    ApprovalRequest,
    ApprovalResponse,
    ApprovalStatus,
    DecisionStatus,
    GuardConfig,
    GuardianAngel,
    PolicyDeniedError,
)


# A simple handler that auto-approves every request.
class AutoApproveHandler:
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


# Load policy from YAML — with an approval handler so require_approval
# decisions are routed through it instead of raising ApprovalRequiredError.
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


@guard.tool(name="resource.delete")
def delete_resource(
    resource_id: str,
    *,
    __guard_attributes__: dict | None = None,
    __guard_request_id__: str | None = None,
):
    return {
        "deleted": True,
        "resource_id": resource_id,
        "request_id": __guard_request_id__,
        "attributes": __guard_attributes__ or {},
    }


@guard.tool(name="resource.update")
def update_resource(
    resource_id: str,
    *,
    __guard_attributes__: dict | None = None,
    __guard_request_id__: str | None = None,
):
    return {
        "updated": True,
        "resource_id": resource_id,
        "request_id": __guard_request_id__,
        "attributes": __guard_attributes__ or {},
    }


# 1. Denied by a plain condition using value_from.
print("1. Cross-tenant delete (condition + value_from -> deny):")
try:
    delete_resource(
        "doc-123",
        __guard_request_id__="req-101",
        __guard_attributes__={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "globex",
            "resource.environment": "prod",
            "context.risk_level": "low",
            "subject.role": "admin",
            "agent.trust_level": "high",
        },
    )
except PolicyDeniedError as e:
    print(f"   Denied: {e}\n")

# 2. Denied by nested all/any/not logic.
print("2. Risky prod delete (all + any + not -> deny):")
try:
    delete_resource(
        "doc-456",
        __guard_request_id__="req-102",
        __guard_attributes__={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "acme",
            "resource.environment": "prod",
            "context.risk_level": "high",
            "subject.role": "developer",
            "agent.trust_level": "medium",
        },
    )
except PolicyDeniedError as e:
    print(f"   Denied: {e}\n")

# 3. Allowed because the not-clause fails.
print("3. Safe prod delete (not clause blocks the deny rule, so allow):")
result = delete_resource(
    "doc-789",
    __guard_request_id__="req-103",
    __guard_attributes__={
        "subject.tenant_id": "acme",
        "resource.tenant_id": "acme",
        "resource.environment": "prod",
        "context.risk_level": "low",
        "subject.role": "admin",
        "agent.trust_level": "high",
    },
)
print(f"   Result: {result}\n")

# 4. Require approval from the YAML policy — auto-approved by the handler.
print("4. Prod update requiring approval (auto-approved via handler):")
result = update_resource(
    "doc-999",
    __guard_request_id__="req-104",
    __guard_attributes__={
        "resource.environment": "prod",
        "context.change_type": "permissions",
        "context.risk_score": 5,
        "subject.role": "developer",
    },
)
print(f"   Result: {result}")
