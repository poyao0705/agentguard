"""Use guard.invoke() with YAML predicates."""

import os
from datetime import datetime, timezone

from guardian_angel import (
    ApprovalRequest,
    ApprovalResponse,
    ApprovalStatus,
    DecisionStatus,
    GuardConfig,
    GuardContext,
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


def delete_resource(resource_id: str):
    return {"deleted": True, "resource_id": resource_id}


def update_resource(resource_id: str):
    return {"updated": True, "resource_id": resource_id}


# 1. Denied by a plain condition using value_from.
print("1. Cross-tenant delete (condition + value_from -> deny):")
try:
    guard.invoke(
        delete_resource,
        "doc-123",
        guard_ctx=GuardContext(
            tool="resource.delete",
            request_id="req-101",
            attributes={
                "subject.tenant_id": "acme",
                "resource.tenant_id": "globex",
                "resource.environment": "prod",
                "context.risk_level": "low",
                "subject.role": "admin",
                "agent.trust_level": "high",
            },
        ),
    )
except PolicyDeniedError as e:
    print(f"   Denied: {e}\n")

# 2. Denied by nested all/any/not logic.
print("2. Risky prod delete (all + any + not -> deny):")
try:
    guard.invoke(
        delete_resource,
        "doc-456",
        guard_ctx=GuardContext(
            tool="resource.delete",
            request_id="req-102",
            attributes={
                "subject.tenant_id": "acme",
                "resource.tenant_id": "acme",
                "resource.environment": "prod",
                "context.risk_level": "high",
                "subject.role": "developer",
                "agent.trust_level": "medium",
            },
        ),
    )
except PolicyDeniedError as e:
    print(f"   Denied: {e}\n")

# 3. Allowed because the not-clause fails.
print("3. Safe prod delete (not clause blocks the deny rule, so allow):")
result = guard.invoke(
    delete_resource,
    "doc-789",
    guard_ctx=GuardContext(
        tool="resource.delete",
        request_id="req-103",
        attributes={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "acme",
            "resource.environment": "prod",
            "context.risk_level": "low",
            "subject.role": "admin",
            "agent.trust_level": "high",
        },
    ),
)
print(f"   Result: {result}\n")

# 4. Require approval from the YAML policy — auto-approved by the handler.
print("4. Prod update requiring approval (auto-approved via handler):")
result = guard.invoke(
    update_resource,
    "doc-999",
    guard_ctx=GuardContext(
        tool="resource.update",
        request_id="req-104",
        attributes={
            "resource.environment": "prod",
            "context.change_type": "permissions",
            "context.risk_score": 5,
            "subject.role": "developer",
        },
    ),
)
print(f"   Result: {result}")
