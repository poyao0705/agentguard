"""Complete pipeline: YAML policy load, GuardConfig, authorization, and approval."""

import os
from datetime import datetime, timezone

from guardian_angel import (
    ActionRequest,
    ApprovalRequest,
    ApprovalResponse,
    ApprovalStatus,
    DecisionStatus,
    GuardConfig,
    GuardianAngel,
    PolicyDeniedError,
)


class AuditApproveHandler:
    """Example approval backend that auto-approves and prints audit context."""

    def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        print(
            "   [approval] "
            f"tool={request.action_request.tool} "
            f"request_id={request.action_request.request_id} "
            f"approval_id={request.approval_id}"
        )
        print(
            "   [approval] "
            f"rule={request.decision.rule_name} "
            f"reason={request.decision.reason}"
        )
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.APPROVED,
            approved_by="audit-bot",
            responded_at=datetime.now(tz=timezone.utc),
        )


policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")

guard = GuardianAngel.from_yaml(
    policy_path,
    approval_handler=AuditApproveHandler(),
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
        on_approval_error=DecisionStatus.DENY,
        protected_tools=frozenset({"resource.archive"}),
        protected_no_match_decision=DecisionStatus.REQUIRE_APPROVAL,
        required_fields=("resource.environment",),
    ),
)


def print_decision(label: str, request: ActionRequest) -> None:
    decision = guard.authorize(request)
    print(label)
    print(
        "   "
        f"status={decision.status} "
        f"source={decision.source} "
        f"rule={decision.rule_name} "
        f"reason={decision.reason}"
    )
    print()


print("=== 1. Load YAML policy + GuardConfig ===\n")
print(f"policy={policy_path}")
print(
    "config="
    "default_allow + deny_on_eval_error + deny_on_approval_error + "
    "protected_resource_archive_requires_approval_on_no_match"
)
print()


print("=== 2. Authorize requests directly ===\n")

print_decision(
    "safe read request (no rule match -> default allow):",
    ActionRequest(
        tool="resource.read",
        request_id="req-pipeline-001",
        attributes={"resource.environment": "prod"},
    ),
)

print_decision(
    "protected no-match request (resource.archive -> require approval):",
    ActionRequest(
        tool="resource.archive",
        request_id="req-pipeline-002",
        attributes={"resource.environment": "prod"},
    ),
)

print_decision(
    "matched deny rule (cross-tenant delete):",
    ActionRequest(
        tool="resource.delete",
        request_id="req-pipeline-003",
        attributes={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "globex",
            "resource.environment": "prod",
        },
    ),
)


print("=== 3. Submit an approval request ===\n")

approval_request = ActionRequest(
    tool="resource.update",
    request_id="req-pipeline-004",
    attributes={
        "resource.environment": "prod",
        "context.change_type": "permissions",
        "context.risk_score": 5,
        "subject.role": "developer",
    },
)

approval_response = guard.request_approval(approval_request)
print(
    "approval result: "
    f"status={approval_response.status} "
    f"approved_by={approval_response.approved_by}"
)
print()


print("=== 4. Use the same guard in a tool wrapper ===\n")


@guard.tool(name="resource.update")
def update_resource(resource_id: str, *, __guard_attributes__=None, __guard_request_id__=None):
    return {
        "updated": True,
        "resource_id": resource_id,
        "request_id": __guard_request_id__,
        "attributes": __guard_attributes__ or {},
    }


tool_result = update_resource(
    "doc-777",
    __guard_request_id__="req-pipeline-005",
    __guard_attributes__={
        "resource.environment": "prod",
        "context.change_type": "schema",
        "context.risk_score": 8,
        "subject.role": "developer",
    },
)
print(f"decorated tool result: {tool_result}")
print()


print("=== 5. Denial still blocks execution ===\n")


@guard.tool(name="resource.delete")
def delete_resource(resource_id: str, *, __guard_attributes__=None, __guard_request_id__=None):
    _ = (__guard_attributes__, __guard_request_id__)
    return {"deleted": True, "resource_id": resource_id}


try:
    delete_resource(
        "doc-888",
        __guard_request_id__="req-pipeline-006",
        __guard_attributes__={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "globex",
            "resource.environment": "prod",
        },
    )
except PolicyDeniedError as exc:
    print(f"blocked delete: {exc}")