"""Load a YAML policy with an explicit safety posture."""

import os

from guardian_angel import ActionRequest, DecisionStatus, GuardConfig, GuardianAngel

# Load policy from YAML
policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
guard = GuardianAngel.from_yaml(
    policy_path,
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
        protected_tools=frozenset({"resource.archive"}),
        protected_no_match_decision=DecisionStatus.REQUIRE_APPROVAL,
    ),
)

# Evaluate some requests
requests = [
    ActionRequest(
        tool="resource.delete",
        request_id="req-201",
        attributes={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "globex",
            "resource.environment": "prod",
            "context.risk_level": "low",
            "subject.role": "admin",
            "agent.trust_level": "high",
        },
    ),
    ActionRequest(
        tool="resource.delete",
        request_id="req-202",
        attributes={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "acme",
            "resource.environment": "prod",
            "context.risk_level": "high",
            "subject.role": "developer",
            "agent.trust_level": "medium",
        },
    ),
    ActionRequest(
        tool="resource.update",
        request_id="req-203",
        attributes={
            "resource.environment": "prod",
            "context.change_type": "permissions",
            "context.risk_score": 5,
            "subject.role": "developer",
        },
    ),
    ActionRequest(
        tool="resource.delete",
        request_id="req-204",
        attributes={
            "subject.tenant_id": "acme",
            "resource.tenant_id": "acme",
            "resource.environment": "prod",
            "context.risk_level": "low",
            "subject.role": "admin",
            "agent.trust_level": "high",
        },
    ),
    ActionRequest(
        tool="resource.archive",
        request_id="req-205",
        attributes={
            "resource.environment": "prod",
        },
    ),
]

for req in requests:
    decision = guard.authorize(req)
    print(
        f"{req.request_id}: tool={req.tool:<18} status={decision.status:<17} "
        f"source={decision.source:<18} rule={decision.rule_name}"
    )
