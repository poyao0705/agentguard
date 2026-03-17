"""Basic usage: build rules in code with predicates and explicit safety posture."""

from guardian_angel import (
    ActionRequest,
    DecisionStatus,
    GuardConfig,
    GuardianAngel,
    Rule,
)
from guardian_angel.core.rule import AllOf, AnyOf, Condition, Not

rules = [
    Rule(
        name="deny_cross_tenant_delete",
        tool="resource.delete",
        decision=DecisionStatus.DENY,
        when=Condition(
            key="subject.tenant_id",
            op="ne",
            value_from="resource.tenant_id",
        ),
    ),
    Rule(
        name="deny_risky_prod_delete",
        tool="resource.delete",
        decision=DecisionStatus.DENY,
        when=AllOf(
            items=(
                Condition(key="resource.environment", op="eq", value="prod"),
                AnyOf(
                    items=(
                        Condition(key="context.risk_level", op="eq", value="high"),
                        Condition(key="subject.role", op="ne", value="admin"),
                    )
                ),
                Not(
                    item=Condition(key="agent.trust_level", op="eq", value="high")
                ),
            )
        ),
    ),
    Rule(
        name="require_prod_update_approval",
        tool="resource.update",
        decision=DecisionStatus.REQUIRE_APPROVAL,
        when=AllOf(
            items=(
                Condition(key="resource.environment", op="eq", value="prod"),
                AnyOf(
                    items=(
                        Condition(
                            key="context.change_type",
                            op="in",
                            value=["schema", "permissions"],
                        ),
                        Condition(key="context.risk_score", op="gte", value=7),
                    )
                ),
                Not(item=Condition(key="subject.role", op="eq", value="sre")),
            )
        ),
    ),
]

guard = GuardianAngel(
    rules=rules,
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
        protected_tools=frozenset({"resource.archive"}),
        protected_no_match_decision=DecisionStatus.REQUIRE_APPROVAL,
    ),
)

requests = [
    ActionRequest(
        tool="resource.delete",
        request_id="req-001",
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
        request_id="req-002",
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
        tool="resource.delete",
        request_id="req-003",
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
        tool="resource.update",
        request_id="req-004",
        attributes={
            "resource.environment": "prod",
            "context.change_type": "permissions",
            "context.risk_score": 5,
            "subject.role": "developer",
        },
    ),
    ActionRequest(
        tool="resource.update",
        request_id="req-005",
        attributes={
            "resource.environment": "prod",
            "context.change_type": "metadata",
            "context.risk_score": 2,
            "subject.role": "sre",
        },
    ),
    ActionRequest(
        tool="resource.archive",
        request_id="req-006",
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
