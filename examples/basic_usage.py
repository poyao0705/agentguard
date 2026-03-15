"""Basic usage: create rules manually, authorize a request, inspect the decision."""

from guardian_angel import (
    ALLOW,
    DENY,
    REQUIRE_APPROVAL,
    ActionRequest,
    GuardianAngel,
    Rule,
)

# Define rules in code
rules = [
    Rule(
        name="deny_prod_delete",
        tool="github.delete_branch",
        decision=DENY,
        attributes={"environment": "prod"},
    ),
    Rule(
        name="require_high_risk_merge",
        tool="github.merge_pr",
        decision=REQUIRE_APPROVAL,
        attributes={"risk_level": "high"},
    ),
]

guard = GuardianAngel(rules=rules)

# Evaluate requests
requests = [
    ActionRequest(
        tool="github.delete_branch",
        attributes={"environment": "prod"},
        agent_id="cleanup-agent",
    ),
    ActionRequest(
        tool="github.merge_pr",
        action="merge",
        attributes={"risk_level": "high"},
        agent_id="release-agent",
        identity={"user_id": "michael", "roles": ["developer"]},
    ),
    ActionRequest(
        tool="github.merge_pr",
        action="merge",
        attributes={"risk_level": "low"},
    ),
    ActionRequest(tool="slack.send_message"),
]

for req in requests:
    decision = guard.authorize(req)
    print(f"Tool: {req.tool:<25} Decision: {decision.status:<20} Reason: {decision.reason}")
