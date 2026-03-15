"""Load policy from a YAML file and evaluate requests."""

import os

from agentguard import ActionRequest, AgentGuard

# Load policy from YAML
policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
guard = AgentGuard.from_yaml(policy_path)

# Evaluate some requests
requests = [
    ActionRequest(tool="resource.delete", attributes={"risk_level": "high"}),
    ActionRequest(tool="resource.delete", attributes={"risk_level": "low"}),
    ActionRequest(tool="resource.read"),
]

for req in requests:
    decision = guard.authorize(req)
    print(f"Tool: {req.tool:<25} Decision: {decision.status:<20} Reason: {decision.reason}")
