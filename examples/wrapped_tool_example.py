"""Use the @guard.tool() decorator to enforce policy on wrapped functions."""

import os

from guardian_angel import GuardianAngel, PolicyDeniedError

# Load policy from YAML
policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
guard = GuardianAngel.from_yaml(policy_path)


@guard.tool(name="resource.delete")
def delete_resource(resource_id: str, *, attributes: dict | None = None):
    return {"deleted": True, "resource_id": resource_id}


@guard.tool(name="resource.read")
def read_resource(resource_id: str, *, attributes: dict | None = None):
    return {"resource_id": resource_id, "status": "read"}


# --- Demonstrate each outcome ---

# 1. Allowed: no matching rule
print("1. Reading a resource (should be allowed):")
result = read_resource("doc-123")
print(f"   Result: {result}\n")

# 2. Denied: matches block_sensitive_action rule
print("2. Deleting a high-risk resource (should be denied):")
try:
    delete_resource("doc-123", attributes={"risk_level": "high"})
except PolicyDeniedError as e:
    print(f"   Denied: {e}\n")

# 3. Allowed: same tool, but attributes do not match the deny rule
print("3. Deleting a low-risk resource (should be allowed):")
result = delete_resource("doc-456", attributes={"risk_level": "low"})
print(f"   Result: {result}")
