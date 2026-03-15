# GuardianAngel

**A lightweight Python SDK for governing AI agent tool execution.**

GuardianAngel intercepts agent actions, evaluates policy, and decides whether they should be **allowed**, **denied**, or **require approval** — before the tool runs.

## Why

Autonomous AI agents can call tools — merge PRs, delete branches, send messages, deploy services. GuardianAngel gives you deterministic, policy-based control over what agents are allowed to do.

## Install

```bash
pip install guardian-angel
```

## Quickstart

```python
from guardian_angel import GuardianAngel, ActionRequest, Rule, DENY

guard = GuardianAngel(rules=[
  Rule(
    name="block_sensitive_action",
    tool="resource.delete",
    decision=DENY,
    attributes={"risk_level": "high"},
  ),
])

decision = guard.authorize(
  ActionRequest(
    tool="resource.delete",
    attributes={"risk_level": "high"},
  )
)

print(decision.status)
# deny
```

## YAML Policy

Define rules in a YAML file:

```yaml
# policy.yaml
rules:
  - name: block_sensitive_action
    tool: resource.delete
    attributes:
      risk_level: high
    decision: deny
```

Load and evaluate:

```python
from guardian_angel import GuardianAngel, ActionRequest

guard = GuardianAngel.from_yaml("policy.yaml")
decision = guard.authorize(
  ActionRequest(tool="resource.delete", attributes={"risk_level": "high"})
)
print(decision.status)  # "deny"
```

## Tool Decorator

Wrap Python functions to enforce policy automatically:

```python
guard = GuardianAngel.from_yaml("policy.yaml")

@guard.tool(name="resource.delete")
def delete_resource(resource_id: str, *, attributes: dict | None = None):
  return {"deleted": True, "resource_id": resource_id}

# This raises PolicyDeniedError if policy blocks it.
# Otherwise the function executes normally.
delete_resource("doc-123", attributes={"risk_level": "high"})
```

## How It Works

```
Agent tool call
      ↓
ActionRequest
      ↓
GuardianAngel.authorize(request)
      ↓
Decision (allow / deny / require_approval)
```

Rules are evaluated **top to bottom, first match wins**. If no rule matches, the default decision is **allow**.

## Roadmap

- **v0.1** — Local policy evaluation, YAML rules, decorator *(current)*
- **v0.2** — Richer identity / resource models, better validation
- **v0.3** — `guardian-angel simulate` CLI, policy testing
- **v0.4** — Lightweight framework adapters (LangGraph, OpenAI, CrewAI)
- **v0.5+** — Remote policy sources, audit sinks, approval stores

## License

MIT
