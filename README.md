# Guardian Angel

**A lightweight Python SDK for governing AI agent tool execution.**

Guardian Angel intercepts agent actions, evaluates policy, and returns **allow**, **deny**, or **require_approval** — before the tool runs.

## Install

```bash
pip install guardian-angel

# optional CLI
pip install guardian-angel[cli]
```

## Quickstart

```yaml
# policy.yaml
rules:
  - name: block_risky_delete
    tool: resource.delete
    decision: deny
    all:
      - key: resource.environment
        op: eq
        value: prod
      - key: context.risk_level
        op: eq
        value: high
```

```python
from guardian_angel import ActionRequest, DecisionStatus, GuardConfig, GuardianAngel

guard = GuardianAngel.from_yaml(
    "policy.yaml",
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
        on_approval_error=DecisionStatus.DENY,
    ),
)

decision = guard.authorize(
    ActionRequest(
        tool="resource.delete",
        attributes={
            "resource.environment": "prod",
            "context.risk_level": "high",
        },
    )
)
print(decision.status)  # "deny"
```

First matching rule wins. No match uses `default_decision`, which defaults to **allow**.

## CLI

```bash
guardian-angel evaluate policy.yaml request.json
guardian-angel evaluate policy.yaml request.json --explain
guardian-angel --verbose evaluate policy.yaml request.json
guardian-angel --version
```

`--explain` prints the matched rule and reason. `--verbose` adds input context.

## Features

- **Predicate rules** — `when`, `all`, `any`, `not` with operators (`eq`, `ne`, `in`, `not_in`, `contains`, `gt`, `gte`, `lt`, `lte`, …)
- **Explicit failure semantics** — configurable default/no-match behavior, evaluation-error behavior, approval-error behavior, protected tools, and required request fields
- **Cross-field comparison** — `value_from` to compare one attribute against another
- **Approval workflow** — pluggable `ApprovalHandler` and `AsyncApprovalHandler` protocols for human-in-the-loop approval (Slack, email, GitHub issues, etc.)
- **Tool invocation** — `guard.invoke()` (sync) and `guard.ainvoke()` (async) for policy enforcement on any function without decorators
- **YAML or Python** — define rules in files or construct `Rule` objects in code
- **CLI** — evaluate policies from the command line with colored output

See [`examples/`](examples/) for more.
If you want one end-to-end reference that wires everything together, start with [`examples/complete_pipeline_example.py`](examples/complete_pipeline_example.py).

## How It Works

```
Agent tool call → ActionRequest → GuardianAngel.authorize() → Decision
                                                                 ├─ allow → execute
                                                                 ├─ deny  → block
                                                                 └─ require_approval → ApprovalHandler
```

## Safety Modes

Guardian Angel now separates:

- no rule matched
- policy evaluation failed
- approval backend failed

```python
from guardian_angel import DecisionStatus, GuardConfig, GuardianAngel

# Global allow, but protected tools require approval when no rule matches.
guard = GuardianAngel(
    rules=rules,
    config=GuardConfig(
        default_decision=DecisionStatus.ALLOW,
        on_evaluation_error=DecisionStatus.DENY,
        on_approval_error=DecisionStatus.DENY,
        protected_tool_prefixes=("github.", "filesystem."),
        protected_no_match_decision=DecisionStatus.REQUIRE_APPROVAL,
    ),
)

# Full fail-closed mode.
fail_closed_guard = GuardianAngel(
    rules=rules,
    config=GuardConfig(default_decision=DecisionStatus.DENY),
)

# Approval-fallback mode.
approval_fallback_guard = GuardianAngel(
    rules=rules,
    config=GuardConfig(on_approval_error=DecisionStatus.REQUIRE_APPROVAL),
)
```

## Operator Semantics

- Missing keys do not match ordinary comparisons such as `eq`, `gt`, `in`, or `contains`.
- Use `exists` and `not_exists` when presence itself matters.
- Type mismatches are converted into deterministic evaluation errors.
- Critical request fields can be required globally with `GuardConfig(required_fields=(...))`.

## Approval Workflow

When a rule returns `require_approval`, Guardian Angel can delegate to a pluggable approval backend. Both synchronous and asynchronous handlers are supported.

### Sync handler

Any class with a `submit(request: ApprovalRequest) -> ApprovalResponse` method satisfies the `ApprovalHandler` protocol:

```python
from guardian_angel import (
    ApprovalHandler, ApprovalRequest, ApprovalResponse, ApprovalStatus,
)

class SlackApprovalHandler:
    def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        # send a Slack message, wait for reaction, return outcome
        ...
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.APPROVED,  # or REJECTED / EXPIRED
            approved_by="alice",
        )
```

### Async handler

For non-blocking I/O, implement `AsyncApprovalHandler` with an `async def submit()`:

```python
from guardian_angel import (
    AsyncApprovalHandler, ApprovalRequest, ApprovalResponse, ApprovalStatus,
)

class AsyncSlackApprovalHandler:
    async def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        # await Slack API call, return outcome
        ...
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.APPROVED,
            approved_by="alice",
        )
```

### Wiring it up

Pass either handler type when creating a `GuardianAngel` instance:

```python
# sync
guard = GuardianAngel(rules=rules, approval_handler=SlackApprovalHandler())

# async
guard = GuardianAngel(rules=rules, approval_handler=AsyncSlackApprovalHandler())

# from YAML (works with either)
guard = GuardianAngel.from_yaml("policy.yaml", approval_handler=handler)
```

### Using `request_approval()` / `request_approval_async()`

```python
from guardian_angel import ActionRequest

# Sync — requires a sync handler
response = guard.request_approval(
    ActionRequest(tool="resource.update", request_id="req-1", attributes={...})
)

# Async — works with both sync and async handlers
response = await guard.request_approval_async(
    ActionRequest(tool="resource.update", request_id="req-1", attributes={...})
)

print(response.approval_id)
print(response.status)  # "approved", "rejected", or "expired"
```

`ActionRequest.request_id` identifies the original tool call. `ApprovalRequest.approval_id` and `ApprovalResponse.approval_id` identify the approval workflow instance. Guardian Angel generates `approval_id` by default, but handlers or advanced integrations can override it when constructing an `ApprovalRequest` manually.

Behavior:
- **require_approval + sync handler** → `request_approval()` calls `handler.submit()`, returns `ApprovalResponse`
- **require_approval + async handler** → `request_approval_async()` awaits `handler.submit()`, returns `ApprovalResponse`
- **require_approval + async handler + sync call** → `request_approval()` raises `TypeError` (use the async variant)
- **require_approval + no handler** → raises `ApprovalRequiredError`
- **allow** → raises `ValueError` (no approval needed)
- **deny** → raises `PolicyDeniedError`
- **approval backend failure** → maps through `on_approval_error`; async code runs sync handlers in `asyncio.to_thread(...)`

### With `guard.invoke()` / `guard.ainvoke()`

`invoke` and `ainvoke` call any function under policy enforcement without decorating it.
Policy context is passed via `guard_ctx`; the function itself stays completely clean:

```python
from guardian_angel import GuardContext

def update_resource(resource_id):
    return {"updated": True, "resource_id": resource_id}

# Sync
result = guard.invoke(
    update_resource,
    "doc-1",
    guard_ctx=GuardContext(
        tool="resource.update",
        attributes={"resource.environment": "prod", "subject.role": "developer"},
        request_id="req-1",
    ),
)

# Async — works with both sync and async functions
async def update_resource_async(resource_id):
    return {"updated": True, "resource_id": resource_id}

result = await guard.ainvoke(
    update_resource_async,
    "doc-1",
    guard_ctx=GuardContext(
        tool="resource.update",
        attributes={"resource.environment": "prod"},
    ),
)
```

If `guard_ctx.tool` is not set, the function's `__name__` is used as the policy tool name.

Without a handler, `ApprovalRequiredError` is raised as before.

See [`examples/approval_example.py`](examples/approval_example.py) (sync) and [`examples/async_approval_example.py`](examples/async_approval_example.py) (async) for full working examples.

## CLI Validation

The CLI now validates request payloads before evaluation.

- Exit code `2`: invalid request input
- Exit code `3`: invalid policy input

## Roadmap

- **v0.1** — Local policy evaluation, YAML rules, decorator
- **v0.2** — Stronger validation, policy linting
- **v0.3** — CLI with `evaluate`, `--explain`, `--verbose`
- **v0.4** — Approval workflow with pluggable handlers *(current)*
- **v0.5** — Framework adapters (LangGraph, OpenAI, CrewAI)

## License

MIT
