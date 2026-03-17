# Guardian Angel Hardening Semantics

Guardian Angel now distinguishes three cases that previously collapsed into simple happy-path behavior:

- no matching rule
- policy evaluation error
- approval backend failure

These outcomes map through `GuardConfig`:

- `default_decision`
- `on_evaluation_error`
- `on_approval_error`

The resulting `Decision` also records `source`, so callers can tell whether a denial came from a matched rule, a no-match default, an evaluation error, or an approval backend failure.

Missing-field behavior:

- `exists` is true only when a key is present.
- `not_exists` is true only when a key is absent.
- Other operators return false when either side is missing.
- Type mismatches become `EvaluationError` and then map through `on_evaluation_error`.

Approval behavior:

- async code runs sync approval handlers through `asyncio.to_thread(...)`
- backend exceptions map through `on_approval_error`
- protected tools can use a different no-match posture than the global default