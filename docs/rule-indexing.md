# Rule Indexing Strategy

`PolicyEngine` now builds an internal `rules_by_tool` index keyed by exact tool name.

Current semantics:

- candidate selection starts with exact tool lookup
- rule order is preserved within each tool bucket
- precedence remains first-match-wins

This reduces per-request work without changing the external `Rule` model.

Future extensions can add separate prefix or wildcard buckets while keeping precedence explicit.