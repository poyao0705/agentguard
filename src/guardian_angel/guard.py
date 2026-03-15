from __future__ import annotations

from .policy_engine import PolicyEngine
from .rule import Rule
from .tool_decorator import make_tool_decorator


class GuardianAngel:
    """Main entry point for the GuardianAngel SDK.

    Usage::

        guard = GuardianAngel(rules=[...])
        decision = guard.authorize(request)
    """

    def __init__(self, rules: list[Rule] | None = None):
        self.engine = PolicyEngine(rules or [])

    @classmethod
    def from_yaml(cls, path: str) -> GuardianAngel:
        """Create a GuardianAngel instance from a YAML policy file."""
        from .yaml_loader import load_policy_file

        rules = load_policy_file(path)
        return cls(rules=rules)

    def authorize(self, request):
        """Evaluate an ActionRequest against loaded rules and return a Decision."""
        return self.engine.evaluate(request)

    def tool(self, name: str, action: str | None = None):
        """Decorator that wraps a function with policy enforcement.

        Usage::

            @guard.tool(name="github.merge_pr", action="merge")
            def merge_pr(pr_id, *, attributes=None):
                ...
        """
        return make_tool_decorator(self, name, action)