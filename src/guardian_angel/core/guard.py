from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timezone

from .approval import ApprovalHandler, AsyncApprovalHandler, ApprovalRequest
from .decision import DecisionStatus
from .exceptions import ApprovalRequiredError, PolicyDeniedError
from .policy_engine import PolicyEngine, PolicyEvaluator
from .request import ActionRequest
from .rule import Rule
from .tool_decorator import make_tool_decorator, make_async_tool_decorator
from .yaml_loader import load_policy_file


class GuardianAngel:
    """Main entry point for the GuardianAngel SDK.

    Usage::

        guard = GuardianAngel(rules=[...])
        decision = guard.authorize(request)

    Or with a custom evaluator::

        guard = GuardianAngel(engine=MyCustomEvaluator())
        decision = guard.authorize(request)

    Or with an approval handler (sync or async)::

        guard = GuardianAngel(rules=[...], approval_handler=MyApprovalHandler())
        guard = GuardianAngel(rules=[...], approval_handler=MyAsyncApprovalHandler())
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        *,
        engine: PolicyEvaluator | None = None,
        approval_handler: ApprovalHandler | AsyncApprovalHandler | None = None,
    ):
        if engine is not None and rules is not None:
            raise ValueError("Specify either 'rules' or 'engine', not both")

        if engine is not None:
            self.engine: PolicyEvaluator = engine
        else:
            self.engine = PolicyEngine(rules or [])

        self.approval_handler = approval_handler

    @classmethod
    def from_yaml(
        cls,
        path: str,
        *,
        approval_handler: ApprovalHandler | AsyncApprovalHandler | None = None,
    ) -> GuardianAngel:
        """Create a GuardianAngel instance from a YAML policy file."""

        rules = load_policy_file(path)
        return cls(rules=rules, approval_handler=approval_handler)

    def authorize(self, request):
        """Evaluate an ActionRequest against loaded rules and return a Decision."""

        return self.engine.evaluate(request)

    def _build_approval_request(self, action_request: ActionRequest) -> ApprovalRequest:
        """Evaluate policy and build an ApprovalRequest, or raise on allow/deny/no-handler."""
        decision = self.authorize(action_request)

        if decision.status == DecisionStatus.ALLOW:
            raise ValueError(
                "Action is already allowed by policy; no approval needed."
            )

        if decision.status == DecisionStatus.DENY:
            raise PolicyDeniedError(decision)

        if self.approval_handler is None:
            raise ApprovalRequiredError(decision)

        return ApprovalRequest(
            action_request=action_request,
            decision=decision,
            requested_at=datetime.now(tz=timezone.utc),
        )

    def request_approval(self, action_request: ActionRequest):
        """Evaluate *action_request* and, if approval is required, delegate to the sync handler.

        Behavior:

        - ``REQUIRE_APPROVAL`` + sync handler → calls ``handler.submit()``, returns
          :class:`~guardian_angel.core.approval.ApprovalResponse`.
        - ``REQUIRE_APPROVAL`` + async handler → raises :class:`TypeError`
          (use :meth:`request_approval_async` instead).
        - ``REQUIRE_APPROVAL`` + no handler → raises :class:`~guardian_angel.core.exceptions.ApprovalRequiredError`.
        - ``ALLOW`` → raises :class:`ValueError` (no approval needed).
        - ``DENY`` → raises :class:`~guardian_angel.core.exceptions.PolicyDeniedError`.
        """
        approval_request = self._build_approval_request(action_request)

        if inspect.iscoroutinefunction(self.approval_handler.submit):
            raise TypeError(
                "approval_handler is async; use request_approval_async() instead"
            )

        return self.approval_handler.submit(approval_request)

    async def request_approval_async(self, action_request: ActionRequest):
        """Async version of :meth:`request_approval`.

        Works with both sync and async approval handlers. If the handler is
        synchronous, its ``submit()`` method is called directly. If async,
        it is awaited.
        """
        approval_request = self._build_approval_request(action_request)

        if inspect.iscoroutinefunction(self.approval_handler.submit):
            return await self.approval_handler.submit(approval_request)

        return self.approval_handler.submit(approval_request)

    def tool(self, name: str):
        """Decorator that wraps a sync function with policy enforcement.

        Usage::

            @guard.tool(name="resource.delete")
            def delete_resource(resource_id, *, attributes=None):
                ...
        """

        return make_tool_decorator(self, name)

    def async_tool(self, name: str):
        """Decorator that wraps an async function with policy enforcement.

        Usage::

            @guard.async_tool(name="resource.delete")
            async def delete_resource(resource_id, *, attributes=None):
                ...
        """

        return make_async_tool_decorator(self, name)