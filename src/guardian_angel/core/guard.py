from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timezone
from typing import cast

from .approval import (
    ApprovalHandler,
    ApprovalRequest,
    ApprovalResponse,
    ApprovalStatus,
    AsyncApprovalHandler,
)
from .config import GuardConfig
from .decision import Decision, DecisionSource, DecisionStatus
from .exceptions import ApprovalBackendError, ApprovalRequiredError, PolicyDeniedError
from .policy_engine import PolicyEngine, PolicyEvaluator
from .request import ActionRequest, GuardContext
from .rule import Rule
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
        config: GuardConfig | None = None,
    ):
        if engine is not None and rules is not None:
            raise ValueError("Specify either 'rules' or 'engine', not both")

        self.config = config or GuardConfig()

        if engine is not None:
            self.engine: PolicyEvaluator = engine
        else:
            self.engine = PolicyEngine(rules or [], config=self.config)

        self.approval_handler = approval_handler

    @classmethod
    def from_yaml(
        cls,
        path: str,
        *,
        approval_handler: ApprovalHandler | AsyncApprovalHandler | None = None,
        config: GuardConfig | None = None,
    ) -> GuardianAngel:
        """Create a GuardianAngel instance from a YAML policy file."""

        rules = load_policy_file(path)
        return cls(rules=rules, approval_handler=approval_handler, config=config)

    def authorize(self, request):
        """Evaluate an ActionRequest against loaded rules and return a Decision."""

        return self.engine.evaluate(request)

    def _decision_for_approval_error(self, error: Exception) -> Decision:
        return Decision(
            status=self.config.on_approval_error,
            reason=f"Approval backend failure: {error}",
            source=DecisionSource.APPROVAL_ERROR,
            error=str(error),
        )

    @staticmethod
    def decision_for_approval_response(
        base_decision: Decision,
        response: ApprovalResponse,
    ) -> Decision:
        if response.status == ApprovalStatus.APPROVED:
            return Decision(
                status=DecisionStatus.ALLOW,
                reason="Approval granted",
                rule_name=base_decision.rule_name,
                source=base_decision.source,
            )

        return Decision(
            status=DecisionStatus.DENY,
            reason=response.reason or f"Approval {response.status.value}",
            rule_name=base_decision.rule_name,
            source=base_decision.source,
        )

    def _raise_for_decision(self, decision: Decision) -> None:
        if decision.status == DecisionStatus.DENY:
            raise PolicyDeniedError(decision)
        if decision.status == DecisionStatus.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(decision)

    def _build_fallback_approval_response(
        self,
        approval_request: ApprovalRequest,
        decision: Decision,
    ) -> ApprovalResponse:
        if decision.status != DecisionStatus.ALLOW:
            raise ApprovalBackendError(
                decision,
                RuntimeError(decision.error or decision.reason or "approval backend failure"),
            )

        return ApprovalResponse(
            approval_id=approval_request.approval_id,
            status=ApprovalStatus.APPROVED,
            approved_by="guardian_angel_fallback",
            reason=decision.reason,
            responded_at=datetime.now(tz=timezone.utc),
        )

    def submit_approval_sync(
        self,
        approval_request: ApprovalRequest,
    ) -> ApprovalResponse | Decision:
        handler = self.approval_handler
        assert handler is not None
        try:
            if inspect.iscoroutinefunction(handler.submit):
                raise TypeError(
                    "approval_handler is async; use request_approval_async() instead"
                )
            return cast(ApprovalHandler, handler).submit(approval_request)
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
            return self._decision_for_approval_error(exc)

    async def submit_approval_async(
        self,
        approval_request: ApprovalRequest,
    ) -> ApprovalResponse | Decision:
        handler = self.approval_handler
        assert handler is not None
        try:
            if inspect.iscoroutinefunction(handler.submit):
                return await cast(AsyncApprovalHandler, handler).submit(approval_request)
            sync_handler = cast(ApprovalHandler, handler)
            return await asyncio.to_thread(sync_handler.submit, approval_request)
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
            return self._decision_for_approval_error(exc)

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
        handler = self.approval_handler
        assert handler is not None

        if inspect.iscoroutinefunction(handler.submit):
            raise TypeError(
                "approval_handler is async; use request_approval_async() instead"
            )

        result = self.submit_approval_sync(approval_request)
        if isinstance(result, Decision):
            self._raise_for_decision(result)
            return self._build_fallback_approval_response(approval_request, result)
        return result

    async def request_approval_async(self, action_request: ActionRequest):
        """Async version of :meth:`request_approval`.

        Works with both sync and async approval handlers. If the handler is
        synchronous, its ``submit()`` method is called directly. If async,
        it is awaited.
        """
        approval_request = self._build_approval_request(action_request)

        result = await self.submit_approval_async(approval_request)
        if isinstance(result, Decision):
            self._raise_for_decision(result)
            return self._build_fallback_approval_response(approval_request, result)
        return result

    # ------------------------------------------------------------------
    # invoke / ainvoke – call any function under policy
    # ------------------------------------------------------------------

    def _submit_approval_for_invoke(
        self, decision: Decision, request: ActionRequest,
    ) -> ApprovalResponse | Decision:
        """Handle the require_approval path synchronously."""
        if self.approval_handler is None:
            raise ApprovalRequiredError(decision)

        if inspect.iscoroutinefunction(self.approval_handler.submit):
            raise TypeError(
                "approval_handler is async; use ainvoke() instead"
            )

        approval_request = ApprovalRequest(
            action_request=request,
            decision=decision,
            requested_at=datetime.now(tz=timezone.utc),
        )
        return self.submit_approval_sync(approval_request)

    async def _submit_approval_for_ainvoke(
        self, decision: Decision, request: ActionRequest,
    ) -> ApprovalResponse | Decision:
        """Handle the require_approval path asynchronously."""
        if self.approval_handler is None:
            raise ApprovalRequiredError(decision)

        approval_request = ApprovalRequest(
            action_request=request,
            decision=decision,
            requested_at=datetime.now(tz=timezone.utc),
        )
        return await self.submit_approval_async(approval_request)

    def _resolve_tool_name(self, fn, guard_ctx: GuardContext | None) -> str:
        if guard_ctx is not None and guard_ctx.tool is not None:
            return guard_ctx.tool
        return getattr(fn, "__name__", str(fn))

    def _build_invoke_request(
        self, fn, guard_ctx: GuardContext | None,
    ) -> ActionRequest:
        name = self._resolve_tool_name(fn, guard_ctx)
        return ActionRequest(
            tool=name,
            attributes=guard_ctx.attributes if guard_ctx else {},
            request_id=guard_ctx.request_id if guard_ctx else None,
        )

    def invoke(self, fn, /, *args, guard_ctx: GuardContext | None = None, **kwargs):
        """Call *fn* under policy enforcement without decorating it.

        Usage::

            result = guard.invoke(
                update_resource,
                "doc-777",
                guard_ctx=GuardContext(
                    tool="resource.update",
                    attributes={"resource.environment": "prod"},
                ),
            )

        The *guard_ctx* is **not** forwarded to *fn*; the function receives
        only ``*args`` and ``**kwargs``.
        """
        request = self._build_invoke_request(fn, guard_ctx)
        decision = self.authorize(request)

        if decision.status == DecisionStatus.DENY:
            raise PolicyDeniedError(decision)

        if decision.status == DecisionStatus.REQUIRE_APPROVAL:
            response = self._submit_approval_for_invoke(decision, request)
            if isinstance(response, Decision):
                if response.status == DecisionStatus.ALLOW:
                    return fn(*args, **kwargs)
                if response.status == DecisionStatus.REQUIRE_APPROVAL:
                    raise ApprovalRequiredError(response)
                raise PolicyDeniedError(response)
            if response.status == ApprovalStatus.APPROVED:
                return fn(*args, **kwargs)
            raise PolicyDeniedError(
                self.decision_for_approval_response(decision, response)
            )

        return fn(*args, **kwargs)

    async def ainvoke(
        self, fn, /, *args, guard_ctx: GuardContext | None = None, **kwargs,
    ):
        """Async version of :meth:`invoke`.

        If *fn* is a coroutine function it is awaited; otherwise it is called
        synchronously.
        """
        request = self._build_invoke_request(fn, guard_ctx)
        decision = self.authorize(request)

        if decision.status == DecisionStatus.DENY:
            raise PolicyDeniedError(decision)

        if decision.status == DecisionStatus.REQUIRE_APPROVAL:
            response = await self._submit_approval_for_ainvoke(decision, request)
            if isinstance(response, Decision):
                if response.status == DecisionStatus.ALLOW:
                    if inspect.iscoroutinefunction(fn):
                        return await fn(*args, **kwargs)
                    return fn(*args, **kwargs)
                if response.status == DecisionStatus.REQUIRE_APPROVAL:
                    raise ApprovalRequiredError(response)
                raise PolicyDeniedError(response)
            if response.status == ApprovalStatus.APPROVED:
                if inspect.iscoroutinefunction(fn):
                    return await fn(*args, **kwargs)
                return fn(*args, **kwargs)
            raise PolicyDeniedError(
                self.decision_for_approval_response(decision, response)
            )

        if inspect.iscoroutinefunction(fn):
            return await fn(*args, **kwargs)
        return fn(*args, **kwargs)