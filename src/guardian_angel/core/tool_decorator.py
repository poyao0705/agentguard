from __future__ import annotations

import functools
import inspect
from datetime import datetime, timezone

from .approval import ApprovalRequest, ApprovalStatus
from .decision import Decision, DecisionStatus
from .exceptions import ApprovalRequiredError, PolicyDeniedError
from .request import ActionRequest


def _build_request_and_evaluate(guard, name, kwargs):
    """Shared logic: build an ActionRequest, evaluate policy, return (decision, request)."""
    attributes = kwargs.get("attributes") or {}
    request_id = kwargs.get("request_id")

    request = ActionRequest(
        tool=name,
        attributes=attributes,
        request_id=request_id,
    )

    decision = guard.authorize(request)
    return decision, request


def _handle_approval_sync(guard, decision, request):
    """Handle the require_approval path synchronously. Returns an ApprovalResponse or raises."""
    if guard.approval_handler is None:
        raise ApprovalRequiredError(decision)

    if inspect.iscoroutinefunction(guard.approval_handler.submit):
        raise TypeError(
            "approval_handler is async; use @guard.async_tool() instead"
        )

    approval_request = ApprovalRequest(
        action_request=request,
        decision=decision,
        requested_at=datetime.now(tz=timezone.utc),
    )
    return guard.submit_approval_sync(approval_request)


async def _handle_approval_async(guard, decision, request):
    """Handle the require_approval path asynchronously. Works with sync or async handlers."""
    if guard.approval_handler is None:
        raise ApprovalRequiredError(decision)

    approval_request = ApprovalRequest(
        action_request=request,
        decision=decision,
        requested_at=datetime.now(tz=timezone.utc),
    )

    return await guard.submit_approval_async(approval_request)


def make_tool_decorator(guard, name: str):
    """Return a decorator that enforces policy on the wrapped sync function."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            decision, request = _build_request_and_evaluate(guard, name, kwargs)

            if decision.status == DecisionStatus.DENY:
                raise PolicyDeniedError(decision)
            if decision.status == DecisionStatus.REQUIRE_APPROVAL:
                response = _handle_approval_sync(guard, decision, request)
                if isinstance(response, Decision):
                    if response.status == DecisionStatus.ALLOW:
                        return func(*args, **kwargs)
                    if response.status == DecisionStatus.REQUIRE_APPROVAL:
                        raise ApprovalRequiredError(response)
                    raise PolicyDeniedError(response)
                if response.status == ApprovalStatus.APPROVED:
                    return func(*args, **kwargs)
                raise PolicyDeniedError(guard.decision_for_approval_response(decision, response))

            return func(*args, **kwargs)

        return wrapper

    return decorator


def make_async_tool_decorator(guard, name: str):
    """Return a decorator that enforces policy on the wrapped async function."""

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            decision, request = _build_request_and_evaluate(guard, name, kwargs)

            if decision.status == DecisionStatus.DENY:
                raise PolicyDeniedError(decision)
            if decision.status == DecisionStatus.REQUIRE_APPROVAL:
                response = await _handle_approval_async(guard, decision, request)
                if isinstance(response, Decision):
                    if response.status == DecisionStatus.ALLOW:
                        return await func(*args, **kwargs)
                    if response.status == DecisionStatus.REQUIRE_APPROVAL:
                        raise ApprovalRequiredError(response)
                    raise PolicyDeniedError(response)
                if response.status == ApprovalStatus.APPROVED:
                    return await func(*args, **kwargs)
                raise PolicyDeniedError(guard.decision_for_approval_response(decision, response))

            return await func(*args, **kwargs)

        return wrapper

    return decorator