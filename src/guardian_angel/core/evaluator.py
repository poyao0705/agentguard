from __future__ import annotations

import operator
from typing import Any

from .exceptions import EvaluationError
from .predicates import AllOf, AnyOf, Condition, Not, Predicate
from .request import ActionRequest

MISSING = object()


def _in_operator(actual: Any, expected: Any) -> bool:
    return actual in expected


def _not_in_operator(actual: Any, expected: Any) -> bool:
    return actual not in expected


def _contains_operator(actual: Any, expected: Any) -> bool:
    return expected in actual


def _not_contains_operator(actual: Any, expected: Any) -> bool:
    return expected not in actual

_CONDITION_OPERATORS = {
    "eq": operator.eq,
    "ne": operator.ne,
    "in": _in_operator,
    "not_in": _not_in_operator,
    "contains": _contains_operator,
    "not_contains": _not_contains_operator,
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
    "exists": lambda actual, _expected: actual is not MISSING,
    "not_exists": lambda actual, _expected: actual is MISSING,
}


def resolve_key(request: ActionRequest, key: str) -> Any:
    """Read a value from the request by key.

    The reserved keys ``tool`` and ``request_id`` map to the corresponding
    top-level fields; everything else is looked up in ``attributes``.
    """

    if key == "tool":
        return request.tool
    if key == "request_id":
        return request.request_id
    return request.attributes.get(key, MISSING)


def evaluate_condition(request: ActionRequest, condition: Condition) -> bool:
    """Apply a single condition's operator against resolved request values."""

    operator_fn = _CONDITION_OPERATORS.get(condition.op)
    if operator_fn is None:
        raise EvaluationError(f"Unsupported operator: {condition.op}")

    actual = resolve_key(request, condition.key)
    expected = None

    if condition.op not in {"exists", "not_exists"}:
        expected = (
            resolve_key(request, condition.value_from)
            if condition.value_from is not None
            else condition.value
        )
        if actual is MISSING or expected is MISSING:
            return False

    try:
        return operator_fn(actual, expected)
    except (TypeError, ValueError) as exc:
        raise EvaluationError(
            f"Condition {condition.key!r} with operator {condition.op!r} failed: {exc}"
        ) from exc


def evaluate_predicate(request: ActionRequest, predicate: Predicate) -> bool:
    """Recursively evaluate a predicate tree against the request."""

    if isinstance(predicate, Condition):
        return evaluate_condition(request, predicate)
    if isinstance(predicate, AllOf):
        return all(evaluate_predicate(request, item) for item in predicate.items)
    if isinstance(predicate, AnyOf):
        return any(evaluate_predicate(request, item) for item in predicate.items)
    if isinstance(predicate, Not):
        return not evaluate_predicate(request, predicate.item)

    raise EvaluationError(f"Unsupported predicate type: {type(predicate)!r}")