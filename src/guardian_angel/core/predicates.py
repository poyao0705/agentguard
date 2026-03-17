from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

Operator = Literal[
    "eq",
    "ne",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "not_exists",
]

ALLOWED_OPERATORS: tuple[Operator, ...] = (
    "eq",
    "ne",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "not_exists",
)


@dataclass(frozen=True, slots=True)
class Condition:
    """A single key/op/value comparison."""

    key: str
    op: Operator
    value: Any = None
    value_from: str | None = None


@dataclass(frozen=True, slots=True)
class AllOf:
    """Matches only when every child predicate matches."""

    items: tuple["Predicate", ...]


@dataclass(frozen=True, slots=True)
class AnyOf:
    """Matches when at least one child predicate matches."""

    items: tuple["Predicate", ...]


@dataclass(frozen=True, slots=True)
class Not:
    """Matches when the child predicate does not match."""

    item: "Predicate"


Predicate: TypeAlias = Condition | AllOf | AnyOf | Not