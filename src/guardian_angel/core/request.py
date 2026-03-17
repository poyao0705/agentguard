from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .exceptions import RequestValidationError


@dataclass(slots=True)
class ActionRequest:
    """Canonical input for policy evaluation.

    Keep the top-level surface intentionally small. Additional metadata should
    be stored in ``attributes`` using dotted namespaces such as
    ``subject.role`` or ``context.risk_level``.
    """

    tool: str
    attributes: dict[str, Any] = field(default_factory=dict)
    request_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tool, str) or not self.tool.strip():
            raise RequestValidationError("'tool' must be a non-empty string")
        if not isinstance(self.attributes, Mapping):
            raise RequestValidationError("'attributes' must be a mapping")
        if self.request_id is not None and not isinstance(self.request_id, str):
            raise RequestValidationError("'request_id' must be a string when provided")
        self.attributes = dict(self.attributes)

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        reject_unknown: bool = True,
    ) -> "ActionRequest":
        if not isinstance(data, Mapping):
            raise RequestValidationError("Action request payload must be a JSON object")

        allowed_fields = {"tool", "attributes", "request_id"}
        unknown_fields = sorted(set(data) - allowed_fields)
        if reject_unknown and unknown_fields:
            raise RequestValidationError(f"Unknown request field(s): {unknown_fields!r}")

        if "tool" not in data:
            raise RequestValidationError("Missing required field 'tool'")

        return cls(
            tool=data["tool"],
            attributes=data.get("attributes", {}),
            request_id=data.get("request_id"),
        )