from __future__ import annotations

import yaml

from .decision import ALLOW, DENY, REQUIRE_APPROVAL
from .exceptions import InvalidPolicyError
from .rule import Rule

_REQUIRED_RULE_FIELDS = ("name", "tool", "decision")
_VALID_DECISIONS = {ALLOW, DENY, REQUIRE_APPROVAL}


def load_policy_file(path: str) -> list[Rule]:
    """Load a YAML policy file and return a list of Rule objects.

    Raises InvalidPolicyError on missing/malformed content.
    """
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except FileNotFoundError as exc:
        raise InvalidPolicyError(f"Policy file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise InvalidPolicyError(f"Malformed YAML in {path}: {exc}") from exc

    return _parse_rules(data, path)


def _parse_rules(data, path: str) -> list[Rule]:
    """Validate parsed YAML data and convert to Rule objects."""

    if not isinstance(data, dict) or "rules" not in data:
        raise InvalidPolicyError("Policy file must contain a top-level 'rules' key")

    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        raise InvalidPolicyError("'rules' must be a list")

    return _build_rules(raw_rules)


def _build_rules(raw_rules: list) -> list[Rule]:
    rules: list[Rule] = []
    for i, entry in enumerate(raw_rules):
        if not isinstance(entry, dict):
            raise InvalidPolicyError(f"Rule at index {i} must be a mapping")

        for field in _REQUIRED_RULE_FIELDS:
            if field not in entry:
                raise InvalidPolicyError(
                    f"Rule at index {i} is missing required field '{field}'"
                )

        name = entry["name"]
        tool = entry["tool"]
        decision = entry["decision"]
        action = entry.get("action")
        attributes = entry.get("attributes", {})

        if not isinstance(name, str) or not name.strip():
            raise InvalidPolicyError(
                f"Rule at index {i}: 'name' must be a non-empty string"
            )
        if not isinstance(tool, str) or not tool.strip():
            raise InvalidPolicyError(
                f"Rule at index {i}: 'tool' must be a non-empty string"
            )
        if decision not in _VALID_DECISIONS:
            raise InvalidPolicyError(
                f"Rule at index {i}: 'decision' must be one of "
                f"{sorted(_VALID_DECISIONS)!r}, got {decision!r}"
            )
        if action is not None and not isinstance(action, str):
            raise InvalidPolicyError(
                f"Rule at index {i}: 'action' must be a string"
            )
        if not isinstance(attributes, dict):
            raise InvalidPolicyError(
                f"Rule at index {i}: 'attributes' must be a mapping"
            )

        rules.append(
            Rule(
                name=name,
                tool=tool,
                decision=decision,
                action=action,
                attributes=attributes,
            )
        )

    return rules
