from __future__ import annotations

import aiofiles
import yaml

from .exceptions import InvalidPolicyError
from .rule import Rule

_REQUIRED_RULE_FIELDS = ("name", "tool", "decision")


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


async def load_policy_file_async(path: str) -> list[Rule]:
    """Async variant of load_policy_file using aiofiles.

    Raises InvalidPolicyError on missing/malformed content.
    """
    try:
        async with aiofiles.open(path) as f:
            content = await f.read()
    except FileNotFoundError as exc:
        raise InvalidPolicyError(f"Policy file not found: {path}") from exc

    try:
        data = yaml.safe_load(content)
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

        rules.append(
            Rule(
                name=entry["name"],
                tool=entry["tool"],
                decision=entry["decision"],
                action=entry.get("action"),
                attributes=entry.get("attributes", {}),
            )
        )

    return rules
