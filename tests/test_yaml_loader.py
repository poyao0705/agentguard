import os
import tempfile

import pytest

from agentguard import AgentGuard, InvalidPolicyError, Rule
from agentguard.yaml_loader import load_policy_file, load_policy_file_async


def _write_yaml(content: str) -> str:
    """Write content to a temp YAML file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.write(fd, content.encode())
    os.close(fd)
    return path


class TestLoadPolicyFile:
    def test_valid_yaml_loads_rules(self):
        path = _write_yaml("""
rules:
  - name: deny_prod_delete
    tool: github.delete_branch
    attributes:
      environment: prod
    decision: deny
  - name: require_merge_approval
    tool: github.merge_pr
    action: merge
    attributes:
      risk_level: high
    decision: require_approval
""")
        try:
            rules = load_policy_file(path)
            assert len(rules) == 2

            assert isinstance(rules[0], Rule)
            assert rules[0].name == "deny_prod_delete"
            assert rules[0].tool == "github.delete_branch"
            assert rules[0].decision == "deny"
            assert rules[0].attributes == {"environment": "prod"}
            assert rules[0].action is None

            assert rules[1].name == "require_merge_approval"
            assert rules[1].action == "merge"
            assert rules[1].attributes == {"risk_level": "high"}
        finally:
            os.unlink(path)

    def test_minimal_rule(self):
        path = _write_yaml("""
rules:
  - name: block_all_deploys
    tool: deploy
    decision: deny
""")
        try:
            rules = load_policy_file(path)
            assert len(rules) == 1
            assert rules[0].attributes == {}
            assert rules[0].action is None
        finally:
            os.unlink(path)

    def test_missing_rules_key_raises(self):
        path = _write_yaml("policies:\n  - name: x\n")
        try:
            with pytest.raises(InvalidPolicyError, match="top-level 'rules' key"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_missing_name_field_raises(self):
        path = _write_yaml("""
rules:
  - tool: deploy
    decision: deny
""")
        try:
            with pytest.raises(InvalidPolicyError, match="missing required field 'name'"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_missing_tool_field_raises(self):
        path = _write_yaml("""
rules:
  - name: block
    decision: deny
""")
        try:
            with pytest.raises(InvalidPolicyError, match="missing required field 'tool'"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_missing_decision_field_raises(self):
        path = _write_yaml("""
rules:
  - name: block
    tool: deploy
""")
        try:
            with pytest.raises(InvalidPolicyError, match="missing required field 'decision'"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_malformed_yaml_raises(self):
        path = _write_yaml("{{invalid yaml: [")
        try:
            with pytest.raises(InvalidPolicyError, match="Malformed YAML"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_file_not_found_raises(self):
        with pytest.raises(InvalidPolicyError, match="Policy file not found"):
            load_policy_file("/nonexistent/path/policy.yaml")

    def test_rules_not_a_list_raises(self):
        path = _write_yaml("rules: not_a_list\n")
        try:
            with pytest.raises(InvalidPolicyError, match="'rules' must be a list"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_rule_entry_not_a_dict_raises(self):
        path = _write_yaml("rules:\n  - just_a_string\n")
        try:
            with pytest.raises(InvalidPolicyError, match="must be a mapping"):
                load_policy_file(path)
        finally:
            os.unlink(path)


class TestLoadPolicyFileAsync:
    @pytest.mark.asyncio
    async def test_valid_yaml_loads_rules(self):
        path = _write_yaml("""
rules:
  - name: deny_prod_delete
    tool: github.delete_branch
    attributes:
      environment: prod
    decision: deny
  - name: require_merge_approval
    tool: github.merge_pr
    action: merge
    decision: require_approval
""")
        try:
            rules = await load_policy_file_async(path)
            assert len(rules) == 2
            assert rules[0].name == "deny_prod_delete"
            assert rules[1].action == "merge"
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_file_not_found_raises(self):
        with pytest.raises(InvalidPolicyError, match="Policy file not found"):
            await load_policy_file_async("/nonexistent/path/policy.yaml")

    @pytest.mark.asyncio
    async def test_malformed_yaml_raises(self):
        path = _write_yaml("{{invalid yaml: [")
        try:
            with pytest.raises(InvalidPolicyError, match="Malformed YAML"):
                await load_policy_file_async(path)
        finally:
            os.unlink(path)

    @pytest.mark.asyncio
    async def test_missing_rules_key_raises(self):
        path = _write_yaml("policies:\n  - name: x\n")
        try:
            with pytest.raises(InvalidPolicyError, match="top-level 'rules' key"):
                await load_policy_file_async(path)
        finally:
            os.unlink(path)


class TestFromYamlAsync:
    @pytest.mark.asyncio
    async def test_from_yaml_async_loads(self):
        path = _write_yaml("""
rules:
  - name: block
    tool: deploy
    decision: deny
""")
        try:
            guard = await AgentGuard.from_yaml_async(path)
            from agentguard import ActionRequest, DENY

            decision = guard.authorize(ActionRequest(tool="deploy"))
            assert decision.status == DENY
        finally:
            os.unlink(path)
