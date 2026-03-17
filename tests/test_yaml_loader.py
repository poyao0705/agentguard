import os
import tempfile

import pytest

from guardian_angel import InvalidPolicyError, Rule
from guardian_angel.core.rule import AllOf, AnyOf, Condition, Not
from guardian_angel.core.yaml_loader import load_policy_file


def _write_yaml(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.write(fd, content.encode())
    os.close(fd)
    return path


class TestLoadPolicyFile:
    def test_valid_yaml_loads_rules(self):
        path = _write_yaml(
            """
rules:
  - name: deny_prod_delete
    tool: github.delete_branch
    attributes:
      resource.environment: prod
    decision: deny
  - name: require_high_risk_merge
    tool: github.merge_pr
    attributes:
      context.risk_level: high
    decision: require_approval
"""
        )
        try:
            rules = load_policy_file(path)
            assert len(rules) == 2
            assert isinstance(rules[0], Rule)
            assert rules[0].name == "deny_prod_delete"
            assert rules[1].name == "require_high_risk_merge"
        finally:
            os.unlink(path)

    def test_minimal_rule(self):
        path = _write_yaml(
            """
rules:
  - name: block_all_deploys
    tool: deploy
    decision: deny
"""
        )
        try:
            rules = load_policy_file(path)
            assert len(rules) == 1
            assert rules[0].attributes == {}
        finally:
            os.unlink(path)

    def test_when_condition_loads_predicate(self):
        path = _write_yaml(
            """
rules:
  - name: block_prod_delete
    tool: resource.delete
    decision: deny
    when:
      key: resource.environment
      op: eq
      value: prod
"""
        )
        try:
            rules = load_policy_file(path)
            assert isinstance(rules[0].when, Condition)
            assert rules[0].when.key == "resource.environment"
            assert rules[0].when.op == "eq"
            assert rules[0].when.value == "prod"
        finally:
            os.unlink(path)

    def test_all_any_not_load_nested_predicates(self):
        path = _write_yaml(
            """
rules:
  - name: review_prod_release
    tool: deploy
    decision: require_approval
    all:
      - key: resource.environment
        op: eq
        value: prod
      - any:
          - key: context.risk_level
            op: eq
            value: high
          - key: subject.role
            op: ne
            value: admin
      - not:
          key: agent.trust_level
          op: eq
          value: high
"""
        )
        try:
            rules = load_policy_file(path)
            assert isinstance(rules[0].when, AllOf)
            all_of = rules[0].when
            assert isinstance(all_of.items[0], Condition)
            assert isinstance(all_of.items[1], AnyOf)
            assert isinstance(all_of.items[2], Not)
        finally:
            os.unlink(path)

    def test_condition_with_value_from_loads(self):
        path = _write_yaml(
            """
rules:
  - name: require_tenant_match
    tool: resource.read
    decision: deny
    when:
      key: subject.tenant_id
      op: ne
      value_from: resource.tenant_id
"""
        )
        try:
            rules = load_policy_file(path)
            assert isinstance(rules[0].when, Condition)
            assert rules[0].when.value_from == "resource.tenant_id"
            assert rules[0].when.value is None
        finally:
            os.unlink(path)

    def test_exists_condition_loads(self):
        path = _write_yaml(
            """
rules:
  - name: require_subject
    tool: resource.read
    decision: deny
    when:
      key: subject.id
      op: exists
"""
        )
        try:
            rules = load_policy_file(path)
            assert rules[0].when.op == "exists"
        finally:
            os.unlink(path)

    def test_missing_rules_key_raises(self):
        path = _write_yaml("policies:\n  - name: x\n")
        try:
            with pytest.raises(InvalidPolicyError, match="top-level 'rules' key"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_multiple_predicate_fields_raise(self):
        path = _write_yaml(
            """
rules:
  - name: bad
    tool: deploy
    decision: deny
    when:
      key: resource.environment
      op: eq
      value: prod
    any:
      - key: subject.role
        op: eq
        value: developer
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match="only one predicate field"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_condition_requires_exactly_one_value_source(self):
        path = _write_yaml(
            """
rules:
  - name: bad
    tool: deploy
    decision: deny
    when:
      key: resource.environment
      op: eq
      value: prod
      value_from: context.target_environment
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match="exactly one of 'value' or 'value_from'"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_missing_name_field_raises(self):
        path = _write_yaml(
            """
rules:
  - tool: deploy
    decision: deny
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match="missing required field 'name'"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_missing_tool_field_raises(self):
        path = _write_yaml(
            """
rules:
  - name: block
    decision: deny
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match="missing required field 'tool'"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_missing_decision_field_raises(self):
        path = _write_yaml(
            """
rules:
  - name: block
    tool: deploy
"""
        )
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

    def test_invalid_decision_value_raises(self):
        path = _write_yaml(
            """
rules:
  - name: bad
    tool: deploy
    decision: maybe
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match="'decision' must be one of"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_attributes_not_a_mapping_raises(self):
        path = _write_yaml(
            """
rules:
  - name: bad
    tool: deploy
    decision: deny
    attributes: just_a_string
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match="'attributes' must be a mapping"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_empty_name_raises(self):
        path = _write_yaml(
            """
rules:
  - name: ""
    tool: deploy
    decision: deny
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match="'name' must be a non-empty string"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_unsupported_action_field_raises(self):
        path = _write_yaml(
            """
rules:
  - name: bad
    tool: deploy
    action: merge
    decision: deny
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match=r"unsupported field\(s\)"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_unknown_rule_field_raises(self):
        path = _write_yaml(
            """
rules:
  - name: bad
    tool: deploy
    decision: deny
    subject:
      role: developer
"""
        )
        try:
            with pytest.raises(
                InvalidPolicyError,
                match="Use namespaced keys under 'attributes'",
            ):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_invalid_operator_rejected(self):
        path = _write_yaml(
            """
rules:
  - name: bad
    tool: deploy
    decision: deny
    when:
      key: subject.role
      op: maybe
      value: admin
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match="unsupported operator"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_exists_rejects_value(self):
        path = _write_yaml(
            """
rules:
  - name: bad
    tool: deploy
    decision: deny
    when:
      key: subject.role
      op: exists
      value: admin
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match="does not accept 'value'"):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_logical_predicate_cannot_mix_condition_fields(self):
        path = _write_yaml(
            """
rules:
  - name: bad
    tool: deploy
    decision: deny
    when:
      all:
        - key: subject.role
          op: eq
          value: admin
      key: resource.environment
"""
        )
        try:
            with pytest.raises(InvalidPolicyError, match="cannot be combined"):
                load_policy_file(path)
        finally:
            os.unlink(path)

