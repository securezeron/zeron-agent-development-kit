"""
Tests for the PolicyEngine (in-process, pure Python).
"""

import pytest
import yaml

from zak.core.dsl.schema import AgentDSL
from zak.core.policy.engine import PolicyEngine


VALID_YAML = """
agent:
  id: test-policy-agent
  name: "Policy Test Agent"
  domain: risk_quant
  version: "1.0.0"

intent:
  goal: "Test policy"

reasoning:
  mode: deterministic
  autonomy_level: bounded

boundaries:
  risk_budget: medium
  allowed_actions:
    - read_asset
    - compute_risk
    - write_risk_node
  denied_actions:
    - delete_asset

safety:
  sandbox_profile: standard
  audit_level: standard
"""

OBSERVE_YAML = """
agent:
  id: observe-agent
  name: "Observe Agent"
  domain: compliance
  version: "1.0.0"

intent:
  goal: "Observe only"

reasoning:
  mode: rule_based
  autonomy_level: observe

boundaries:
  risk_budget: low

safety:
  sandbox_profile: strict
  audit_level: verbose
"""


def load(yaml_str: str) -> AgentDSL:
    return AgentDSL.model_validate(yaml.safe_load(yaml_str))


class TestPolicyEngine:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_allowed_action_is_permitted(self):
        dsl = load(VALID_YAML)
        decision = self.engine.evaluate(dsl, action="read_asset")
        assert decision.allowed is True

    def test_denied_action_is_blocked(self):
        dsl = load(VALID_YAML)
        decision = self.engine.evaluate(dsl, action="delete_asset")
        assert decision.allowed is False
        assert "explicitly denied" in decision.reason

    def test_action_not_in_allowlist_is_blocked(self):
        dsl = load(VALID_YAML)
        decision = self.engine.evaluate(dsl, action="execute_exploit")
        assert decision.allowed is False
        assert "allow-list" in decision.reason

    def test_observe_agent_cannot_write(self):
        dsl = load(OBSERVE_YAML)
        decision = self.engine.evaluate(dsl, action="write_finding")
        assert decision.allowed is False
        assert "observe" in decision.reason

    def test_observe_agent_can_read(self):
        dsl = load(OBSERVE_YAML)
        decision = self.engine.evaluate(dsl, action="read_asset")
        assert decision.allowed is True

    def test_environment_out_of_scope_is_blocked(self):
        # Use a fixture that explicitly scopes to production+staging only
        scoped_yaml = """
agent:
  id: scoped-agent
  name: Scoped Agent
  domain: risk_quant
  version: "1.0.0"
intent:
  goal: test
reasoning:
  mode: deterministic
  autonomy_level: bounded
boundaries:
  risk_budget: medium
  allowed_actions:
    - compute_risk
  environment_scope:
    - production
    - staging
safety:
  sandbox_profile: standard
  audit_level: standard
"""
        dsl = load(scoped_yaml)
        decision = self.engine.evaluate(dsl, action="compute_risk", environment="dev")
        assert decision.allowed is False
        assert "scope" in decision.reason.lower()

    def test_approval_gate_detection(self):
        # Use the supply chain template which has approval_gates
        supply_chain_yaml = """
agent:
  id: sc-agent
  name: SC
  domain: supply_chain
  version: "1.0.0"
intent:
  goal: test
reasoning:
  mode: hybrid
  autonomy_level: bounded
boundaries:
  risk_budget: medium
  approval_gates:
    - flag_critical_vendor
safety:
  sandbox_profile: standard
  audit_level: standard
"""
        dsl = AgentDSL.model_validate(yaml.safe_load(supply_chain_yaml))
        assert self.engine.check_approval_gate(dsl, "flag_critical_vendor") is True
        assert self.engine.check_approval_gate(dsl, "read_vendor") is False
