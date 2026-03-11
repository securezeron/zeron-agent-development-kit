"""
Tests that deactivated tenants cannot run agents.

AgentExecutor must block execution when the tenant is deactivated in TenantRegistry.
"""

import pytest
import yaml

from zak.core.dsl.schema import AgentDSL
from zak.core.runtime.agent import AgentContext
from zak.core.runtime.executor import AgentExecutor
from zak.tenants.context import TenantRegistry


MINIMAL_AGENT_YAML = """
agent:
  id: tenant-test-agent
  name: Tenant Test Agent
  domain: risk_quant
  version: 1.0.0
intent:
  goal: Test
  success_criteria: []
  priority: high
reasoning:
  mode: deterministic
  autonomy_level: bounded
  confidence_threshold: 0.75
capabilities:
  tools: [compute_risk]
  data_access: []
boundaries:
  risk_budget: medium
  allowed_actions: [agent_execute, compute_risk]
  denied_actions: []
  environment_scope: [staging]
safety:
  sandbox_profile: standard
  audit_level: standard
"""


def _make_context(tenant_id: str = "test-tenant") -> AgentContext:
    dsl = AgentDSL.model_validate(yaml.safe_load(MINIMAL_AGENT_YAML))
    return AgentContext(
        tenant_id=tenant_id,
        trace_id="trace-001",
        dsl=dsl,
        environment="staging",
    )


def test_deactivated_tenant_raises_permission_error():
    """Deactivated tenant must not be able to run an agent."""
    from zak.agents import load_all_agents
    load_all_agents()

    reg = TenantRegistry.get()
    reg.clear()

    reg.register("blocked-tenant", "Blocked")
    reg.deactivate("blocked-tenant")

    ctx = _make_context(tenant_id="blocked-tenant")
    agent_cls = __import__("zak.agents.risk_quant.agent", fromlist=["RiskQuantAgent"]).RiskQuantAgent
    agent = agent_cls()
    executor = AgentExecutor()

    with pytest.raises(PermissionError, match="deactivated. Access denied"):
        executor.run(agent, ctx)


def test_active_tenant_runs_successfully():
    """Active tenant can run an agent (no regression)."""
    from zak.agents import load_all_agents
    load_all_agents()

    reg = TenantRegistry.get()
    reg.clear()

    reg.register("active-tenant", "Active")

    ctx = _make_context(tenant_id="active-tenant")
    agent_cls = __import__("zak.agents.risk_quant.agent", fromlist=["RiskQuantAgent"]).RiskQuantAgent
    agent = agent_cls()
    executor = AgentExecutor()

    result = executor.run(agent, ctx)

    assert result.success is True
