"""
Tests for the ZAK Tool Substrate — @zak_tool decorator and ToolExecutor.
"""

import pytest
import yaml

from zak.core.dsl.schema import AgentDSL
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.tools.substrate import ToolExecutor, ToolRegistry, zak_tool
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TOOL_AGENT_YAML = """
agent:
  id: tool-test-agent
  name: "Tool Test Agent"
  domain: risk_quant
  version: "1.0.0"

intent:
  goal: "Test tools"

reasoning:
  mode: deterministic
  autonomy_level: bounded

capabilities:
  tools:
    - my_test_tool
    - compute_risk
  data_access: []

boundaries:
  risk_budget: medium
  allowed_actions:
    - my_test_tool
    - compute_risk

safety:
  sandbox_profile: standard
  audit_level: standard
"""


def make_context(yaml_str: str = TOOL_AGENT_YAML) -> AgentContext:
    dsl = AgentDSL.model_validate(yaml.safe_load(yaml_str))
    return AgentContext(
        tenant_id="test-tenant",
        trace_id="trace-001",
        dsl=dsl,
        environment="staging",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestZakTool:
    def setup_method(self):
        ToolRegistry.get().clear()

    def test_decorator_registers_tool(self):
        @zak_tool(name="my_test_tool", description="A test tool", action_id="my_test_tool")
        def my_tool():
            return "hello"

        assert ToolRegistry.get().is_registered("my_test_tool")

    def test_decorator_attaches_metadata(self):
        @zak_tool(name="meta_tool", description="Meta desc", action_id="meta_tool")
        def meta_tool():
            pass

        assert meta_tool._zak_tool.name == "meta_tool"
        assert meta_tool._zak_tool.description == "Meta desc"
        assert meta_tool._zak_tool.action_id == "meta_tool"

    def test_action_id_defaults_to_name(self):
        @zak_tool(name="default_id_tool")
        def auto_id_tool():
            pass

        assert ToolRegistry.get().is_registered("default_id_tool")

    def test_tool_registry_summary(self):
        @zak_tool(name="sum_tool", description="Summary tool", action_id="sum_tool")
        def sum_tool():
            pass

        summary = ToolRegistry.get().summary()
        assert "sum_tool" in summary


class TestToolExecutor:
    def setup_method(self):
        ToolRegistry.get().clear()

    def test_tool_executes_successfully(self):
        @zak_tool(name="my_test_tool", description="Returns 42", action_id="my_test_tool")
        def my_test_tool():
            return 42

        ctx = make_context()
        result = ToolExecutor.call(my_test_tool, context=ctx)
        assert result == 42

    def test_tool_injects_context_if_requested(self):
        @zak_tool(name="my_test_tool", description="Uses context", action_id="my_test_tool")
        def my_test_tool(context: AgentContext):
            return context.tenant_id

        ctx = make_context()
        result = ToolExecutor.call(my_test_tool, context=ctx)
        assert result == "test-tenant"

    def test_tool_blocked_if_not_in_capabilities(self):
        @zak_tool(name="unlisted_tool", description="Not in caps", action_id="unlisted_tool")
        def unlisted_tool():
            return "should not run"

        ctx = make_context()
        with pytest.raises(PermissionError, match="not declared in agent capabilities"):
            ToolExecutor.call(unlisted_tool, context=ctx)

    def test_tool_blocked_by_policy_deny_list(self):
        # Register a tool whose action_id is in capabilities.tools
        # but also in denied_actions — policy deny-list should block it.
        deny_yaml = """
agent:
  id: deny-test-agent
  name: Deny Test Agent
  domain: risk_quant
  version: "1.0.0"
intent:
  goal: test
reasoning:
  mode: deterministic
  autonomy_level: bounded
capabilities:
  tools:
    - delete_asset
boundaries:
  risk_budget: medium
  allowed_actions:
    - read_asset
  denied_actions:
    - delete_asset
safety:
  sandbox_profile: standard
  audit_level: standard
"""
        @zak_tool(name="delete_asset", description="Delete an asset", action_id="delete_asset")
        def delete_tool():
            return "deleted"

        ctx = make_context(deny_yaml)
        with pytest.raises(PermissionError, match="Policy denied"):
            ToolExecutor.call(delete_tool, context=ctx)

    def test_non_zak_tool_raises_value_error(self):
        def plain_fn():
            return "plain"

        ctx = make_context()
        with pytest.raises(ValueError, match="not a @zak_tool"):
            ToolExecutor.call(plain_fn, context=ctx)

    def test_compute_risk_builtin_tool(self):
        """Smoke test the built-in compute_risk tool via ToolExecutor."""
        import zak.core.tools.builtins  # noqa: F401 — trigger registration

        ctx = make_context()
        result = ToolExecutor.call(
            zak.core.tools.builtins.compute_risk,
            context=ctx,
            criticality="high",
            exposure="external",
            exploitability=0.8,
            control_effectiveness=0.3,
            privilege_level="admin",
        )
        assert "risk_score" in result
        assert "risk_level" in result
        assert 0.0 <= result["risk_score"] <= 10.0
