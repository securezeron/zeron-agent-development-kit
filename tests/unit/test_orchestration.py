"""
Tests for multi-agent orchestration (spawn_agent) and SIF reasoning trace memory.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import yaml

from zak.core.dsl.schema import AgentDSL, ReasoningMode
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.registry import AgentRegistry
from zak.core.tools.substrate import ToolRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_context(extra_tools: list[str] | None = None) -> AgentContext:
    tools = ["spawn_agent", "list_assets"] + (extra_tools or [])
    dsl = AgentDSL.model_validate(yaml.safe_load(f"""
agent:
  id: orch-test
  name: "Orch Test"
  domain: risk_quant
  version: "1.0.0"
intent:
  goal: test orchestration
reasoning:
  mode: llm_react
  autonomy_level: bounded
capabilities:
  tools: {tools}
  data_access: []
boundaries:
  risk_budget: medium
  allowed_actions: {tools}
safety:
  sandbox_profile: standard
  audit_level: standard
"""))
    return AgentContext(
        tenant_id="test-tenant",
        trace_id="trace-orch-001",
        dsl=dsl,
        environment="staging",
    )


class _ChildAgent(BaseAgent):
    """Minimal deterministic agent used as a spawn target in tests."""
    def execute(self, context: AgentContext) -> AgentResult:
        return AgentResult.ok(context, output={"findings": 3, "source": "child"})


# ---------------------------------------------------------------------------
# spawn_agent tool tests
# ---------------------------------------------------------------------------

class TestSpawnAgent:
    def setup_method(self):
        ToolRegistry.get().clear()
        AgentRegistry.get().clear()

    def test_spawn_agent_is_registered_as_zak_tool(self):
        import zak.core.tools.orchestration as _orch  # triggers registration
        assert ToolRegistry.get().is_registered("spawn_agent")

    def test_spawn_known_agent_returns_success(self):
        from zak.core.tools.orchestration import spawn_agent

        AgentRegistry.get().register(
            domain="vuln_triage",
            agent_class=_ChildAgent,
            edition="open-source",
        )

        ctx = _make_context()

        # Patch DOMAIN_TEMPLATES so spawn_agent can load a DSL for vuln_triage
        fake_tmpl = MagicMock()
        fake_tmpl.yaml_template = """
agent:
  id: child-vuln-triage
  name: "Spawned — vuln_triage"
  domain: vuln_triage
  version: "1.0.0"
intent:
  goal: triage
reasoning:
  mode: deterministic
  autonomy_level: bounded
capabilities:
  tools: []
  data_access: []
boundaries:
  risk_budget: low
  allowed_actions:
    - agent_execute
safety:
  sandbox_profile: standard
  audit_level: standard
"""
        with patch("zak.cli.templates.DOMAIN_TEMPLATES", {"vuln_triage": fake_tmpl}):
            result = spawn_agent(context=ctx, domain="vuln_triage", environment="staging")

        assert result["domain"] == "vuln_triage"
        assert result["success"] is True
        assert result["output"]["findings"] == 3

    def test_spawn_unknown_domain_returns_error(self):
        from zak.core.tools.orchestration import spawn_agent

        ctx = _make_context()
        result = spawn_agent(context=ctx, domain="nonexistent_domain")

        assert result["domain"] == "nonexistent_domain"
        assert "error" in result
        assert "No agent registered" in result["error"]

    def test_spawn_forces_deterministic_mode(self):
        """Child agent must always run in deterministic mode regardless of its YAML."""
        from zak.core.tools.orchestration import _force_deterministic

        yaml_with_llm = "reasoning:\n  mode: llm_react\n"
        result = _force_deterministic(yaml_with_llm)
        assert "mode: deterministic" in result
        assert "llm_react" not in result

    def test_spawn_passes_tenant_id_to_child(self):
        """Child context must inherit tenant_id from parent context."""
        from zak.core.tools.orchestration import spawn_agent

        captured: list[AgentContext] = []

        class _CapturingAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                captured.append(context)
                return AgentResult.ok(context, output={})

        AgentRegistry.get().register(
            domain="vuln_triage",
            agent_class=_CapturingAgent,
            edition="open-source",
        )

        ctx = _make_context()

        fake_tmpl = MagicMock()
        fake_tmpl.yaml_template = """
agent:
  id: child-vuln-triage
  name: "Spawned — vuln_triage"
  domain: vuln_triage
  version: "1.0.0"
intent:
  goal: capture
reasoning:
  mode: llm_react
  autonomy_level: bounded
capabilities:
  tools: []
  data_access: []
boundaries:
  risk_budget: low
  allowed_actions:
    - agent_execute
safety:
  sandbox_profile: standard
  audit_level: standard
"""
        with patch("zak.cli.templates.DOMAIN_TEMPLATES", {"vuln_triage": fake_tmpl}):
            spawn_agent(context=ctx, domain="vuln_triage", environment="production")

        assert len(captured) == 1
        assert captured[0].tenant_id == "test-tenant"
        assert captured[0].dsl.reasoning.mode == ReasoningMode.DETERMINISTIC


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Reasoning trace (Memgraph adapter) tests
# ---------------------------------------------------------------------------

class TestReasoningTrace:
    def _make_adapter_with_mock_driver(self):
        """Return a KuzuAdapter whose Bolt driver is fully mocked."""
        from zak.sif.graph.adapter import KuzuAdapter
        adapter = object.__new__(KuzuAdapter)  # bypass __init__ (no real connection)
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = lambda s, *a: mock_session
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        adapter._driver = mock_driver
        return adapter, mock_driver, mock_session

    def test_write_reasoning_trace_calls_cypher(self):
        adapter, _, mock_session = self._make_adapter_with_mock_driver()

        adapter.write_reasoning_trace("t1", {
            "trace_id": "run-abc",
            "domain": "risk_quant",
            "environment": "production",
            "status": "completed",
            "iteration_count": 3,
            "tool_calls": [{"tool": "list_assets", "arguments": {}}],
            "output": {"assets_scored": 5},
        })

        mock_session.run.assert_called_once()
        call_kwargs = mock_session.run.call_args
        assert call_kwargs[1]["trace_id"] == "run-abc"
        assert call_kwargs[1]["domain"] == "risk_quant"
        assert call_kwargs[1]["status"] == "completed"
        assert call_kwargs[1]["iteration_count"] == 3

        tool_calls_json = call_kwargs[1]["tool_calls"]
        assert json.loads(tool_calls_json)[0]["tool"] == "list_assets"

    def test_write_reasoning_trace_survives_driver_error(self):
        """Should log a warning and not raise when Memgraph is unreachable."""
        from zak.sif.graph.adapter import KuzuAdapter
        adapter = object.__new__(KuzuAdapter)
        mock_driver = MagicMock()
        mock_driver.session.side_effect = ConnectionRefusedError("no connection")
        adapter._driver = mock_driver

        # Must not raise
        adapter.write_reasoning_trace("t1", {"trace_id": "x", "domain": "test"})

    def test_get_reasoning_traces_deserialises_json_blobs(self):
        adapter, _, mock_session = self._make_adapter_with_mock_driver()

        # Simulate a Memgraph node record — dict() must work on record["t"]
        fake_node = {
            "trace_id": "run-abc",
            "tenant_id": "t1",
            "domain": "risk_quant",
            "tool_calls": json.dumps([{"tool": "list_assets"}]),
            "output": json.dumps({"assets_scored": 7}),
        }
        mock_session.run.return_value = [{"t": fake_node}]

        traces = adapter.get_reasoning_traces("t1", domain="risk_quant")

        assert len(traces) == 1
        assert traces[0]["tool_calls"] == [{"tool": "list_assets"}]
        assert traces[0]["output"] == {"assets_scored": 7}

    def test_get_reasoning_traces_returns_empty_on_error(self):
        from zak.sif.graph.adapter import KuzuAdapter
        adapter = object.__new__(KuzuAdapter)
        mock_driver = MagicMock()
        mock_driver.session.side_effect = OSError("unreachable")
        adapter._driver = mock_driver

        result = adapter.get_reasoning_traces("t1")
        assert result == []
