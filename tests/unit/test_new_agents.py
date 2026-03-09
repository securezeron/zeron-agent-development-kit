
import pytest
from zak.core.runtime.agent import AgentContext
from zak.core.runtime.registry import AgentRegistry
from zak.core.tools.substrate import ToolRegistry
from zak.agents.usage_metrics.agent import UsageMetricsAgent
from zak.agents.compliance.dpdp_agent import DPDPAgent

def test_usage_metrics_agent_registration():
    import importlib
    import zak.agents.usage_metrics.agent
    importlib.reload(zak.agents.usage_metrics.agent)
    from zak.agents.usage_metrics.agent import UsageMetricsAgent
    
    agent_cls = AgentRegistry.get().resolve("usage_metrics")
    assert agent_cls == UsageMetricsAgent

def test_dpdp_agent_registration():
    import importlib
    import zak.agents.compliance.dpdp_agent
    importlib.reload(zak.agents.compliance.dpdp_agent)
    from zak.agents.compliance.dpdp_agent import DPDPAgent
    
    agent_cls = AgentRegistry.get().resolve("compliance")
    assert agent_cls == DPDPAgent

def test_compliance_tools_registration():
    from zak.agents import load_all_agents
    load_all_agents()
    tool_entry = ToolRegistry.get().get_tool("fetch_website_content")
    assert tool_entry is not None
    meta, fn = tool_entry
    assert meta.action_id == "fetch_website_content"

def test_usage_metrics_tools_registration():
    from zak.agents import load_all_agents
    load_all_agents()
    tool_entry = ToolRegistry.get().get_tool("gather_platform_stats")
    assert tool_entry is not None
    
    tool_entry = ToolRegistry.get().get_tool("gather_tenant_stats")
    assert tool_entry is not None
