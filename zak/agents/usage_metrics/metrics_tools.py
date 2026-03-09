"""
Zeron Usage Metrics Tools — gathering platform and tenant platform metrics.
"""

from __future__ import annotations

from typing import Any
from zak.core.runtime.agent import AgentContext
from zak.core.tools.substrate import zak_tool


@zak_tool(
    name="gather_platform_stats",
    description="Gather platform-level usage metrics (total tenants and registered agents).",
    action_id="gather_platform_stats",
    tags=["metrics", "platform"],
)
def gather_platform_stats(context: AgentContext) -> dict[str, Any]:
    """Returns total counts of tenants and agents registered in the platform."""
    from zak.tenants.context import TenantRegistry
    from zak.core.runtime.registry import AgentRegistry

    tenants = TenantRegistry.get().all()
    agents = AgentRegistry.get().all_registrations_unfiltered()

    return {
        "total_tenants": len(tenants),
        "total_agents": len(agents),
        "active_tenants": len([t for t in tenants if t.active]),
    }


@zak_tool(
    name="gather_tenant_stats",
    description="Gather usage metrics for the current tenant (asset count, vulnerability count, etc.).",
    action_id="gather_tenant_stats",
    tags=["metrics", "tenant"],
)
def gather_tenant_stats(context: AgentContext) -> dict[str, Any]:
    """Returns counts of various SIF nodes for the current tenant."""
    from zak.sif.graph.adapter import KuzuAdapter

    adapter = KuzuAdapter()
    
    stats = {
        "asset_count": len(adapter.get_nodes(context.tenant_id, "asset")),
        "vulnerability_count": len(adapter.get_nodes(context.tenant_id, "vulnerability")),
        "risk_count": len(adapter.get_nodes(context.tenant_id, "risk")),
        "control_count": len(adapter.get_nodes(context.tenant_id, "control")),
        "vendor_count": len(adapter.get_nodes(context.tenant_id, "vendor")),
        "identity_count": len(adapter.get_nodes(context.tenant_id, "identity")),
        "ai_model_count": len(adapter.get_nodes(context.tenant_id, "ai_model")),
    }
    
    return stats
