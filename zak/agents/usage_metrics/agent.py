"""
UsageMetricsAgent — gathers and consolidates metrics from across the Zeron platform.
"""

from __future__ import annotations

import time
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.registry import register_agent
from zak.core.tools.substrate import ToolExecutor
from zak.agents.usage_metrics import metrics_tools


@register_agent(
    domain="usage_metrics",
    description="Gathers usage metrics from the platform and specific tenants.",
    version="1.0.0",
    edition="open-source",
)
class UsageMetricsAgent(BaseAgent):
    """Gathers and consolidates platform and tenant metrics."""

    def execute(self, context: AgentContext) -> AgentResult:
        start = time.time()

        # 1. Gather Platform Stats
        platform_stats = ToolExecutor.call(
            metrics_tools.gather_platform_stats,
            context=context
        )

        # 2. Gather Tenant Stats
        tenant_stats = ToolExecutor.call(
            metrics_tools.gather_tenant_stats,
            context=context
        )

        output = {
            "platform": platform_stats,
            "tenant": {
                "tenant_id": context.tenant_id,
                "metrics": tenant_stats
            },
            "timestamp": time.time()
        }

        duration_ms = (time.time() - start) * 1000
        return AgentResult.ok(context, output=output, duration_ms=duration_ms)
