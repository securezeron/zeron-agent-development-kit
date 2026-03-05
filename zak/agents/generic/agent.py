"""
GenericAgent — executor for DSL-only custom agents created via the platform UI.

DSL-only agents have a YAML config but no custom Python execute() method.
This agent reads the DSL metadata from AgentContext and returns a structured
placeholder result explaining what the agent is configured to do.
"""

from __future__ import annotations

from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.registry import register_agent


@register_agent(
    domain="generic",
    description="Generic executor for DSL-only custom agents. Returns a structured summary of the agent configuration.",
    version="1.0.0",
    edition="open-source",
)
class GenericAgent(BaseAgent):
    """Runs DSL-only agents created via the platform UI."""

    def execute(self, context: AgentContext) -> AgentResult:
        import time
        start = time.time()

        dsl = context.dsl
        agent_meta = dsl.agent

        output = {
            "agent_id": agent_meta.id,
            "agent_name": agent_meta.name,
            "domain": str(agent_meta.domain),
            "version": agent_meta.version,
            "goal": dsl.intent.goal,
            "success_criteria": dsl.intent.success_criteria,
            "reasoning_mode": str(dsl.reasoning.mode),
            "autonomy_level": str(dsl.reasoning.autonomy_level),
            "confidence_threshold": dsl.reasoning.confidence_threshold,
            "tools": dsl.capabilities.tools if dsl.capabilities else [],
            "environment": context.environment,
            "status": "dsl_only",
            "message": (
                "This is a DSL-only agent. Add a Python execute() implementation "
                "to perform real analysis. The configuration above defines this agent's "
                "intended behavior, boundaries, and reasoning strategy."
            ),
        }

        duration_ms = (time.time() - start) * 1000
        return AgentResult.ok(context, output=output, duration_ms=duration_ms)
