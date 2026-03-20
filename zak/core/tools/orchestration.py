"""
ZAK orchestration tools — multi-agent coordination utilities.

spawn_agent: Synchronously runs a named child agent and returns its output.
Child agents always execute in deterministic mode to prevent recursive LLM spawning.
"""

from __future__ import annotations

import inspect
import os
import tempfile
from typing import Any

from zak.core.runtime.agent import AgentContext
from zak.core.tools.substrate import zak_tool


@zak_tool(
    name="spawn_agent",
    description=(
        "Spawn a child security agent and return its analysis results. "
        "Use this to delegate specialised sub-tasks to domain-specific agents. "
        "The child always runs in deterministic mode."
    ),
    action_id="spawn_agent",
    tags=["orchestration", "spawn"],
)
def spawn_agent(
    context: AgentContext,
    domain: str,
    environment: str = "production",
) -> dict[str, Any]:
    """
    Resolve and synchronously execute a child agent.

    Args:
        context:     Parent agent context (supplies tenant_id, trace_id).
        domain:      Domain slug of the child agent (e.g. 'vuln_triage').
        environment: Target environment — passed through to child context.

    Returns:
        dict with keys: domain, success, output  (or: domain, error)
    """
    from zak.cli.templates import DOMAIN_TEMPLATES
    from zak.core.dsl.parser import load_agent_yaml
    from zak.core.dsl.schema import ReasoningMode
    from zak.core.runtime.executor import AgentExecutor
    from zak.core.runtime.registry import AgentRegistry

    registry = AgentRegistry.get()

    if not registry.is_registered(domain):
        return {"domain": domain, "error": f"No agent registered for domain '{domain}'."}

    # Load child DSL from template
    if domain not in DOMAIN_TEMPLATES:
        return {"domain": domain, "error": f"No DSL template found for domain '{domain}'."}

    tmpl = DOMAIN_TEMPLATES[domain]
    yaml_str = tmpl.yaml_template.format(
        agent_id=f"spawn-{domain.replace('_', '-')}",
        agent_name=f"Spawned — {domain}",
    )

    # Force deterministic mode — no recursive LLM spawning
    yaml_str = _force_deterministic(yaml_str)

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_str)
            tmp_path = f.name
        try:
            dsl = load_agent_yaml(tmp_path)
        finally:
            os.unlink(tmp_path)
    except Exception as exc:
        return {"domain": domain, "error": f"DSL parse error: {exc}"}

    # Force deterministic on the parsed DSL object too (in case yaml override missed it)
    dsl.reasoning.mode = ReasoningMode.DETERMINISTIC

    child_context = AgentContext(
        tenant_id=context.tenant_id,
        trace_id=context.trace_id,
        dsl=dsl,
        environment=environment,
    )

    # Instantiate child agent (inject adapter if the constructor accepts one)
    try:
        agent_cls = registry.resolve(domain)
    except Exception as exc:
        return {"domain": domain, "error": str(exc)}

    sig = inspect.signature(agent_cls.__init__)  # type: ignore[misc]
    if "adapter" in sig.parameters:
        try:
            from zak.sif.graph.adapter import KuzuAdapter
            adapter = KuzuAdapter()
            adapter.initialize_schema(context.tenant_id)
            agent = agent_cls(adapter)
        except Exception:
            agent = agent_cls()
    else:
        agent = agent_cls()

    result = AgentExecutor().run(agent, child_context)

    if result.success:
        return {"domain": domain, "success": True, "output": result.output}
    else:
        return {"domain": domain, "success": False, "error": "; ".join(result.errors)}


def _force_deterministic(yaml_str: str) -> str:
    """Replace 'mode: llm_react' with 'mode: deterministic' in a YAML string."""
    import re
    return re.sub(r"mode:\s*llm_react", "mode: deterministic", yaml_str)
