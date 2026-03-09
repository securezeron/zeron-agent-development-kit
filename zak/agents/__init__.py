"""ZAK agents package — open-source edition."""

# Open-source built-in agent modules.
ALL_AGENT_MODULES: list[str] = [
    "zak.agents.generic.agent",
    "zak.agents.risk_quant.agent",
    "zak.agents.vuln_triage.agent",
    "zak.agents.appsec.agent",
    "zak.agents.usage_metrics.agent",
    "zak.agents.compliance.dpdp_agent",
]


def load_all_agents() -> None:
    """Import all built-in agent modules so @register_agent decorators fire."""
    import importlib
    for mod in ALL_AGENT_MODULES:
        importlib.import_module(mod)
