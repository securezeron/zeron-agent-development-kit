"""
Vulnerability Triage Agent — ZAK reference implementation.

Reads vulnerability nodes and linked assets, then prioritises CVEs by
combining CVSS severity, asset criticality, exploitability, and whether
a public exploit exists.

Supports two execution modes:

  reasoning.mode: deterministic  (default)
    → Applies the ZAK priority-scoring formula deterministically.

  reasoning.mode: llm_react
    → Uses an LLM in a ReAct loop to contextually triage vulnerabilities.
    → LLM calls list_vulnerabilities, list_assets, compute_risk.
    → Produces natural language triage summary + reasoning trace.
"""

from __future__ import annotations

from zak.core.dsl.schema import ReasoningMode
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.llm_agent import LLMAgent
from zak.core.runtime.registry import register_agent

try:
    from zak.sif.graph.adapter import KuzuAdapter
except Exception:
    KuzuAdapter = None  # type: ignore[assignment,misc]

_SEVERITY_SCORES = {"critical": 10.0, "high": 7.5, "medium": 4.0, "low": 1.5, "info": 0.5}
_CRIT_MULT = {"critical": 1.5, "high": 1.2, "medium": 1.0, "low": 0.7}


@register_agent(
    domain="vuln_triage",
    description="Prioritises CVEs by CVSS severity, asset criticality, and exploitability",
    version="2.0.0",
    edition="open-source",
)
class VulnTriageAgent(BaseAgent):
    """
    Reads vulnerability nodes from SIF and ranks them using a composite priority
    score: CVSS severity × asset criticality × exploit-availability multiplier.

    Supports both deterministic and LLM-powered ReAct modes.
    Set reasoning.mode: llm_react in the agent DSL to enable LLM mode.
    """

    def __init__(self, adapter: object | None = None) -> None:
        self._adapter = adapter

    def execute(self, context: AgentContext) -> AgentResult:
        if context.dsl.reasoning.mode == ReasoningMode.LLM_REACT:
            return _LLMVulnTriageAgent().execute(context)
        return self._execute_deterministic(context)

    def _execute_deterministic(self, context: AgentContext) -> AgentResult:
        tenant_id = context.tenant_id
        vulns = (
            self._adapter.get_nodes(tenant_id=tenant_id, node_type="vulnerability")  # type: ignore[union-attr]
            if self._adapter is not None else []
        )
        assets = (
            self._adapter.get_nodes(tenant_id=tenant_id, node_type="asset")  # type: ignore[union-attr]
            if self._adapter is not None else []
        )

        asset_crit = {a["node_id"]: a.get("criticality", "medium") for a in assets}
        triaged: list[dict] = []

        for vuln in vulns:
            severity = vuln.get("severity", "medium").lower()
            has_exploit = bool(vuln.get("exploit_available", False))
            affected_asset = vuln.get("affected_asset_id", "")
            crit = asset_crit.get(affected_asset, "medium")

            base = _SEVERITY_SCORES.get(severity, 4.0)
            mult = _CRIT_MULT.get(crit, 1.0)
            exploit_bonus = 2.0 if has_exploit else 0.0
            priority_score = round(min(base * mult + exploit_bonus, 10.0), 2)

            triaged.append({
                "vuln_id": vuln.get("node_id"),
                "cve_id": vuln.get("cve_id", "CVE-UNKNOWN"),
                "severity": severity,
                "affected_asset": affected_asset,
                "exploit_available": has_exploit,
                "priority_score": priority_score,
                "recommendation": "immediate" if priority_score >= 8 else "scheduled",
            })

        triaged.sort(key=lambda x: x["priority_score"], reverse=True)
        critical_count = sum(1 for v in triaged if v["priority_score"] >= 8.0)

        return AgentResult.ok(
            context,
            output={
                "total_vulns": len(triaged),
                "critical_priority": critical_count,
                "triaged": triaged,
            },
        )


# ---------------------------------------------------------------------------
# LLM-powered implementation
# ---------------------------------------------------------------------------

class _LLMVulnTriageAgent(LLMAgent):
    """
    LLM-powered vulnerability triage using the ReAct loop.

    The LLM follows this sequence:
        1. list_vulnerabilities  → discover all CVEs and findings
        2. list_assets           → understand asset criticality context
        3. compute_risk          → score the most dangerous combinations
        4. STOP + summarize      → structured triage report with priorities
    """

    @property
    def tools(self) -> list:
        from zak.core.tools.builtins import (
            list_vulnerabilities,
            list_assets,
            compute_risk,
        )
        return [list_vulnerabilities, list_assets, compute_risk]

    def system_prompt(self, context: AgentContext) -> str:
        return f"""You are an expert vulnerability triage agent for tenant '{context.tenant_id}'.

Your goal: Analyse all vulnerabilities in this environment and produce a prioritised remediation plan.

Follow this sequence:
1. Call list_vulnerabilities to get all CVEs and security findings.
2. Call list_assets to understand asset criticality and exposure.
3. For the top 5 most dangerous vulnerabilities, call compute_risk with appropriate parameters.
4. When done, return a JSON summary with:
   - total_vulns: total count
   - critical_priority: count of vulnerabilities requiring immediate action (score >= 8)
   - triaged: list of top 10 vulns, each with: vuln_id, cve_id, severity, priority_score (0-10), recommendation ("immediate"|"scheduled"|"monitor"), justification
   - top_finding: the single most dangerous vulnerability and why
   - remediation_plan: ordered list of 3-5 actionable steps

Base every priority score on tool output. Explain your reasoning for each critical finding."""
