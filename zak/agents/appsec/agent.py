"""
Application Security Agent — ZAK reference implementation.

Scans application repositories for SAST findings, dependency vulnerabilities,
secrets exposure, and IaC misconfigurations. Feeds results into the SIF graph.

Supports two execution modes:

  reasoning.mode: deterministic  (default)
    → Aggregates SAST findings and CVEs from SIF graph nodes.

  reasoning.mode: llm_react
    → Uses an LLM in a ReAct loop to reason about application security risks.
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

_FINDING_SEVERITY_SCORE = {"critical": 10, "high": 7, "medium": 4, "low": 1}


@register_agent(
    domain="appsec",
    description="SAST, SCA, secrets detection, and dependency vulnerability scanning for application repos",
    version="2.0.0",
    edition="open-source",
)
class AppSecAgent(BaseAgent):
    """
    Reads application/repository nodes and performs AppSec analysis.
    Supports both deterministic and LLM-powered ReAct modes.
    """

    def __init__(self, adapter: object | None = None) -> None:
        self._adapter = adapter

    def execute(self, context: AgentContext) -> AgentResult:
        if context.dsl.reasoning.mode == ReasoningMode.LLM_REACT:
            return _LLMAppSecAgent().execute(context)
        return self._execute_deterministic(context)

    def _execute_deterministic(self, context: AgentContext) -> AgentResult:
        tenant_id = context.tenant_id
        repos = (
            self._adapter.get_nodes(tenant_id=tenant_id, node_type="repository")  # type: ignore[union-attr]
            if self._adapter is not None else []
        )
        deps = (
            self._adapter.get_nodes(tenant_id=tenant_id, node_type="dependency")  # type: ignore[union-attr]
            if self._adapter is not None else []
        )

        findings: list[dict] = []
        secrets_found = 0

        for repo in repos:
            repo_findings = repo.get("sast_findings", [])
            for finding in repo_findings:
                sev = finding.get("severity", "medium").lower()
                findings.append({
                    "repo_id": repo.get("node_id"),
                    "finding_type": finding.get("type", "unknown"),
                    "severity": sev,
                    "score": _FINDING_SEVERITY_SCORE.get(sev, 4),
                    "file": finding.get("file", ""),
                    "line": finding.get("line", 0),
                })
            secrets_found += int(repo.get("exposed_secrets_count", 0))

        vuln_deps = [d for d in deps if d.get("has_known_cve", False)]
        critical_findings = [f for f in findings if f["severity"] in ("critical", "high")]

        return AgentResult.ok(
            context,
            output={
                "repos_scanned": len(repos),
                "total_findings": len(findings),
                "critical_high_findings": len(critical_findings),
                "vulnerable_dependencies": len(vuln_deps),
                "exposed_secrets": secrets_found,
                "findings": findings[:50],
            },
        )


# ---------------------------------------------------------------------------
# LLM-powered implementation
# ---------------------------------------------------------------------------

class _LLMAppSecAgent(LLMAgent):
    """LLM-powered application security analysis using the ReAct loop."""

    @property
    def tools(self) -> list:
        from zak.core.tools.builtins import (
            list_assets,
            list_vulnerabilities,
            compute_risk,
        )
        return [list_assets, list_vulnerabilities, compute_risk]

    def system_prompt(self, context: AgentContext) -> str:
        return f"""You are an expert application security (AppSec) analyst for tenant '{context.tenant_id}'.

Your goal: Identify OWASP Top 10 risks, vulnerable dependencies, secrets exposure, and SAST findings across the application portfolio.

Follow this sequence:
1. Call list_assets — identify application assets (asset_type: web_app, api, microservice).
   Look for: exposed_secrets_count > 0, sast_findings, dependency_cve_count.
2. Call list_vulnerabilities — find CVEs in application dependencies and frameworks.
   Focus on: injection (SQL/LDAP/OS), XSS, SSRF, deserialization, broken auth.
3. For the top 5 riskiest application assets, call compute_risk.
4. Return a JSON summary with:
   - repos_scanned: total application assets reviewed
   - total_findings: all SAST + SCA findings
   - critical_high_findings: count with severity critical or high
   - vulnerable_dependencies: count of deps with known CVEs
   - exposed_secrets: total count of hardcoded secrets/keys
   - owasp_top10_coverage: dict mapping OWASP categories (A01-A10) to finding count
   - findings: top 50 findings with repo_id, finding_type, severity, cve_id, owasp_category,
     description, remediation
   - security_debt_score: 0-100 (100 = no issues)
   - recommended_tools: list of tools (Semgrep, Snyk, Trivy, GitLeaks) mapped to finding types"""
