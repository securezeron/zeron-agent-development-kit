"""
Risk Quantification Agent — ZAK reference implementation.

Reads asset + vulnerability data from the SIF graph, computes risk scores
using the RiskPropagationEngine, and writes RiskNodes back to the graph.

This agent supports two execution modes:

  reasoning.mode: deterministic  (default)
    → Applies the ZAK RiskPropagationEngine formula deterministically.
    → Identical output on every run for the same data.

  reasoning.mode: llm_react
    → Uses an LLM (configured via reasoning.llm) in a ReAct loop.
    → LLM calls list_assets, list_vulnerabilities, compute_risk, write_risk_node.
    → Adapts its analysis based on what it discovers; produces natural language summary.
    → Requires LLM_API_KEY + LLM_PROVIDER env vars.

QBER integration point: replace _compute_eal_stub() with PyMC model in Phase 3.
"""

from __future__ import annotations

from zak.core.dsl.schema import ReasoningMode
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.registry import register_agent
from zak.sif.risk.propagation import RiskInputs, RiskPropagationEngine
from zak.sif.schema.nodes import RiskNode

try:
    from zak.sif.graph.adapter import KuzuAdapter
except ImportError:
    KuzuAdapter = None  # type: ignore[assignment,misc]


@register_agent(
    domain="risk_quant",
    description="Computes risk scores for all assets using the ZAK risk propagation engine",
    version="1.0.0",
    edition="open-source",
)
class RiskQuantAgent(BaseAgent):
    """
    Computes and persists risk scores for all assets in a tenant's SIF graph.

    Supports both deterministic and LLM-powered ReAct modes.
    Set reasoning.mode: llm_react in the agent DSL to enable LLM mode.
    """

    def __init__(self, adapter: object | None = None) -> None:
        self._adapter = adapter
        self._engine = RiskPropagationEngine()

    def execute(self, context: AgentContext) -> AgentResult:
        # Delegate to LLM mode when reasoning.mode == llm_react
        if context.dsl.reasoning.mode == ReasoningMode.LLM_REACT:
            return self._execute_llm(context)
        return self._execute_deterministic(context)

    # ── LLM-powered execution ───────────────────────────────────────────────

    def _execute_llm(self, context: AgentContext) -> AgentResult:
        """LLM ReAct loop — delegates to LLMRiskQuantAgent."""
        agent = _LLMRiskQuantAgent(adapter=self._adapter)
        return agent.execute(context)

    # ── Deterministic execution (original) ─────────────────────────────────

    def _execute_deterministic(self, context: AgentContext) -> AgentResult:
        tenant_id = context.tenant_id
        scored: list[dict] = []
        errors: list[str] = []

        # Load all assets for this tenant (graceful when graph is unavailable)
        assets = (
            self._adapter.get_nodes(tenant_id=tenant_id, node_type="asset")
            if self._adapter is not None else []
        )

        for asset in assets:
            try:
                risk_output = self._score_asset(asset, tenant_id)
                risk_node = RiskNode(
                    node_id=f"risk-{asset['node_id']}",
                    risk_type="cyber",
                    likelihood=risk_output.raw_score,
                    impact=float(asset.get("criticality_score", 5.0)),
                    risk_score=risk_output.risk_score,
                    eal=self._compute_eal_stub(risk_output.risk_score),
                    source=context.agent_id,
                )
                if self._adapter is not None:
                    self._adapter.upsert_node(tenant_id, risk_node)
                scored.append({
                    "asset_id": asset["node_id"],
                    "risk_score": risk_output.risk_score,
                    "risk_level": risk_output.risk_level,
                })
            except Exception as e:
                errors.append(f"Failed to score asset {asset.get('node_id')}: {e}")

        if errors and not scored:
            return AgentResult.fail(context, errors=errors)

        return AgentResult.ok(
            context,
            output={
                "assets_scored": len(scored),
                "results": scored,
                "errors": errors,
            },
        )

    def _score_asset(self, asset: dict, tenant_id: str) -> object:
        """Compute risk for a single asset dict."""
        criticality = asset.get("criticality", "medium")
        exposure = asset.get("exposure_level", "internal")

        # Load worst-case vulnerability exploitability for this asset
        vulns = self._adapter.get_nodes(tenant_id=tenant_id, node_type="vulnerability") if self._adapter is not None else []
        max_exploitability = max(
            (float(v.get("exploitability", 0.5)) for v in vulns), default=0.5
        )

        # Load best control effectiveness
        controls = self._adapter.get_nodes(tenant_id=tenant_id, node_type="control") if self._adapter is not None else []
        max_control_eff = max(
            (float(c.get("effectiveness", 0.5)) for c in controls), default=0.0
        )

        inputs = RiskInputs(
            base_risk=RiskPropagationEngine.criticality_to_base_risk(criticality),
            exposure_factor=RiskPropagationEngine.exposure_to_factor(exposure),
            exploitability=max_exploitability,
            control_effectiveness=max_control_eff,
            privilege_amplifier=1.0,  # Will be computed from IdentityNodes in Phase 3
        )
        return RiskPropagationEngine.compute(inputs)

    def _compute_eal_stub(self, risk_score: float) -> float:
        """
        Stub for Expected Annual Loss computation.
        TODO: Replace with QBER PyMC probabilistic model in Phase 3.
        """
        # Simple placeholder: EAL scales with risk score (in USD thousands)
        return round(risk_score * 50_000, 2)


# ---------------------------------------------------------------------------
# LLM-powered implementation — used by RiskQuantAgent when mode=llm_react
# ---------------------------------------------------------------------------

class _LLMRiskQuantAgent:
    """
    Internal LLM-powered risk quantification agent using the ReAct loop.

    Not registered in AgentRegistry — accessed only through RiskQuantAgent
    when reasoning.mode == llm_react.

    The LLM follows this tool sequence:
        1. list_assets        → discover all assets
        2. list_vulnerabilities → find CVEs and weaknesses
        3. compute_risk       → score each asset (called per asset)
        4. write_risk_node    → persist each RiskNode to the SIF graph
        5. STOP + summarize   → produce structured JSON summary

    All tool calls route through ToolExecutor → policy check + audit trail.
    """

    def __init__(self, adapter: object | None = None) -> None:
        self._adapter = adapter

    def execute(self, context: AgentContext) -> AgentResult:
        from zak.core.llm.registry import get_llm_client
        from zak.core.runtime.llm_agent import _build_openai_schema
        from zak.core.tools.builtins import (
            list_assets,
            list_vulnerabilities,
            compute_risk,
            write_risk_node,
        )
        import json

        available_tools = [list_assets, list_vulnerabilities, compute_risk, write_risk_node]
        tools_schema = _build_openai_schema(available_tools)

        # LLM config from DSL
        llm_cfg: dict = {}
        if context.dsl.reasoning.llm:
            llm_block = context.dsl.reasoning.llm
            llm_cfg = (
                llm_block if isinstance(llm_block, dict)
                else llm_block.model_dump(exclude_none=True)
            )

        client = get_llm_client(
            provider=llm_cfg.get("provider"),
            model=llm_cfg.get("model"),
        )
        temperature = float(llm_cfg.get("temperature", 0.2))
        max_tokens = int(llm_cfg.get("max_tokens", 4096))
        max_iter = int(llm_cfg.get("max_iterations", 10))

        system = f"""You are a cyber risk quantification agent for tenant '{context.tenant_id}'.

Your goal: Compute accurate risk scores for every asset in this tenant's environment.

Follow this exact sequence:
1. Call list_assets to discover all assets.
2. Call list_vulnerabilities to find all CVEs and misconfigurations.
3. For each asset, call compute_risk with appropriate criticality, exposure, and exploitability.
4. Optionally call write_risk_node to persist critical findings.
5. When done, return a JSON summary with:
   - assets_scored: total count
   - highest_risk_asset: asset_id + risk_score
   - average_risk_score: mean across all assets
   - risk_distribution: {{critical: N, high: N, medium: N, low: N}}
   - recommendations: list of top 3 actionable findings

Ground every risk score in tool output. Do not invent values."""

        messages = [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": (
                    f"Run risk quantification for tenant '{context.tenant_id}'. "
                    f"Environment: {context.environment}."
                ),
            },
        ]

        reasoning_trace = []
        total_usage: dict = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        def resolve(name: str):
            for fn in available_tools:
                meta = getattr(fn, "_zak_tool", None)
                if meta and meta.action_id == name:
                    return fn
            return None

        for iteration in range(max_iter):
            response = client.chat(
                messages=messages,
                tools=tools_schema,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            for k in total_usage:
                total_usage[k] += response.usage.get(k, 0)

            if response.finish_reason == "stop" or not response.tool_calls:
                conclusion = response.content or "Risk quantification complete."
                reasoning_trace.append({
                    "iteration": iteration + 1, "type": "conclusion", "content": conclusion,
                })
                return AgentResult.ok(
                    context,
                    output={
                        "summary": conclusion,
                        "reasoning_trace": reasoning_trace,
                        "iterations": iteration + 1,
                        "llm_usage": total_usage,
                        "provider": llm_cfg.get("provider", "openai"),
                        "model": llm_cfg.get("model"),
                    },
                )

            tool_results = []
            for tc in response.tool_calls:
                entry = {
                    "iteration": iteration + 1, "type": "tool_call",
                    "tool": tc.name, "arguments": tc.arguments,
                }
                reasoning_trace.append(entry)
                fn = resolve(tc.name)
                if fn is None:
                    err = {"error": f"Unknown tool: {tc.name}"}
                    entry["result"] = err
                    tool_results.append({
                        "role": "tool", "tool_call_id": tc.id,
                        "content": json.dumps(err),
                    })
                    continue
                try:
                    result = ToolExecutor.call(fn, context=context, **tc.arguments)
                    entry["result"] = result
                    tool_results.append({
                        "role": "tool", "tool_call_id": tc.id,
                        "content": json.dumps(result) if not isinstance(result, str) else result,
                    })
                except Exception as exc:
                    err = {"error": str(exc)}
                    entry["result"] = err
                    tool_results.append({
                        "role": "tool", "tool_call_id": tc.id,
                        "content": json.dumps(err),
                    })

            messages.append({
                "role": "assistant",
                "content": response.content,
                "tool_calls": [
                    {
                        "id": tc.id, "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    }
                    for tc in response.tool_calls
                ],
            })
            messages.extend(tool_results)

        return AgentResult.fail(
            context,
            errors=[f"LLM risk_quant agent reached max_iterations ({max_iter}) without conclusion."],
        )


# Avoid F401
from zak.core.tools.substrate import ToolExecutor  # noqa: E402
