"""
Risk Scenario Generator Agent — ZAK reference implementation.

Takes a domain as input and generates CRML (Cyber Risk Modeling Language) cyber
risk scenarios for the company associated with that domain.

Uses the CRML specification (https://github.com/Faux16/crml) to produce
schema-valid scenario YAML documents with calibrated frequency and severity
parameters based on publicly available domain intelligence.

Supports two CRML modeling styles:
  - FAIR-style:  Poisson frequency + Lognormal severity (simpler, expert-driven)
  - QBER-style:  Hierarchical Gamma-Poisson + Mixture severity (Bayesian, enterprise)

Execution modes:
  reasoning.mode: llm_react   (recommended — LLM analyses domain and generates scenarios)
  reasoning.mode: deterministic (generates a basic data-breach scenario from domain info)
"""

from __future__ import annotations

from typing import Any

from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.registry import register_agent
from zak.agents.risk_scenario.tools import (
    fetch_domain_intel,
    generate_crml_scenario,
    validate_crml_scenario,
)


@register_agent(
    domain="risk_scenario",
    description=(
        "Generates CRML cyber risk scenarios for a target domain. "
        "Performs domain reconnaissance, identifies industry and threat profile, "
        "then produces calibrated CRML scenario YAML documents using FAIR or QBER models."
    ),
    version="1.0.0",
    edition="open-source",
)
class RiskScenarioAgent(BaseAgent):
    """
    Generates CRML cyber risk scenarios from domain intelligence.

    In LLM mode, the agent follows this tool sequence:
        1. fetch_domain_intel    -> gather company/domain context
        2. generate_crml_scenario -> produce CRML YAML for each identified risk
        3. validate_crml_scenario -> verify CRML schema compliance
        4. STOP + summarize       -> return scenarios + risk narrative

    In deterministic mode, produces a baseline data-breach scenario
    using conservative industry-average parameters.
    """

    def execute(self, context: AgentContext) -> AgentResult:
        from zak.core.dsl.schema import ReasoningMode

        if context.dsl.reasoning.mode == ReasoningMode.LLM_REACT:
            return self._execute_llm(context)
        return self._execute_deterministic(context)

    # ── LLM-powered execution ───────────────────────────────────────────

    def _execute_llm(self, context: AgentContext) -> AgentResult:
        """Full LLM ReAct loop for intelligent scenario generation."""
        agent = _LLMRiskScenarioAgent()
        return agent.execute(context)

    # ── Deterministic fallback ──────────────────────────────────────────

    def _execute_deterministic(self, context: AgentContext) -> AgentResult:
        """
        Generate a baseline CRML scenario using conservative defaults.

        Fetches domain intelligence, then produces a single data-breach
        scenario with industry-average FAIR parameters.
        """
        from zak.core.tools.substrate import ToolExecutor

        target_domain = context.metadata.get("target_domain", "")
        if not target_domain:
            return AgentResult.fail(
                context,
                errors=["No target_domain provided in agent metadata."],
            )

        # Step 1: Gather domain intel
        try:
            intel = ToolExecutor.call(
                fetch_domain_intel, context=context, domain=target_domain
            )
        except Exception as exc:
            intel = {"domain": target_domain, "error": str(exc), "page_text": ""}

        domain_name = intel.get("domain", target_domain)
        has_hsts = "strict-transport-security" in str(intel.get("http_headers", {})).lower()

        # Step 2: Generate a conservative data-breach scenario
        scenario_result = ToolExecutor.call(
            generate_crml_scenario,
            context=context,
            name=f"{domain_name}-data-breach",
            description=f"Baseline data breach risk scenario for {domain_name}",
            frequency_model="poisson",
            frequency_lambda=0.05,
            severity_model="lognormal",
            severity_median="100 000",
            severity_sigma=1.2,
            severity_currency="USD",
            tags="data-breach,baseline",
            controls_json=(
                '[{"id": "org:iam.mfa", "effectiveness_against_threat": 0.85}]'
                if has_hsts else "[]"
            ),
        )

        # Step 3: Validate
        validation = ToolExecutor.call(
            validate_crml_scenario,
            context=context,
            yaml_content=scenario_result["yaml"],
        )

        return AgentResult.ok(
            context,
            output={
                "domain": domain_name,
                "scenarios_generated": 1,
                "scenarios": [
                    {
                        "name": scenario_result["scenario_name"],
                        "yaml": scenario_result["yaml"],
                        "validation": validation,
                    }
                ],
                "domain_intel": {
                    "domain": domain_name,
                    "has_hsts": has_hsts,
                    "headers_found": list(intel.get("http_headers", {}).keys()),
                },
            },
        )


# ---------------------------------------------------------------------------
# LLM-powered implementation
# ---------------------------------------------------------------------------

class _LLMRiskScenarioAgent:
    """
    Internal LLM-powered risk scenario generator using the ReAct loop.

    Not registered in AgentRegistry — accessed only through RiskScenarioAgent
    when reasoning.mode == llm_react.

    The LLM follows this sequence:
        1. fetch_domain_intel        -> understand the target company
        2. generate_crml_scenario    -> create 3-5 tailored risk scenarios
        3. validate_crml_scenario    -> verify each scenario is schema-valid
        4. STOP + summarize          -> produce structured output
    """

    def execute(self, context: AgentContext) -> AgentResult:
        from zak.core.llm.registry import get_llm_client
        from zak.core.runtime.llm_agent import _build_openai_schema
        from zak.core.tools.substrate import ToolExecutor
        import json

        target_domain = context.metadata.get("target_domain", "unknown.com")

        available_tools = [fetch_domain_intel, generate_crml_scenario, validate_crml_scenario]
        tools_schema = _build_openai_schema(available_tools)

        # LLM config from DSL
        llm_cfg: dict[str, Any] = {}
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
        temperature = float(llm_cfg.get("temperature", 0.3))
        max_tokens = int(llm_cfg.get("max_tokens", 8192))
        max_iter = int(llm_cfg.get("max_iterations", 15))

        system = f"""You are a cyber risk scenario generation agent for tenant '{context.tenant_id}'.

TARGET DOMAIN: {target_domain}

Your goal: Generate realistic, calibrated CRML (Cyber Risk Modeling Language) cyber risk scenarios
for the company behind the domain '{target_domain}'.

CRML SCENARIO FORMAT (crml_scenario "1.0"):
Each scenario has:
- meta: name, description, tags, company_size, industries
- scenario.frequency: how often the threat occurs (poisson or hierarchical_gamma_poisson model)
- scenario.severity: conditional loss per event (lognormal, gamma, or mixture model)
- scenario.controls: optional relevant controls with effectiveness_against_threat (0.0-1.0)

FREQUENCY MODEL GUIDANCE:
- Use 'poisson' with lambda parameter for FAIR-style models
  - lambda = annual probability of occurrence (e.g. 0.05 = 5%/year, 0.15 = 15%/year)
  - Ransomware: lambda 0.05-0.15, Phishing: 0.3-0.8, Data breach: 0.02-0.10
  - Larger companies face higher lambda for most threats
- Use 'hierarchical_gamma_poisson' with alpha_base/beta_base for QBER/Bayesian models

SEVERITY MODEL GUIDANCE:
- Use 'lognormal' with median (human-readable, e.g. "250 000") and sigma (0.8-2.0)
  - sigma < 1.0: low variability | sigma 1.0-1.5: moderate | sigma > 1.5: high variability
  - Ransomware median: $200K-$2M depending on size | Data breach: $50K-$500K
  - Larger companies: higher medians
- Currency should always be specified (default: USD)

CONTROL ID FORMAT:
- Must be namespace:key (e.g. "org:iam.mfa", "org:net.firewall", "org:email.dmarc")
- Must NOT start with "attck:" (reserved)
- effectiveness_against_threat: 0.0-1.0

TOOL SEQUENCE:
1. Call fetch_domain_intel with the target domain to understand the company
2. Based on the intel, determine: industry, company size, likely tech stack, security posture
3. Generate 3-5 CRML scenarios covering different threat types:
   - Ransomware attack
   - Data breach / data exfiltration
   - Phishing / social engineering (leading to credential compromise)
   - Supply chain / third-party risk
   - Business email compromise (BEC)
   Choose scenarios most relevant to the identified industry.
4. For each scenario, call generate_crml_scenario with calibrated parameters
5. Validate each scenario with validate_crml_scenario
6. If validation fails, fix and regenerate

OUTPUT FORMAT (your final response):
Return a JSON object with:
{{
  "domain": "{target_domain}",
  "company_profile": {{
    "industry": "...",
    "estimated_size": "smb|mid-market|enterprise|large-enterprise",
    "security_posture_indicators": ["..."],
    "risk_factors": ["..."]
  }},
  "scenarios_generated": N,
  "scenarios": [
    {{
      "name": "...",
      "threat_type": "ransomware|data_breach|phishing|supply_chain|bec|...",
      "model_style": "fair|qber",
      "crml_yaml": "...",
      "calibration_rationale": "Why these specific parameters were chosen"
    }}
  ],
  "aggregate_risk_narrative": "Brief executive summary of the company's cyber risk profile"
}}

Ground every parameter choice in the domain intelligence you gathered. Do not invent data.
Calibrate parameters to be realistic for the identified industry and company size."""

        messages = [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": (
                    f"Generate cyber risk scenarios for domain '{target_domain}'. "
                    f"Tenant: {context.tenant_id}. Environment: {context.environment}."
                ),
            },
        ]

        reasoning_trace: list[Any] = []
        total_usage: dict[str, Any] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        def resolve(name: str) -> Any:
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
                conclusion = response.content or "Risk scenario generation complete."
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
                "content": response.content or "",
                "tool_calls": [  # type: ignore[dict-item]
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
            errors=[f"LLM risk_scenario agent reached max_iterations ({max_iter}) without conclusion."],
        )
