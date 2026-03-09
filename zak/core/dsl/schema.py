"""
ZAK Core DSL — Pydantic v2 schema models for the Universal Security Agent DSL (US-ADSL).

Every agent definition is a YAML file that validates against these models.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Domain(str, Enum):
    """Supported security agent domains."""
    RED_TEAM        = "red_team"
    APPSEC          = "appsec"
    AI_SECURITY     = "ai_security"
    RISK_QUANT      = "risk_quant"
    SUPPLY_CHAIN    = "supply_chain"
    COMPLIANCE      = "compliance"
    # Enterprise domains
    API_SECURITY    = "api_security"
    ATTACK_SURFACE  = "attack_surface"
    CLOUD_POSTURE   = "cloud_posture"
    CONTAINER_SECURITY = "container_security"
    CYBER_INSURANCE = "cyber_insurance"
    DATA_PRIVACY    = "data_privacy"
    IAC_SECURITY    = "iac_security"
    IAM_DRIFT       = "iam_drift"
    IDENTITY_RISK   = "identity_risk"
    INCIDENT_RESPONSE = "incident_response"
    MALWARE_ANALYSIS = "malware_analysis"
    NETWORK_SECURITY = "network_security"
    PENTEST_AUTO    = "pentest_auto"
    THREAT_DETECTION = "threat_detection"
    THREAT_INTEL    = "threat_intel"
    VULN_TRIAGE     = "vuln_triage"
    USAGE_METRICS   = "usage_metrics"


class ReasoningMode(str, Enum):
    """How the agent reasons and makes decisions."""
    DETERMINISTIC = "deterministic"
    RULE_BASED = "rule_based"
    LLM_ASSISTED = "llm_assisted"
    HYBRID = "hybrid"
    PROBABILISTIC = "probabilistic"
    LLM_REACT = "llm_react"   # Full ReAct loop — LLM perceives, reasons, acts, observes


class AutonomyLevel(str, Enum):
    """How much autonomous action the agent is permitted to take."""
    OBSERVE = "observe"
    SUGGEST = "suggest"
    BOUNDED = "bounded"
    HIGH = "high"
    FULLY_AUTONOMOUS = "fully_autonomous"


class Priority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskBudget(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SandboxProfile(str, Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"
    OFFENSIVE_ISOLATED = "offensive_isolated"


class AuditLevel(str, Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    VERBOSE = "verbose"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class AgentIdentity(BaseModel):
    """Identifies the agent uniquely within the platform."""
    id: str = Field(..., description="Unique agent identifier (slug format)")
    name: str = Field(..., description="Human-readable agent name")
    domain: Domain = Field(..., description="Security domain this agent operates in")
    version: str = Field(..., description="Semantic version string (e.g. 1.0.0)")

    @field_validator("id")
    @classmethod
    def id_must_be_slug(cls, v: str) -> str:
        import re
        if not re.match(r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$", v):
            raise ValueError(
                f"Agent id '{v}' must be lowercase alphanumeric with hyphens only "
                "(e.g. 'risk-quant-v1')"
            )
        return v

    @field_validator("version")
    @classmethod
    def version_must_be_semver(cls, v: str) -> str:
        import re
        if not re.match(r"^\d+\.\d+\.\d+$", v):
            raise ValueError(f"Version '{v}' must be semver format (e.g. '1.0.0')")
        return v


class AgentIntent(BaseModel):
    """Describes what the agent is trying to achieve."""
    goal: str = Field(..., description="Clear description of the agent's objective")
    success_criteria: list[str] = Field(
        default_factory=list,
        description="Measurable conditions for mission success",
    )
    priority: Priority = Field(Priority.MEDIUM, description="Execution priority")


class LLMConfig(BaseModel):
    """LLM provider configuration — used when reasoning.mode = llm_react."""
    provider: str = Field(
        "openai",
        description="LLM provider: openai | anthropic | google | local",
    )
    model: str = Field(
        "gpt-4o",
        description="Model name (e.g. gpt-4o, claude-opus-4-5, gemini-1.5-pro, llama3.1:70b)",
    )
    temperature: float = Field(
        0.2,
        ge=0.0,
        le=2.0,
        description="Sampling temperature — 0.0 = deterministic, 1.0 = creative",
    )
    max_iterations: int = Field(
        10,
        ge=1,
        le=50,
        description="Maximum ReAct loop iterations before the agent is forced to stop",
    )
    max_tokens: int = Field(
        4096,
        ge=256,
        le=32768,
        description="Maximum tokens per LLM response",
    )


class ReasoningConfig(BaseModel):
    """Controls how the agent thinks and decides."""
    mode: ReasoningMode = Field(..., description="Reasoning strategy")
    autonomy_level: AutonomyLevel = Field(
        AutonomyLevel.BOUNDED, description="Degree of autonomous action permitted"
    )
    confidence_threshold: float = Field(
        0.75,
        ge=0.0,
        le=1.0,
        description="Minimum confidence required before acting (0.0–1.0)",
    )
    llm: Optional[LLMConfig] = Field(
        None,
        description="LLM provider settings — required when mode is llm_react",
    )


class CapabilitiesConfig(BaseModel):
    """What the agent is allowed to use/access."""
    tools: list[str] = Field(
        default_factory=list,
        description="Registered tool names the agent may call",
    )
    data_access: list[str] = Field(
        default_factory=list,
        description="Data sources the agent may read",
    )
    graph_access: list[str] = Field(
        default_factory=list,
        description="SIF graph node types the agent may query",
    )


class BoundariesConfig(BaseModel):
    """Hard constraints on agent behaviour."""
    risk_budget: RiskBudget = Field(
        RiskBudget.MEDIUM,
        description="Maximum acceptable risk level for autonomous actions",
    )
    allowed_actions: list[str] = Field(
        default_factory=list,
        description="Explicit allow-list of action identifiers",
    )
    denied_actions: list[str] = Field(
        default_factory=list,
        description="Explicit deny-list of action identifiers (takes precedence over allowed)",
    )
    environment_scope: list[str] = Field(
        default_factory=list,
        description="Environments the agent may operate in (e.g. production, staging, dev)",
    )
    approval_gates: list[str] = Field(
        default_factory=list,
        description="Actions requiring explicit human approval before execution",
    )

    @model_validator(mode="after")
    def no_overlap_in_allow_deny(self) -> BoundariesConfig:
        overlap = set(self.allowed_actions) & set(self.denied_actions)
        if overlap:
            raise ValueError(
                f"Actions {overlap} appear in both allowed_actions and denied_actions. "
                "Denied actions always take precedence — remove them from allowed_actions."
            )
        return self


class SafetyConfig(BaseModel):
    """Safety guardrails applied to every execution."""
    guardrails: list[str] = Field(
        default_factory=list,
        description="Named guardrail policies to enforce",
    )
    sandbox_profile: SandboxProfile = Field(
        SandboxProfile.STANDARD,
        description="Execution sandboxing profile",
    )
    audit_level: AuditLevel = Field(
        AuditLevel.STANDARD,
        description="Verbosity of the audit trail",
    )


# ---------------------------------------------------------------------------
# Top-level AgentDSL model
# ---------------------------------------------------------------------------


class AgentDSL(BaseModel):
    """
    The complete validated representation of a US-ADSL agent definition.

    Parsed from YAML by zak.core.dsl.parser.load_agent_yaml().
    """
    agent: AgentIdentity
    intent: AgentIntent
    reasoning: ReasoningConfig
    capabilities: CapabilitiesConfig = Field(default_factory=CapabilitiesConfig)
    boundaries: BoundariesConfig = Field(default_factory=BoundariesConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)

    @model_validator(mode="after")
    def offensive_agents_require_isolated_sandbox(self) -> AgentDSL:
        if self.agent.domain == Domain.RED_TEAM:
            if self.safety.sandbox_profile != SandboxProfile.OFFENSIVE_ISOLATED:
                raise ValueError(
                    "Red team agents MUST use sandbox_profile: offensive_isolated. "
                    "Safety requirement cannot be overridden."
                )
            if self.safety.audit_level != AuditLevel.VERBOSE:
                raise ValueError(
                    "Red team agents MUST use audit_level: verbose. "
                    "Safety requirement cannot be overridden."
                )
        return self

    @model_validator(mode="after")
    def llm_react_requires_llm_config(self) -> AgentDSL:
        if self.reasoning.mode == ReasoningMode.LLM_REACT:
            if self.reasoning.llm is None:
                # Auto-populate with defaults so the field is never missing
                self.reasoning = self.reasoning.model_copy(
                    update={"llm": LLMConfig()}
                )
        return self

    @model_validator(mode="after")
    def fully_autonomous_requires_high_confidence(self) -> AgentDSL:
        if self.reasoning.autonomy_level == AutonomyLevel.FULLY_AUTONOMOUS:
            if self.reasoning.confidence_threshold < 0.9:
                raise ValueError(
                    "fully_autonomous autonomy level requires confidence_threshold >= 0.9"
                )
        return self
