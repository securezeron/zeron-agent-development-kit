"""
Tests for the Risk Scenario Generator Agent — tools, validation, and agent execution.
"""

import json

import yaml
import pytest

from zak.core.dsl.schema import AgentDSL
from zak.core.runtime.agent import AgentContext, AgentResult
from zak.core.tools.substrate import ToolRegistry

# Import tools to trigger @zak_tool registration
import zak.agents.risk_scenario.tools as scenario_tools  # noqa: F401
from zak.agents.risk_scenario.tools import (
    generate_crml_scenario,
    validate_crml_scenario,
)
from zak.agents.risk_scenario.agent import RiskScenarioAgent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

RISK_SCENARIO_YAML = """
agent:
  id: risk-scenario-test
  name: "Risk Scenario Test Agent"
  domain: risk_scenario
  version: "1.0.0"

intent:
  goal: "Generate CRML risk scenarios for a target domain"

reasoning:
  mode: deterministic
  autonomy_level: bounded

capabilities:
  tools:
    - fetch_domain_intel
    - generate_crml_scenario
    - validate_crml_scenario

boundaries:
  risk_budget: low
  allowed_actions:
    - agent_execute
    - fetch_domain_intel
    - generate_crml_scenario
    - validate_crml_scenario

safety:
  sandbox_profile: standard
  audit_level: standard
"""


def make_context(
    yaml_str: str = RISK_SCENARIO_YAML,
    metadata: dict | None = None,
) -> AgentContext:
    dsl = AgentDSL.model_validate(yaml.safe_load(yaml_str))
    return AgentContext(
        tenant_id="test-tenant",
        trace_id="trace-riskscen-001",
        dsl=dsl,
        environment="staging",
        metadata=metadata or {"target_domain": "example.com"},
    )


# ---------------------------------------------------------------------------
# Tests: Tool Registration
# ---------------------------------------------------------------------------


class TestToolRegistration:
    def test_fetch_domain_intel_registered(self) -> None:
        assert ToolRegistry.get().is_registered("fetch_domain_intel")

    def test_generate_crml_scenario_registered(self) -> None:
        assert ToolRegistry.get().is_registered("generate_crml_scenario")

    def test_validate_crml_scenario_registered(self) -> None:
        assert ToolRegistry.get().is_registered("validate_crml_scenario")


# ---------------------------------------------------------------------------
# Tests: generate_crml_scenario tool
# ---------------------------------------------------------------------------


class TestGenerateCRMLScenario:
    def setup_method(self):
        self.ctx = make_context()

    def test_basic_poisson_lognormal(self) -> None:
        result = generate_crml_scenario(
            context=self.ctx,
            name="test-data-breach",
            description="Test data breach scenario",
            frequency_model="poisson",
            frequency_lambda=0.05,
            severity_model="lognormal",
            severity_median="100 000",
            severity_sigma=1.2,
        )
        assert "yaml" in result
        assert result["scenario_name"] == "test-data-breach"

        doc = yaml.safe_load(result["yaml"])
        assert doc["crml_scenario"] == "1.0"
        assert doc["meta"]["name"] == "test-data-breach"
        assert doc["scenario"]["frequency"]["model"] == "poisson"
        assert doc["scenario"]["frequency"]["parameters"]["lambda"] == 0.05
        assert doc["scenario"]["severity"]["model"] == "lognormal"
        assert doc["scenario"]["severity"]["parameters"]["sigma"] == 1.2

    def test_hierarchical_gamma_poisson(self) -> None:
        result = generate_crml_scenario(
            context=self.ctx,
            name="test-qber-model",
            description="QBER-style Bayesian model",
            frequency_model="hierarchical_gamma_poisson",
            frequency_lambda=0.0,  # not used for this model
            frequency_alpha_base=2.0,
            frequency_beta_base=1.5,
            severity_model="lognormal",
            severity_median="250 000",
            severity_sigma=1.5,
        )
        doc = yaml.safe_load(result["yaml"])
        freq = doc["scenario"]["frequency"]
        assert freq["model"] == "hierarchical_gamma_poisson"
        assert freq["parameters"]["alpha_base"] == 2.0
        assert freq["parameters"]["beta_base"] == 1.5

    def test_mixture_severity(self) -> None:
        components = [
            {"lognormal": {"weight": 0.7, "median": "200 000", "sigma": 1.2, "currency": "USD"}},
            {"gamma": {"weight": 0.3, "shape": 2.5, "scale": "10 000", "currency": "USD"}},
        ]
        result = generate_crml_scenario(
            context=self.ctx,
            name="test-mixture",
            description="Mixture severity model",
            frequency_model="poisson",
            frequency_lambda=0.1,
            severity_model="mixture",
            severity_median="200 000",
            severity_sigma=1.2,
            severity_components_json=json.dumps(components),
        )
        doc = yaml.safe_load(result["yaml"])
        assert doc["scenario"]["severity"]["model"] == "mixture"
        assert len(doc["scenario"]["severity"]["components"]) == 2

    def test_with_controls(self) -> None:
        controls = [
            {"id": "org:iam.mfa", "effectiveness_against_threat": 0.85},
            {"id": "org:email.dmarc", "effectiveness_against_threat": 0.55},
        ]
        result = generate_crml_scenario(
            context=self.ctx,
            name="test-with-controls",
            description="Scenario with controls",
            frequency_model="poisson",
            frequency_lambda=0.4,
            severity_model="lognormal",
            severity_median="25 000",
            severity_sigma=1.15,
            controls_json=json.dumps(controls),
        )
        doc = yaml.safe_load(result["yaml"])
        assert len(doc["scenario"]["controls"]) == 2
        assert doc["scenario"]["controls"][0]["id"] == "org:iam.mfa"
        assert doc["scenario"]["controls"][0]["effectiveness_against_threat"] == 0.85

    def test_tags_and_metadata(self) -> None:
        result = generate_crml_scenario(
            context=self.ctx,
            name="test-meta",
            description="Test metadata",
            frequency_model="poisson",
            frequency_lambda=0.1,
            severity_model="lognormal",
            severity_median="50 000",
            severity_sigma=1.0,
            tags="ransomware,encryption",
            company_size="enterprise,large-enterprise",
            industries="healthcare,finance",
            author="Test Author",
        )
        doc = yaml.safe_load(result["yaml"])
        assert doc["meta"]["tags"] == ["ransomware", "encryption"]
        assert doc["meta"]["company_size"] == ["enterprise", "large-enterprise"]
        assert doc["meta"]["industries"] == ["healthcare", "finance"]
        assert doc["meta"]["author"] == "Test Author"

    def test_per_asset_unit_basis(self) -> None:
        result = generate_crml_scenario(
            context=self.ctx,
            name="test-per-asset",
            description="Per-asset-unit basis",
            frequency_model="poisson",
            frequency_lambda=0.01,
            severity_model="lognormal",
            severity_median="50 000",
            severity_sigma=1.0,
            frequency_basis="per_asset_unit_per_year",
        )
        doc = yaml.safe_load(result["yaml"])
        assert doc["scenario"]["frequency"]["basis"] == "per_asset_unit_per_year"

    def test_default_mixture_components_when_json_invalid(self) -> None:
        result = generate_crml_scenario(
            context=self.ctx,
            name="test-bad-mixture-json",
            description="Bad JSON falls back to defaults",
            frequency_model="poisson",
            frequency_lambda=0.1,
            severity_model="mixture",
            severity_median="100 000",
            severity_sigma=1.0,
            severity_components_json="NOT VALID JSON",
        )
        doc = yaml.safe_load(result["yaml"])
        assert doc["scenario"]["severity"]["model"] == "mixture"
        # Should fall back to default components
        assert len(doc["scenario"]["severity"]["components"]) == 2

    def test_gamma_severity_model(self) -> None:
        result = generate_crml_scenario(
            context=self.ctx,
            name="test-gamma-severity",
            description="Gamma severity model",
            frequency_model="poisson",
            frequency_lambda=0.05,
            severity_model="gamma",
            severity_median="50 000",
            severity_sigma=2.5,
        )
        doc = yaml.safe_load(result["yaml"])
        sev = doc["scenario"]["severity"]
        assert sev["model"] == "gamma"
        assert sev["parameters"]["shape"] == 2.5
        assert sev["parameters"]["scale"] == "50 000"


# ---------------------------------------------------------------------------
# Tests: validate_crml_scenario tool
# ---------------------------------------------------------------------------


class TestValidateCRMLScenario:
    def setup_method(self):
        self.ctx = make_context()

    def test_valid_simple_scenario(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test-scenario"
scenario:
  frequency:
    basis: per_organization_per_year
    model: poisson
    parameters:
      lambda: 0.05
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: 1.2
      currency: USD
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_missing_crml_scenario_version(self) -> None:
        yaml_str = """
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.05
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: 1.0
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("crml_scenario" in e for e in result["errors"])

    def test_missing_scenario_block(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("scenario" in e.lower() for e in result["errors"])

    def test_missing_meta_name(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta: {}
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.1
  severity:
    model: lognormal
    parameters:
      median: "50 000"
      sigma: 1.0
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("meta.name" in e for e in result["errors"])

    def test_invalid_frequency_model(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: exponential
    parameters:
      rate: 0.1
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: 1.0
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("frequency model" in e.lower() for e in result["errors"])

    def test_missing_poisson_lambda(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters: {}
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: 1.0
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("lambda" in e.lower() for e in result["errors"])

    def test_negative_lambda_rejected(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: -0.5
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: 1.0
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("non-negative" in e.lower() for e in result["errors"])

    def test_high_lambda_warning(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 150
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: 1.0
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is True  # Warning, not error
        assert any("unusually high" in w.lower() for w in result["warnings"])

    def test_missing_lognormal_sigma(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.1
  severity:
    model: lognormal
    parameters:
      median: "100 000"
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("sigma" in e.lower() for e in result["errors"])

    def test_missing_lognormal_median_and_mu(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.1
  severity:
    model: lognormal
    parameters:
      sigma: 1.0
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("median" in e.lower() or "mu" in e.lower() for e in result["errors"])

    def test_invalid_severity_model(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.1
  severity:
    model: exponential
    parameters:
      rate: 0.01
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("severity model" in e.lower() for e in result["errors"])

    def test_invalid_control_id_attck_prefix(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.1
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: 1.0
  controls:
    - id: "attck:T1566"
      effectiveness_against_threat: 0.5
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("attck:" in e for e in result["errors"])

    def test_control_effectiveness_out_of_range(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.1
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: 1.0
  controls:
    - id: "org:iam.mfa"
      effectiveness_against_threat: 1.5
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("0.0-1.0" in e for e in result["errors"])

    def test_mixture_empty_components(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.1
  severity:
    model: mixture
    parameters: {}
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("component" in e.lower() for e in result["errors"])

    def test_mixture_weights_warning(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.1
  severity:
    model: mixture
    parameters: {}
    components:
      - lognormal:
          weight: 0.5
          median: "100 000"
          sigma: 1.0
      - gamma:
          weight: 0.3
          shape: 2.0
          scale: 5000
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is True  # Valid but warning about weights
        assert any("weights sum" in w.lower() for w in result["warnings"])

    def test_hierarchical_missing_alpha(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: hierarchical_gamma_poisson
    parameters:
      beta_base: 1.5
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: 1.0
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("alpha_base" in e for e in result["errors"])

    def test_invalid_yaml(self) -> None:
        result = validate_crml_scenario(context=self.ctx, yaml_content=": : invalid [yaml")
        assert result["valid"] is False
        assert any("parse error" in e.lower() for e in result["errors"])

    def test_invalid_frequency_basis(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    basis: per_employee_per_year
    model: poisson
    parameters:
      lambda: 0.1
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: 1.0
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("basis" in e.lower() for e in result["errors"])

    def test_using_mu_instead_of_median(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.8
  severity:
    model: lognormal
    parameters:
      mu: 10.0
      sigma: 1.2
      currency: USD
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is True

    def test_negative_sigma_rejected(self) -> None:
        yaml_str = """
crml_scenario: "1.0"
meta:
  name: "test"
scenario:
  frequency:
    model: poisson
    parameters:
      lambda: 0.1
  severity:
    model: lognormal
    parameters:
      median: "100 000"
      sigma: -0.5
"""
        result = validate_crml_scenario(context=self.ctx, yaml_content=yaml_str)
        assert result["valid"] is False
        assert any("sigma" in e.lower() for e in result["errors"])


# ---------------------------------------------------------------------------
# Tests: Roundtrip — generate then validate
# ---------------------------------------------------------------------------


class TestRoundtrip:
    def setup_method(self):
        self.ctx = make_context()

    def test_generated_poisson_lognormal_validates(self) -> None:
        result = generate_crml_scenario(
            context=self.ctx,
            name="roundtrip-test",
            description="Roundtrip validation test",
            frequency_model="poisson",
            frequency_lambda=0.1,
            severity_model="lognormal",
            severity_median="250 000",
            severity_sigma=1.5,
            tags="test,roundtrip",
        )
        validation = validate_crml_scenario(context=self.ctx, yaml_content=result["yaml"])
        assert validation["valid"] is True, f"Validation failed: {validation['errors']}"

    def test_generated_hierarchical_mixture_validates(self) -> None:
        components = [
            {"lognormal": {"weight": 0.7, "median": "200 000", "sigma": 1.2, "currency": "USD"}},
            {"gamma": {"weight": 0.3, "shape": 2.5, "scale": "10 000", "currency": "USD"}},
        ]
        result = generate_crml_scenario(
            context=self.ctx,
            name="roundtrip-qber",
            description="QBER roundtrip test",
            frequency_model="hierarchical_gamma_poisson",
            frequency_lambda=0.0,
            frequency_alpha_base=2.0,
            frequency_beta_base=1.5,
            severity_model="mixture",
            severity_median="200 000",
            severity_sigma=1.2,
            severity_components_json=json.dumps(components),
        )
        validation = validate_crml_scenario(context=self.ctx, yaml_content=result["yaml"])
        assert validation["valid"] is True, f"Validation failed: {validation['errors']}"

    def test_generated_with_controls_validates(self) -> None:
        controls = [
            {"id": "org:iam.mfa", "effectiveness_against_threat": 0.85},
            {"id": "org:net.firewall", "effectiveness_against_threat": 0.6},
            {"id": "org:email.dmarc", "effectiveness_against_threat": 0.55},
        ]
        result = generate_crml_scenario(
            context=self.ctx,
            name="roundtrip-controls",
            description="Roundtrip with controls",
            frequency_model="poisson",
            frequency_lambda=0.4,
            severity_model="lognormal",
            severity_median="25 000",
            severity_sigma=1.15,
            controls_json=json.dumps(controls),
        )
        validation = validate_crml_scenario(context=self.ctx, yaml_content=result["yaml"])
        assert validation["valid"] is True, f"Validation failed: {validation['errors']}"


# ---------------------------------------------------------------------------
# Tests: Agent Registration
# ---------------------------------------------------------------------------


class TestAgentRegistration:
    def test_risk_scenario_agent_importable(self) -> None:
        from zak.agents.risk_scenario.agent import RiskScenarioAgent
        assert RiskScenarioAgent is not None

    def test_domain_attribute(self) -> None:
        assert RiskScenarioAgent._zak_domain == "risk_scenario"

    def test_edition_open_source(self) -> None:
        assert RiskScenarioAgent._zak_edition == "open-source"

    def test_version(self) -> None:
        assert RiskScenarioAgent._zak_version == "1.0.0"


# ---------------------------------------------------------------------------
# Tests: DSL Validation
# ---------------------------------------------------------------------------


class TestDSLValidation:
    def test_risk_scenario_yaml_validates(self) -> None:
        yaml_str = """
agent:
  id: risk-scenario-gen-v1
  name: "Risk Scenario Generator Agent"
  domain: risk_scenario
  version: "1.0.0"

intent:
  goal: "Generate CRML risk scenarios"

reasoning:
  mode: llm_react
  autonomy_level: bounded
  confidence_threshold: 0.75
  llm:
    provider: openai
    model: gpt-4o
    temperature: 0.3
    max_iterations: 15

capabilities:
  tools:
    - fetch_domain_intel
    - generate_crml_scenario
    - validate_crml_scenario

boundaries:
  risk_budget: low
  allowed_actions:
    - agent_execute
    - fetch_domain_intel
    - generate_crml_scenario
    - validate_crml_scenario

safety:
  sandbox_profile: standard
  audit_level: standard
"""
        dsl = AgentDSL.model_validate(yaml.safe_load(yaml_str))
        assert dsl.agent.domain == "risk_scenario"
        assert dsl.reasoning.mode.value == "llm_react"

    def test_deterministic_mode_validates(self) -> None:
        dsl = AgentDSL.model_validate(yaml.safe_load(RISK_SCENARIO_YAML))
        assert dsl.agent.domain == "risk_scenario"
        assert dsl.reasoning.mode.value == "deterministic"


# ---------------------------------------------------------------------------
# Tests: CRML Spec Compliance
# ---------------------------------------------------------------------------


class TestCRMLSpecCompliance:
    """Verify generated scenarios conform to actual CRML spec patterns."""

    def setup_method(self):
        self.ctx = make_context()

    def test_matches_crml_data_breach_simple_pattern(self) -> None:
        """Generated scenario should match the structure of examples/scenarios/data-breach-simple.yaml."""
        result = generate_crml_scenario(
            context=self.ctx,
            name="data-breach-simple",
            description="Simple data breach risk model for beginners",
            frequency_model="poisson",
            frequency_lambda=0.05,
            severity_model="lognormal",
            severity_median="100 000",
            severity_sigma=1.2,
            severity_currency="USD",
            tags="data-breach,beginner,pii",
            company_size="smb",
            industries="all",
        )
        doc = yaml.safe_load(result["yaml"])

        # Structural match with CRML examples
        assert doc["crml_scenario"] == "1.0"
        assert "meta" in doc
        assert "scenario" in doc
        assert "frequency" in doc["scenario"]
        assert "severity" in doc["scenario"]
        assert doc["scenario"]["frequency"]["basis"] == "per_organization_per_year"
        assert doc["scenario"]["severity"]["parameters"]["currency"] == "USD"

    def test_matches_crml_ransomware_pattern(self) -> None:
        """Generated scenario should match ransomware-scenario.yaml patterns."""
        result = generate_crml_scenario(
            context=self.ctx,
            name="ransomware-scenario",
            description="Real-world ransomware risk model based on industry statistics",
            frequency_model="poisson",
            frequency_lambda=0.08,
            severity_model="lognormal",
            severity_median="700 000",
            severity_sigma=1.8,
            severity_currency="USD",
            tags="ransomware,extortion",
            company_size="enterprise,large-enterprise",
        )
        doc = yaml.safe_load(result["yaml"])

        assert doc["scenario"]["frequency"]["parameters"]["lambda"] == 0.08
        assert doc["scenario"]["severity"]["parameters"]["median"] == "700 000"
        assert doc["scenario"]["severity"]["parameters"]["sigma"] == 1.8

    def test_matches_crml_qber_simplified_pattern(self) -> None:
        """Generated QBER scenario should match qber-simplified.yaml patterns."""
        components = [
            {"lognormal": {"weight": 0.7, "median": "162 755", "currency": "USD", "sigma": 1.2}},
            {"gamma": {"weight": 0.3, "shape": 2.5, "scale": 10000, "currency": "USD"}},
        ]
        result = generate_crml_scenario(
            context=self.ctx,
            name="qber-simplified",
            description="Simplified QBER-style model",
            frequency_model="hierarchical_gamma_poisson",
            frequency_lambda=0.0,
            frequency_alpha_base=1.5,
            frequency_beta_base=1.5,
            severity_model="mixture",
            severity_median="162 755",
            severity_sigma=1.2,
            severity_components_json=json.dumps(components),
            tags="qber,bayesian",
            company_size="enterprise,large-enterprise",
        )
        doc = yaml.safe_load(result["yaml"])

        assert doc["scenario"]["frequency"]["model"] == "hierarchical_gamma_poisson"
        assert doc["scenario"]["severity"]["model"] == "mixture"
        assert len(doc["scenario"]["severity"]["components"]) == 2
