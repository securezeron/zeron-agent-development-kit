"""
Tests for the ZAK DSL schema and parser.
"""

import pytest
from pydantic import ValidationError
import yaml
import tempfile
import os

from zak.core.dsl.schema import (
    AgentDSL, AutonomyLevel, Domain, ReasoningMode, SandboxProfile, AuditLevel
)
from zak.core.dsl.parser import load_agent_yaml, validate_agent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_YAML = """
agent:
  id: test-agent-v1
  name: Test Agent
  domain: risk_quant
  version: "1.0.0"

intent:
  goal: "Test goal"
  priority: medium

reasoning:
  mode: deterministic
  autonomy_level: bounded
  confidence_threshold: 0.75

capabilities:
  tools:
    - sif_graph_read

boundaries:
  risk_budget: medium
  allowed_actions:
    - read_asset

safety:
  sandbox_profile: standard
  audit_level: standard
"""

VALID_RED_TEAM_YAML = """
agent:
  id: redteam-v1
  name: Red Team Agent
  domain: red_team
  version: "1.0.0"

intent:
  goal: "Red team testing"

reasoning:
  mode: hybrid
  autonomy_level: bounded

boundaries:
  environment_scope:
    - staging

safety:
  sandbox_profile: offensive_isolated
  audit_level: verbose
"""


def write_temp_yaml(content: str) -> str:
    """Write YAML content to a temp file and return its path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        return f.name


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParser:
    def test_valid_yaml_loads_successfully(self):
        path = write_temp_yaml(VALID_YAML)
        dsl = load_agent_yaml(path)
        assert dsl.agent.id == "test-agent-v1"
        assert dsl.agent.domain == Domain.RISK_QUANT
        os.unlink(path)

    def test_missing_file_raises_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_agent_yaml("/nonexistent/path/agent.yaml")

    def test_invalid_yaml_raises_error(self):
        path = write_temp_yaml("not: valid: yaml: {{{")
        with pytest.raises(Exception):
            load_agent_yaml(path)
        os.unlink(path)

    def test_validate_returns_true_for_valid_yaml(self):
        path = write_temp_yaml(VALID_YAML)
        result = validate_agent(path)
        assert result.valid is True
        assert result.agent_id == "test-agent-v1"
        os.unlink(path)

    def test_validate_returns_false_for_missing_id(self):
        bad = VALID_YAML.replace("id: test-agent-v1", "")
        path = write_temp_yaml(bad)
        result = validate_agent(path)
        assert result.valid is False
        assert len(result.errors) > 0
        os.unlink(path)


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------

class TestSchemaValidation:
    def test_agent_id_must_be_slug(self):
        data = yaml.safe_load(VALID_YAML)
        data["agent"]["id"] = "Invalid ID With Spaces!"
        with pytest.raises(ValidationError) as exc_info:
            AgentDSL.model_validate(data)
        assert "slug" in str(exc_info.value).lower() or "id" in str(exc_info.value).lower()

    def test_version_must_be_semver(self):
        data = yaml.safe_load(VALID_YAML)
        data["agent"]["version"] = "v1.0"
        with pytest.raises(ValidationError):
            AgentDSL.model_validate(data)

    def test_allow_deny_overlap_raises(self):
        data = yaml.safe_load(VALID_YAML)
        data["boundaries"]["allowed_actions"] = ["read_asset", "delete_asset"]
        data["boundaries"]["denied_actions"] = ["delete_asset"]
        with pytest.raises(ValidationError) as exc_info:
            AgentDSL.model_validate(data)
        assert "denied" in str(exc_info.value).lower()

    def test_red_team_requires_offensive_isolated(self):
        data = yaml.safe_load(VALID_RED_TEAM_YAML)
        data["safety"]["sandbox_profile"] = "standard"  # wrong
        with pytest.raises(ValidationError) as exc_info:
            AgentDSL.model_validate(data)
        assert "offensive_isolated" in str(exc_info.value)

    def test_red_team_requires_verbose_audit(self):
        data = yaml.safe_load(VALID_RED_TEAM_YAML)
        data["safety"]["audit_level"] = "minimal"  # wrong
        with pytest.raises(ValidationError) as exc_info:
            AgentDSL.model_validate(data)
        assert "verbose" in str(exc_info.value)

    def test_fully_autonomous_requires_high_confidence(self):
        data = yaml.safe_load(VALID_YAML)
        data["reasoning"]["autonomy_level"] = "fully_autonomous"
        data["reasoning"]["confidence_threshold"] = 0.5  # too low
        with pytest.raises(ValidationError) as exc_info:
            AgentDSL.model_validate(data)
        assert "confidence_threshold" in str(exc_info.value)

    def test_valid_red_team_passes_validation(self):
        data = yaml.safe_load(VALID_RED_TEAM_YAML)
        dsl = AgentDSL.model_validate(data)
        assert dsl.agent.domain == Domain.RED_TEAM
        assert dsl.safety.sandbox_profile == SandboxProfile.OFFENSIVE_ISOLATED
