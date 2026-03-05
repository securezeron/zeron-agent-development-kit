"""
ZAK DSL Parser — loads and validates US-ADSL YAML agent definitions.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from zak.core.dsl.schema import AgentDSL


@dataclass
class ValidationResult:
    """Result of validating an agent YAML definition."""
    valid: bool
    agent_id: str | None = None
    errors: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        if self.valid:
            return f"✅ Valid agent definition: {self.agent_id}"
        lines = [f"❌ Invalid agent definition — {len(self.errors)} error(s):"]
        for i, err in enumerate(self.errors, 1):
            lines.append(f"  {i}. {err}")
        return "\n".join(lines)


def load_agent_yaml(path: str | Path) -> AgentDSL:
    """
    Load and validate a US-ADSL agent YAML file.

    Args:
        path: Path to the YAML file.

    Returns:
        Validated AgentDSL instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
        pydantic.ValidationError: If the YAML does not conform to the schema.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Agent definition not found: {path}")

    with open(path, "r") as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping at root level, got {type(raw).__name__}")

    return AgentDSL.model_validate(raw)


def validate_agent(path: str | Path) -> ValidationResult:
    """
    Validate an agent YAML file and return a structured result.

    Unlike load_agent_yaml(), this never raises — errors are captured in ValidationResult.

    Args:
        path: Path to the YAML file.

    Returns:
        ValidationResult with valid=True or a list of human-readable errors.
    """
    path = Path(path)

    # File existence check
    if not path.exists():
        return ValidationResult(valid=False, errors=[f"File not found: {path}"])

    # YAML parse check
    try:
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return ValidationResult(valid=False, errors=[f"YAML syntax error: {e}"])

    if not isinstance(raw, dict):
        return ValidationResult(
            valid=False,
            errors=[f"Root YAML element must be a mapping, got {type(raw).__name__}"],
        )

    # Schema validation
    try:
        dsl = AgentDSL.model_validate(raw)
        return ValidationResult(valid=True, agent_id=dsl.agent.id)
    except ValidationError as e:
        errors = []
        for err in e.errors():
            loc = " → ".join(str(p) for p in err["loc"])
            errors.append(f"[{loc}] {err['msg']}")
        agent_id = raw.get("agent", {}).get("id") if isinstance(raw, dict) else None
        return ValidationResult(valid=False, agent_id=agent_id, errors=errors)
