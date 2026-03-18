"""
Slopsquatting Detector — ZAK Supply Chain Agent.

Detects AI-hallucinated package names (slopsquatting) by scanning source code
imports and verifying them against real package registries (PyPI, npm).
"""

from __future__ import annotations

from typing import Any

from zak.core.runtime.agent import AgentContext
from zak.core.runtime.llm_agent import LLMAgent
from zak.core.runtime.registry import register_agent
from zak.core.tools.builtins import read_local_code_file

from .tools import check_npm_package, check_pypi_package, extract_imports


@register_agent(
    domain="supply_chain",
    description="Detects slopsquatting: AI-hallucinated package names that attackers pre-register",
    version="1.0.0",
    edition="open-source",
)
class SlopsquattingDetectorAgent(LLMAgent):
    """
    Slopsquatting Detector

    Uses an LLM to scan source code files, extract import statements, and verify
    every package against the real npm/PyPI registries. Flags packages that don't
    exist or were recently created (suspicious registration).
    """

    def system_prompt(self, context: AgentContext) -> str:
        """Returns the system prompt for the slopsquatting detector."""
        target_file = context.metadata.get("target_file", "demo/slopsquatting-demo.py")

        return f"""You are a Supply Chain Security Analyst for tenant '{context.tenant_id}'.

Your goal: Detect phantom/hallucinated package imports (slopsquatting) in AI-generated code by verifying every imported package against real package registries.

Target File: {target_file}

Follow this sequence:
1. Call `read_local_code_file` with the path '{target_file}' to read the source code.
2. Call `extract_imports` with the file content to get all imported package names and the detected language.
3. For each extracted package, verify it exists on the appropriate registry:
   - If language is "python": call `check_pypi_package` for each package name.
   - If language is "javascript" or "typescript": call `check_npm_package` for each package name.
4. Output a structured JSON response containing:
   - `file_scanned`: the file path that was analyzed
   - `language`: detected language (python, javascript, typescript)
   - `total_imports`: total number of unique packages found
   - `phantom_packages`: list of packages that DO NOT exist on the registry
   - `suspicious_packages`: list of packages that exist but were created less than 30 days ago
   - `verified_packages`: list of packages confirmed to exist and are well-established
   - `risk_assessment`: "critical" if any phantom packages found, "warning" if only suspicious, "clean" if all verified
   - `summary`: brief human-readable summary of findings

IMPORTANT: You MUST output ONLY raw JSON. Do not include markdown blocks like ```json.
Be thorough — check EVERY imported package, not just a sample."""

    @property
    def tools(self) -> list[Any]:
        """Provides the list of allowed tools for this agent."""
        return [read_local_code_file, extract_imports, check_pypi_package, check_npm_package]
