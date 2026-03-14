"""
ZAK built-in tools — SIF graph read/write tools available to all agents.

These are the platform-level tools that agents declare in capabilities.tools.
Domain-specific tools can be added alongside these in their respective agent packages.
"""

from __future__ import annotations

from typing import Any, Optional

from zak.core.runtime.agent import AgentContext
from zak.core.tools.substrate import zak_tool

import logging

_logger = logging.getLogger(__name__)

# Shared adapter singleton to avoid creating a new connection per tool call.
_shared_adapter: Optional[Any] = None


def _get_adapter() -> Any:
    """Return a shared graph adapter instance, creating it on first call."""
    global _shared_adapter
    if _shared_adapter is None:
        from zak.sif.graph.factory import create_adapter
        _shared_adapter = create_adapter()
    return _shared_adapter


# ---------------------------------------------------------------------------
# SIF Graph Read Tools
# ---------------------------------------------------------------------------

@zak_tool(
    name="read_asset",
    description="Read an asset node from the SIF graph by ID",
    action_id="read_asset",
    tags=["sif", "read", "asset"],
)
def read_asset(context: AgentContext, asset_id: str) -> Optional[dict[str, Any]]:
    """Read a single asset node from the SIF graph."""
    adapter = _get_adapter()
    return adapter.get_node(tenant_id=context.tenant_id, node_type="asset", node_id=asset_id)


@zak_tool(
    name="list_assets",
    description="List all asset nodes in the SIF graph for the current tenant",
    action_id="list_assets",
    tags=["sif", "read", "asset"],
)
def list_assets(context: AgentContext) -> list[dict[str, Any]]:
    """List all assets for the current tenant."""
    adapter = _get_adapter()
    return adapter.get_nodes(tenant_id=context.tenant_id, node_type="asset")


@zak_tool(
    name="list_vulnerabilities",
    description="List all vulnerability nodes for the current tenant",
    action_id="list_vulnerabilities",
    tags=["sif", "read", "vulnerability"],
)
def list_vulnerabilities(context: AgentContext) -> list[dict[str, Any]]:
    """List all vulnerability nodes for the current tenant."""
    adapter = _get_adapter()
    return adapter.get_nodes(tenant_id=context.tenant_id, node_type="vulnerability")


@zak_tool(
    name="list_vendors",
    description="List all vendor nodes for the current tenant",
    action_id="list_vendors",
    tags=["sif", "read", "vendor"],
)
def list_vendors(context: AgentContext) -> list[dict[str, Any]]:
    """List all vendor nodes for the current tenant."""
    adapter = _get_adapter()
    return adapter.get_nodes(tenant_id=context.tenant_id, node_type="vendor")


@zak_tool(
    name="list_controls",
    description="List all security control nodes (firewalls, IAM policies, MFA, DLP) for the current tenant",
    action_id="list_controls",
    tags=["sif", "read", "control"],
)
def list_controls(context: AgentContext) -> list[dict[str, Any]]:
    """List all security control nodes for the current tenant."""
    adapter = _get_adapter()
    return adapter.get_nodes(tenant_id=context.tenant_id, node_type="control")


@zak_tool(
    name="list_identities",
    description="List all identity nodes (users, service accounts, API keys, roles) for the current tenant",
    action_id="list_identities",
    tags=["sif", "read", "identity"],
)
def list_identities(context: AgentContext) -> list[dict[str, Any]]:
    """List all identity nodes for the current tenant."""
    adapter = _get_adapter()
    return adapter.get_nodes(tenant_id=context.tenant_id, node_type="identity")


@zak_tool(
    name="list_risks",
    description="List all computed risk nodes for the current tenant",
    action_id="list_risks",
    tags=["sif", "read", "risk"],
)
def list_risks(context: AgentContext) -> list[dict[str, Any]]:
    """List all risk nodes for the current tenant."""
    adapter = _get_adapter()
    return adapter.get_nodes(tenant_id=context.tenant_id, node_type="risk")


@zak_tool(
    name="list_ai_models",
    description="List all AI/ML model nodes for the current tenant",
    action_id="list_ai_models",
    tags=["sif", "read", "ai_model"],
)
def list_ai_models(context: AgentContext) -> list[dict[str, Any]]:
    """List all AI model nodes for the current tenant."""
    adapter = _get_adapter()
    return adapter.get_nodes(tenant_id=context.tenant_id, node_type="ai_model")


# ---------------------------------------------------------------------------
# SIF Graph Write Tools
# ---------------------------------------------------------------------------

@zak_tool(
    name="write_risk_node",
    description="Write a RiskNode to the SIF graph",
    action_id="write_risk_node",
    tags=["sif", "write", "risk"],
)
def write_risk_node(context: AgentContext, risk_node: Any) -> None:
    """Upsert a RiskNode into the SIF graph for the current tenant."""
    adapter = _get_adapter()
    adapter.upsert_node(tenant_id=context.tenant_id, node=risk_node)


# ---------------------------------------------------------------------------
# Risk Tools
# ---------------------------------------------------------------------------

@zak_tool(
    name="compute_risk",
    description="Compute risk score for an asset using the ZAK risk propagation engine",
    action_id="compute_risk",
    tags=["risk", "compute"],
)
def compute_risk(
    context: AgentContext,
    criticality: str = "medium",
    exposure: str = "internal",
    exploitability: float = 0.5,
    control_effectiveness: float = 0.5,
    privilege_level: str = "medium",
) -> dict[str, Any]:
    """Compute and return a risk score dict from input parameters."""
    from zak.sif.risk.propagation import RiskInputs, RiskPropagationEngine
    inputs = RiskInputs(
        base_risk=RiskPropagationEngine.criticality_to_base_risk(criticality),
        exposure_factor=RiskPropagationEngine.exposure_to_factor(exposure),
        exploitability=exploitability,
        control_effectiveness=control_effectiveness,
        privilege_amplifier=RiskPropagationEngine.privilege_to_amplifier(privilege_level),
    )
    output = RiskPropagationEngine.compute(inputs)
    return {
        "risk_score": output.risk_score,
        "risk_level": output.risk_level,
        "raw_score": output.raw_score,
    }


# ---------------------------------------------------------------------------
# File Tools
# ---------------------------------------------------------------------------

@zak_tool(
    name="read_local_code_file",
    description="Reads the contents of a local code file for security analysis.",
    action_id="read_local_code_file",
    tags=["appsec", "read", "local_file"],
)
def read_local_code_file(context: AgentContext, file_path: str) -> str:
    """
    Read a local file from disk. Only allows reading files under the workspace root.

    Workspace root is taken from ZAK_WORKSPACE_ROOT (default: process cwd).
    Paths are resolved with os.path.realpath; access is denied if the resolved path
    lies outside the workspace.
    """
    import os
    workspace_root = os.getenv("ZAK_WORKSPACE_ROOT", os.getcwd())
    try:
        real_workspace = os.path.realpath(workspace_root)
    except Exception:
        real_workspace = os.path.realpath(os.getcwd())
    if not os.path.isdir(real_workspace):
        real_workspace = os.path.realpath(os.getcwd())

    try:
        abs_path = os.path.abspath(file_path)
        real_path = os.path.realpath(abs_path)
    except Exception as e:
        return f"Error: Invalid path {file_path}: {e}"

    try:
        if os.path.commonpath([real_workspace, real_path]) != real_workspace:
            raise PermissionError(
                f"Access denied: '{file_path}' is outside the workspace ({real_workspace}). "
                "Set ZAK_WORKSPACE_ROOT to allow a different root."
            )
    except ValueError:
        raise PermissionError(
            f"Access denied: '{file_path}' is outside the workspace ({real_workspace})."
        )

    try:
        if not os.path.exists(real_path):
            return f"Error: File not found at {file_path}"
        with open(real_path, "r", encoding="utf-8") as f:
            content = f.read()
        return content[:20000]  # Cap size for LLM safety
    except PermissionError:
        raise
    except Exception as e:
        return f"Error reading file {file_path}: {e}"
