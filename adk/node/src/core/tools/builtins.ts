/**
 * ZAK Built-in Tools -- SIF graph read/write tools available to all agents.
 *
 * These are the platform-level tools that agents declare in capabilities.tools.
 * Domain-specific tools can be added alongside these in their respective agent
 * packages.
 *
 * All tools are placeholder implementations. Actual graph I/O comes from the
 * SIF graph adapter (KuzuAdapter, Neo4jAdapter, etc.) which is injected at
 * runtime.
 *
 * TypeScript equivalent of zak/core/tools/builtins.py.
 */

import { zakTool, type ToolFunction } from "./substrate.js";
import { RiskPropagationEngine } from "../../sif/risk/propagation.js";

// ---------------------------------------------------------------------------
// SIF Graph Read Tools
// ---------------------------------------------------------------------------

export const readAsset = zakTool({
  name: "read_asset",
  description: "Read an asset node from the SIF graph by ID",
  actionId: "read_asset",
  tags: ["sif", "read", "asset"],
})(
  ((_context: unknown, _assetId: unknown) => {
    return JSON.stringify({
      placeholder: true,
      message:
        "read_asset: not yet connected to a graph adapter. " +
        "Provide a KuzuAdapter or Neo4jAdapter at runtime.",
    });
  }) as ToolFunction,
);

export const listAssets = zakTool({
  name: "list_assets",
  description:
    "List all asset nodes in the SIF graph for the current tenant",
  actionId: "list_assets",
  tags: ["sif", "read", "asset"],
})(
  ((_context: unknown) => {
    return JSON.stringify({
      placeholder: true,
      assets: [],
      message: "list_assets: not yet connected to a graph adapter.",
    });
  }) as ToolFunction,
);

export const listVulnerabilities = zakTool({
  name: "list_vulnerabilities",
  description: "List all vulnerability nodes for the current tenant",
  actionId: "list_vulnerabilities",
  tags: ["sif", "read", "vulnerability"],
})(
  ((_context: unknown) => {
    return JSON.stringify({
      placeholder: true,
      vulnerabilities: [],
      message: "list_vulnerabilities: not yet connected to a graph adapter.",
    });
  }) as ToolFunction,
);

export const listIdentities = zakTool({
  name: "list_identities",
  description:
    "List all identity nodes (users, service accounts, API keys, roles) for the current tenant",
  actionId: "list_identities",
  tags: ["sif", "read", "identity"],
})(
  ((_context: unknown) => {
    return JSON.stringify({
      placeholder: true,
      identities: [],
      message: "list_identities: not yet connected to a graph adapter.",
    });
  }) as ToolFunction,
);

export const listRisks = zakTool({
  name: "list_risks",
  description: "List all computed risk nodes for the current tenant",
  actionId: "list_risks",
  tags: ["sif", "read", "risk"],
})(
  ((_context: unknown) => {
    return JSON.stringify({
      placeholder: true,
      risks: [],
      message: "list_risks: not yet connected to a graph adapter.",
    });
  }) as ToolFunction,
);

export const listControls = zakTool({
  name: "list_controls",
  description:
    "List all security control nodes (firewalls, IAM policies, MFA, DLP) for the current tenant",
  actionId: "list_controls",
  tags: ["sif", "read", "control"],
})(
  ((_context: unknown) => {
    return JSON.stringify({
      placeholder: true,
      controls: [],
      message: "list_controls: not yet connected to a graph adapter.",
    });
  }) as ToolFunction,
);

export const listVendors = zakTool({
  name: "list_vendors",
  description: "List all vendor nodes for the current tenant",
  actionId: "list_vendors",
  tags: ["sif", "read", "vendor"],
})(
  ((_context: unknown) => {
    return JSON.stringify({
      placeholder: true,
      vendors: [],
      message: "list_vendors: not yet connected to a graph adapter.",
    });
  }) as ToolFunction,
);

export const listAIModels = zakTool({
  name: "list_ai_models",
  description: "List all AI/ML model nodes for the current tenant",
  actionId: "list_ai_models",
  tags: ["sif", "read", "ai_model"],
})(
  ((_context: unknown) => {
    return JSON.stringify({
      placeholder: true,
      aiModels: [],
      message: "list_ai_models: not yet connected to a graph adapter.",
    });
  }) as ToolFunction,
);

// ---------------------------------------------------------------------------
// SIF Graph Write Tools
// ---------------------------------------------------------------------------

export const writeRiskNode = zakTool({
  name: "write_risk_node",
  description: "Write a RiskNode to the SIF graph",
  actionId: "write_risk_node",
  tags: ["sif", "write", "risk"],
})(
  ((_context: unknown, _riskNode: unknown) => {
    return JSON.stringify({
      placeholder: true,
      message: "write_risk_node: not yet connected to a graph adapter.",
    });
  }) as ToolFunction,
);

// ---------------------------------------------------------------------------
// Risk Tools
// ---------------------------------------------------------------------------

export const computeRisk = zakTool({
  name: "compute_risk",
  description:
    "Compute risk score for an asset using the ZAK risk propagation engine",
  actionId: "compute_risk",
  tags: ["risk", "compute"],
})(
  ((
    _context: unknown,
    criticality: unknown = "medium",
    exposure: unknown = "internal",
    exploitability: unknown = 0.5,
    controlEffectiveness: unknown = 0.5,
    privilegeLevel: unknown = "medium",
  ) => {
    const crit = String(criticality ?? "medium");
    const exp = String(exposure ?? "internal");
    const expl = Number(exploitability ?? 0.5);
    const ctrl = Number(controlEffectiveness ?? 0.5);
    const priv = String(privilegeLevel ?? "medium");

    const inputs = {
      baseRisk: RiskPropagationEngine.criticalityToBaseRisk(crit),
      exposureFactor: RiskPropagationEngine.exposureToFactor(exp),
      exploitability: expl,
      controlEffectiveness: ctrl,
      privilegeAmplifier: RiskPropagationEngine.privilegeToAmplifier(priv),
    };
    const output = RiskPropagationEngine.compute(inputs);
    return JSON.stringify({
      risk_score: output.riskScore,
      risk_level: output.riskLevel,
      raw_score: output.rawScore,
    });
  }) as ToolFunction,
);

// ---------------------------------------------------------------------------
// Script/File Tools
// ---------------------------------------------------------------------------

export const executePython = zakTool({
  name: "execute_python",
  description:
    "Execute a Python script in a sandboxed environment for security analysis",
  actionId: "execute_python",
  tags: ["compute", "python", "sandbox"],
})(
  ((_context: unknown, _script: unknown) => {
    return JSON.stringify({
      placeholder: true,
      message:
        "execute_python: sandboxed Python execution is not yet implemented. " +
        "This will be available when the compute substrate is connected.",
    });
  }) as ToolFunction,
);

// ---------------------------------------------------------------------------
// Convenience: all built-in tools as an array
// ---------------------------------------------------------------------------

export const ALL_BUILTIN_TOOLS = [
  readAsset,
  listAssets,
  listVulnerabilities,
  listIdentities,
  listRisks,
  listControls,
  listVendors,
  listAIModels,
  writeRiskNode,
  computeRisk,
  executePython,
] as const;
