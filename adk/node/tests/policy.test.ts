/**
 * ZAK Policy Engine Tests
 *
 * Covers all six policy rules plus approval gate detection:
 * Rule 1: Denied actions are blocked
 * Rule 2: Allow-list enforcement
 * Rule 3: Observe-only agents cannot mutate
 * Rule 4: Risk budget enforcement
 * Rule 5: Environment scope enforcement
 * Rule 6: Red team production restriction
 * Approval gate detection
 * Action allowed when all rules pass
 */

import { describe, it, expect } from "vitest";
import { PolicyEngine, permit, deny } from "../src/core/policy/engine.js";
import type { AgentDSL } from "../src/core/dsl/schema.js";

// ---------------------------------------------------------------------------
// Helper to create a minimal AgentDSL-like object for policy testing.
// The policy engine reads from the parsed DSL type, so we construct
// conforming objects directly rather than going through YAML parsing.
// ---------------------------------------------------------------------------

function makeAgent(overrides: {
  domain?: string;
  autonomy_level?: string;
  risk_budget?: string;
  allowed_actions?: string[];
  denied_actions?: string[];
  environment_scope?: string[];
  approval_gates?: string[];
}): AgentDSL {
  return {
    agent: {
      id: "test-agent-v1",
      name: "Test Agent",
      domain: overrides.domain ?? "appsec",
      version: "1.0.0",
    },
    intent: {
      goal: "Testing policy engine",
      success_criteria: [],
      priority: "medium",
    },
    reasoning: {
      mode: "deterministic",
      autonomy_level: overrides.autonomy_level ?? "bounded",
      confidence_threshold: 0.75,
      llm: null,
    },
    capabilities: {
      tools: [],
      data_access: [],
      graph_access: [],
    },
    boundaries: {
      risk_budget: overrides.risk_budget ?? "medium",
      allowed_actions: overrides.allowed_actions ?? [],
      denied_actions: overrides.denied_actions ?? [],
      environment_scope: overrides.environment_scope ?? [],
      approval_gates: overrides.approval_gates ?? [],
    },
    safety: {
      guardrails: [],
      sandbox_profile: overrides.domain === "red_team" ? "offensive_isolated" : "standard",
      audit_level: overrides.domain === "red_team" ? "verbose" : "standard",
    },
  } as AgentDSL;
}

// ---------------------------------------------------------------------------
// Policy helpers
// ---------------------------------------------------------------------------
describe("PolicyDecision helpers", () => {
  it("permit() returns allowed=true with default reason", () => {
    const decision = permit();
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("Action permitted by policy");
  });

  it("permit() accepts custom reason", () => {
    const decision = permit("Custom reason");
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("Custom reason");
  });

  it("deny() returns allowed=false with given reason", () => {
    const decision = deny("Blocked by test");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("Blocked by test");
  });
});

// ---------------------------------------------------------------------------
// PolicyEngine instantiation
// ---------------------------------------------------------------------------
describe("PolicyEngine instantiation", () => {
  it("creates a PolicyEngine instance", () => {
    const engine = new PolicyEngine();
    expect(engine).toBeInstanceOf(PolicyEngine);
  });
});

// ---------------------------------------------------------------------------
// Rule 1: Denied actions are blocked
// ---------------------------------------------------------------------------
describe("Rule 1: Denied actions are blocked", () => {
  const engine = new PolicyEngine();

  it("blocks an action that is explicitly denied", () => {
    const agent = makeAgent({
      denied_actions: ["delete_data", "execute_exploit"],
    });
    const decision = engine.evaluate(agent, "delete_data");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("explicitly denied");
    expect(decision.reason).toContain("delete_data");
  });

  it("blocks another explicitly denied action", () => {
    const agent = makeAgent({
      denied_actions: ["execute_exploit"],
    });
    const decision = engine.evaluate(agent, "execute_exploit");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("explicitly denied");
  });

  it("allows actions not in the deny list", () => {
    const agent = makeAgent({
      denied_actions: ["delete_data"],
    });
    const decision = engine.evaluate(agent, "read_data");
    expect(decision.allowed).toBe(true);
  });

  it("deny list takes precedence over allow list", () => {
    const agent = makeAgent({
      allowed_actions: ["delete_data", "read_data"],
      denied_actions: ["delete_data"],
    });
    const decision = engine.evaluate(agent, "delete_data");
    expect(decision.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Rule 2: Allow-list enforcement
// ---------------------------------------------------------------------------
describe("Rule 2: Allow-list enforcement", () => {
  const engine = new PolicyEngine();

  it("blocks action not in the allow list when allow list is defined", () => {
    const agent = makeAgent({
      allowed_actions: ["read_asset", "list_assets"],
    });
    const decision = engine.evaluate(agent, "delete_asset");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("not in the agent's allow-list");
    expect(decision.reason).toContain("read_asset");
  });

  it("allows action in the allow list", () => {
    const agent = makeAgent({
      allowed_actions: ["read_asset", "list_assets"],
    });
    const decision = engine.evaluate(agent, "read_asset");
    expect(decision.allowed).toBe(true);
  });

  it("allows any action when allow list is empty (no restrictions)", () => {
    const agent = makeAgent({
      allowed_actions: [],
    });
    const decision = engine.evaluate(agent, "any_random_action");
    expect(decision.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Rule 3: Observe-only agents cannot mutate
// ---------------------------------------------------------------------------
describe("Rule 3: Observe-only agents cannot mutate", () => {
  const engine = new PolicyEngine();

  it("blocks write operations for observe-only agents", () => {
    const agent = makeAgent({ autonomy_level: "observe" });
    const decision = engine.evaluate(agent, "write_report");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("mutating operation");
    expect(decision.reason).toContain("observe");
  });

  it("blocks delete operations for observe-only agents", () => {
    const agent = makeAgent({ autonomy_level: "observe" });
    const decision = engine.evaluate(agent, "delete_record");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("mutating operation");
  });

  it("blocks update operations for observe-only agents", () => {
    const agent = makeAgent({ autonomy_level: "observe" });
    const decision = engine.evaluate(agent, "update_config");
    expect(decision.allowed).toBe(false);
  });

  it("blocks create operations for observe-only agents", () => {
    const agent = makeAgent({ autonomy_level: "observe" });
    const decision = engine.evaluate(agent, "create_ticket");
    expect(decision.allowed).toBe(false);
  });

  it("blocks modify operations for observe-only agents", () => {
    const agent = makeAgent({ autonomy_level: "observe" });
    const decision = engine.evaluate(agent, "modify_setting");
    expect(decision.allowed).toBe(false);
  });

  it("blocks execute operations for observe-only agents", () => {
    const agent = makeAgent({ autonomy_level: "observe" });
    const decision = engine.evaluate(agent, "execute_script");
    expect(decision.allowed).toBe(false);
  });

  it("allows read operations for observe-only agents", () => {
    const agent = makeAgent({ autonomy_level: "observe" });
    const decision = engine.evaluate(agent, "read_asset");
    expect(decision.allowed).toBe(true);
  });

  it("allows list operations for observe-only agents", () => {
    const agent = makeAgent({ autonomy_level: "observe" });
    const decision = engine.evaluate(agent, "list_assets");
    expect(decision.allowed).toBe(true);
  });

  it("allows scan operations for observe-only agents", () => {
    const agent = makeAgent({ autonomy_level: "observe" });
    const decision = engine.evaluate(agent, "scan_network");
    expect(decision.allowed).toBe(true);
  });

  it("is case-insensitive for mutating verb detection", () => {
    const agent = makeAgent({ autonomy_level: "observe" });
    const decision = engine.evaluate(agent, "Write_Report");
    expect(decision.allowed).toBe(false);
  });

  it("allows mutating operations for bounded agents", () => {
    const agent = makeAgent({ autonomy_level: "bounded" });
    const decision = engine.evaluate(agent, "write_report");
    expect(decision.allowed).toBe(true);
  });

  it("allows mutating operations for suggest agents", () => {
    const agent = makeAgent({ autonomy_level: "suggest" });
    const decision = engine.evaluate(agent, "delete_record");
    expect(decision.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Rule 4: Risk budget enforcement
// ---------------------------------------------------------------------------
describe("Rule 4: Risk budget enforcement", () => {
  const engine = new PolicyEngine();

  it("blocks high-risk action with low risk budget", () => {
    const agent = makeAgent({ risk_budget: "low" });
    const decision = engine.evaluate(agent, "execute_exploit");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("risk_budget");
    expect(decision.reason).toContain("medium");
  });

  it("blocks deploy_payload with low risk budget", () => {
    const agent = makeAgent({ risk_budget: "low" });
    const decision = engine.evaluate(agent, "deploy_payload");
    expect(decision.allowed).toBe(false);
  });

  it("blocks modify_production with low risk budget", () => {
    const agent = makeAgent({ risk_budget: "low" });
    const decision = engine.evaluate(agent, "modify_production");
    expect(decision.allowed).toBe(false);
  });

  it("allows high-risk action with medium risk budget", () => {
    const agent = makeAgent({ risk_budget: "medium" });
    const decision = engine.evaluate(agent, "execute_exploit");
    expect(decision.allowed).toBe(true);
  });

  it("allows high-risk action with high risk budget", () => {
    const agent = makeAgent({ risk_budget: "high" });
    const decision = engine.evaluate(agent, "deploy_payload");
    expect(decision.allowed).toBe(true);
  });

  it("allows non-high-risk action with low budget", () => {
    const agent = makeAgent({ risk_budget: "low" });
    const decision = engine.evaluate(agent, "read_asset");
    expect(decision.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Rule 5: Environment scope enforcement
// ---------------------------------------------------------------------------
describe("Rule 5: Environment scope enforcement", () => {
  const engine = new PolicyEngine();

  it("blocks action in out-of-scope environment", () => {
    const agent = makeAgent({
      environment_scope: ["staging", "dev"],
    });
    const decision = engine.evaluate(agent, "read_asset", "production");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("not in scope");
    expect(decision.reason).toContain("production");
  });

  it("allows action in scoped environment", () => {
    const agent = makeAgent({
      environment_scope: ["staging", "dev"],
    });
    const decision = engine.evaluate(agent, "read_asset", "staging");
    expect(decision.allowed).toBe(true);
  });

  it("allows action when environment scope is empty (no restriction)", () => {
    const agent = makeAgent({
      environment_scope: [],
    });
    const decision = engine.evaluate(agent, "read_asset", "production");
    expect(decision.allowed).toBe(true);
  });

  it("allows action when no environment is specified", () => {
    const agent = makeAgent({
      environment_scope: ["staging"],
    });
    const decision = engine.evaluate(agent, "read_asset");
    expect(decision.allowed).toBe(true);
  });

  it("allows action when environment is null", () => {
    const agent = makeAgent({
      environment_scope: ["staging"],
    });
    const decision = engine.evaluate(agent, "read_asset", null);
    expect(decision.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Rule 6: Red team production restriction
// ---------------------------------------------------------------------------
describe("Rule 6: Red team production restriction", () => {
  const engine = new PolicyEngine();

  it("blocks red team agent from targeting production without explicit scope", () => {
    // Use empty environment_scope so Rule 5 does not fire first.
    // Rule 6 specifically checks red_team + production when production
    // is NOT in environment_scope.
    const agent = makeAgent({
      domain: "red_team",
      environment_scope: [],
    });
    const decision = engine.evaluate(agent, "scan_network", "production");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("Red team");
    expect(decision.reason).toContain("production");
  });

  it("blocks red team with empty environment_scope from accessing production", () => {
    const agent = makeAgent({
      domain: "red_team",
      environment_scope: [],
    });
    const decision = engine.evaluate(agent, "scan_network", "production");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("Red team");
  });

  it("allows red team agent to target production when explicitly scoped", () => {
    const agent = makeAgent({
      domain: "red_team",
      environment_scope: ["staging", "production"],
    });
    const decision = engine.evaluate(agent, "scan_network", "production");
    expect(decision.allowed).toBe(true);
  });

  it("allows red team agent to target staging", () => {
    const agent = makeAgent({
      domain: "red_team",
      environment_scope: ["staging"],
    });
    const decision = engine.evaluate(agent, "scan_network", "staging");
    expect(decision.allowed).toBe(true);
  });

  it("allows non-red-team agent in production without explicit scope", () => {
    const agent = makeAgent({
      domain: "appsec",
      environment_scope: [],
    });
    const decision = engine.evaluate(agent, "read_asset", "production");
    expect(decision.allowed).toBe(true);
  });

  it("Rule 5 fires before Rule 6 when environment_scope is defined without production", () => {
    // When environment_scope has entries but not "production",
    // Rule 5 (env scope) fires before Rule 6 (red team) since rules
    // are evaluated in order.
    const agent = makeAgent({
      domain: "red_team",
      environment_scope: ["staging"],
    });
    const decision = engine.evaluate(agent, "scan_network", "production");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("not in scope");
  });

  it("red team production restriction does not apply when environment is not production", () => {
    const agent = makeAgent({
      domain: "red_team",
      environment_scope: ["staging"],
    });
    const decision = engine.evaluate(agent, "scan_network", "staging");
    expect(decision.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Approval gate detection
// ---------------------------------------------------------------------------
describe("Approval gate detection", () => {
  const engine = new PolicyEngine();

  it("detects action requiring approval", () => {
    const agent = makeAgent({
      approval_gates: ["execute_exploit", "deploy_payload"],
    });
    expect(engine.checkApprovalGate(agent, "execute_exploit")).toBe(true);
  });

  it("detects another gated action", () => {
    const agent = makeAgent({
      approval_gates: ["execute_exploit", "deploy_payload"],
    });
    expect(engine.checkApprovalGate(agent, "deploy_payload")).toBe(true);
  });

  it("returns false for non-gated action", () => {
    const agent = makeAgent({
      approval_gates: ["execute_exploit"],
    });
    expect(engine.checkApprovalGate(agent, "read_asset")).toBe(false);
  });

  it("returns false when no approval gates are defined", () => {
    const agent = makeAgent({
      approval_gates: [],
    });
    expect(engine.checkApprovalGate(agent, "any_action")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Action is allowed when all rules pass
// ---------------------------------------------------------------------------
describe("Action allowed when all rules pass", () => {
  const engine = new PolicyEngine();

  it("allows action that passes all rules for a bounded agent", () => {
    const agent = makeAgent({
      allowed_actions: ["read_asset", "list_assets"],
      denied_actions: [],
      environment_scope: ["staging", "dev"],
      risk_budget: "medium",
      autonomy_level: "bounded",
    });
    const decision = engine.evaluate(agent, "read_asset", "staging");
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe("Action permitted by policy");
  });

  it("allows any action for a minimally constrained agent", () => {
    const agent = makeAgent({});
    const decision = engine.evaluate(agent, "anything_goes");
    expect(decision.allowed).toBe(true);
  });

  it("allows action with no environment specified and all other rules pass", () => {
    const agent = makeAgent({
      allowed_actions: ["scan_target"],
      denied_actions: [],
      risk_budget: "high",
      autonomy_level: "high",
    });
    const decision = engine.evaluate(agent, "scan_target");
    expect(decision.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Rule priority / ordering
// ---------------------------------------------------------------------------
describe("Rule evaluation order (first deny wins)", () => {
  const engine = new PolicyEngine();

  it("deny list takes precedence even if action is in allow list (Rule 1 before Rule 2)", () => {
    const agent = makeAgent({
      allowed_actions: ["execute_exploit"],
      denied_actions: ["execute_exploit"],
    });
    const decision = engine.evaluate(agent, "execute_exploit");
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("explicitly denied");
  });

  it("deny list check happens before observe-only check", () => {
    const agent = makeAgent({
      autonomy_level: "observe",
      denied_actions: ["read_asset"],
    });
    const decision = engine.evaluate(agent, "read_asset");
    expect(decision.allowed).toBe(false);
    // Should be denied by Rule 1 (deny list), not Rule 3 (observe)
    expect(decision.reason).toContain("explicitly denied");
  });

  it("allow list check happens before environment scope check", () => {
    const agent = makeAgent({
      allowed_actions: ["read_asset"],
      environment_scope: ["staging"],
    });
    const decision = engine.evaluate(agent, "write_report", "staging");
    expect(decision.allowed).toBe(false);
    // Should fail on Rule 2 (allow-list)
    expect(decision.reason).toContain("not in the agent's allow-list");
  });
});

// ---------------------------------------------------------------------------
// Metadata parameter (Phase 1 - unused but should not cause errors)
// ---------------------------------------------------------------------------
describe("Metadata parameter handling", () => {
  const engine = new PolicyEngine();

  it("accepts metadata without errors", () => {
    const agent = makeAgent({});
    const decision = engine.evaluate(agent, "read_asset", "staging", {
      user: "test",
      requestId: "abc-123",
    });
    expect(decision.allowed).toBe(true);
  });

  it("accepts null metadata without errors", () => {
    const agent = makeAgent({});
    const decision = engine.evaluate(agent, "read_asset", "staging", null);
    expect(decision.allowed).toBe(true);
  });
});
