/**
 * ZAK DSL Schema + Parser Tests
 *
 * Covers:
 * - Valid YAML fixture parsing
 * - Schema validation for missing fields
 * - Slug format validation for agent ID
 * - Semver validation for version
 * - Red team cross-field validation (offensive_isolated + verbose)
 * - fully_autonomous confidence threshold requirement
 * - llm_react auto-population of LLM config
 * - Allowed/denied action overlap rejection
 * - validateAgent() structured result
 * - validateAgentString() string input
 * - loadAgentYaml() missing file handling
 * - loadAgentYamlString() string input
 */

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { readFileSync } from "node:fs";

import { AgentDSLSchema, LLMConfigSchema } from "../src/core/dsl/schema.js";
import {
  loadAgentYaml,
  loadAgentYamlString,
  validateAgent,
  validateAgentString,
  formatValidationResult,
} from "../src/core/dsl/parser.js";

// ---------------------------------------------------------------------------
// __dirname equivalent for ESM
// ---------------------------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Fixture helper
const fixture = (name: string) =>
  path.resolve(__dirname, "../../../tests/fixtures", name);

// ---------------------------------------------------------------------------
// 1. Valid YAML fixtures parse correctly
// ---------------------------------------------------------------------------
describe("Valid YAML fixtures", () => {
  it("parses valid-generic.yaml successfully", () => {
    const dsl = loadAgentYaml(fixture("valid-generic.yaml"));
    expect(dsl.agent.id).toBe("test-generic-v1");
    expect(dsl.agent.name).toBe("Test Generic Agent");
    expect(dsl.agent.domain).toBe("appsec");
    expect(dsl.agent.version).toBe("1.0.0");
    expect(dsl.intent.goal).toBe("Perform a basic application security scan");
    expect(dsl.intent.priority).toBe("medium");
    expect(dsl.reasoning.mode).toBe("deterministic");
    expect(dsl.reasoning.autonomy_level).toBe("bounded");
    expect(dsl.reasoning.confidence_threshold).toBe(0.75);
    expect(dsl.capabilities.tools).toContain("read_asset");
    expect(dsl.boundaries.environment_scope).toEqual(["staging", "dev"]);
    expect(dsl.safety.sandbox_profile).toBe("standard");
    expect(dsl.safety.audit_level).toBe("standard");
  });

  it("parses valid-risk-quant.yaml successfully", () => {
    const dsl = loadAgentYaml(fixture("valid-risk-quant.yaml"));
    expect(dsl.agent.id).toBe("risk-quant-v1");
    expect(dsl.agent.domain).toBe("risk_quant");
    expect(dsl.reasoning.mode).toBe("llm_react");
    expect(dsl.reasoning.llm).not.toBeNull();
    expect(dsl.reasoning.llm!.provider).toBe("openai");
    expect(dsl.reasoning.llm!.model).toBe("gpt-4o");
    expect(dsl.reasoning.llm!.temperature).toBe(0.2);
    expect(dsl.reasoning.llm!.max_iterations).toBe(10);
    expect(dsl.reasoning.llm!.max_tokens).toBe(4096);
    expect(dsl.capabilities.tools).toContain("compute_risk");
    expect(dsl.intent.priority).toBe("high");
  });

  it("parses valid-red-team.yaml successfully", () => {
    const dsl = loadAgentYaml(fixture("valid-red-team.yaml"));
    expect(dsl.agent.id).toBe("red-team-scanner-v1");
    expect(dsl.agent.domain).toBe("red_team");
    expect(dsl.safety.sandbox_profile).toBe("offensive_isolated");
    expect(dsl.safety.audit_level).toBe("verbose");
    expect(dsl.boundaries.denied_actions).toContain("modify_production");
    expect(dsl.boundaries.denied_actions).toContain("deploy_payload");
    expect(dsl.boundaries.approval_gates).toContain("execute_exploit");
    expect(dsl.reasoning.confidence_threshold).toBe(0.9);
    expect(dsl.intent.priority).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// 2. Schema validation catches missing fields
// ---------------------------------------------------------------------------
describe("Schema validation for missing fields", () => {
  it("rejects YAML missing the agent section", () => {
    expect(() =>
      loadAgentYaml(fixture("invalid-missing-agent.yaml"))
    ).toThrow();
  });

  it("validateAgent returns errors for missing agent section", () => {
    const result = validateAgent(fixture("invalid-missing-agent.yaml"));
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.agentId).toBeNull();
  });

  it("rejects an object missing agent.id", () => {
    const raw = {
      agent: { name: "Test", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: { mode: "deterministic" },
    };
    expect(() => AgentDSLSchema.parse(raw)).toThrow();
  });

  it("rejects an object missing agent.name", () => {
    const raw = {
      agent: { id: "test-v1", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: { mode: "deterministic" },
    };
    expect(() => AgentDSLSchema.parse(raw)).toThrow();
  });

  it("rejects an object missing intent.goal", () => {
    const raw = {
      agent: { id: "test-v1", name: "Test", domain: "appsec", version: "1.0.0" },
      intent: { priority: "medium" },
      reasoning: { mode: "deterministic" },
    };
    expect(() => AgentDSLSchema.parse(raw)).toThrow();
  });

  it("rejects an object missing reasoning.mode", () => {
    const raw = {
      agent: { id: "test-v1", name: "Test", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: { autonomy_level: "bounded" },
    };
    expect(() => AgentDSLSchema.parse(raw)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// 3. Slug format validation for agent ID
// ---------------------------------------------------------------------------
describe("Agent ID slug format validation", () => {
  const makeRaw = (id: string) => ({
    agent: { id, name: "Test", domain: "appsec", version: "1.0.0" },
    intent: { goal: "Test" },
    reasoning: { mode: "deterministic" },
  });

  it("accepts valid slug: lowercase with hyphens", () => {
    const dsl = AgentDSLSchema.parse(makeRaw("my-agent-v1"));
    expect(dsl.agent.id).toBe("my-agent-v1");
  });

  it("accepts valid slug: alphanumeric only", () => {
    const dsl = AgentDSLSchema.parse(makeRaw("agent01"));
    expect(dsl.agent.id).toBe("agent01");
  });

  it("rejects uppercase characters in agent ID", () => {
    expect(() => AgentDSLSchema.parse(makeRaw("My-Agent"))).toThrow();
  });

  it("rejects underscores in agent ID", () => {
    expect(() => AgentDSLSchema.parse(makeRaw("my_agent_v1"))).toThrow();
  });

  it("rejects spaces in agent ID", () => {
    expect(() => AgentDSLSchema.parse(makeRaw("my agent"))).toThrow();
  });

  it("rejects agent ID starting with hyphen", () => {
    expect(() => AgentDSLSchema.parse(makeRaw("-agent"))).toThrow();
  });

  it("rejects agent ID ending with hyphen", () => {
    expect(() => AgentDSLSchema.parse(makeRaw("agent-"))).toThrow();
  });

  it("rejects empty agent ID", () => {
    expect(() => AgentDSLSchema.parse(makeRaw(""))).toThrow();
  });

  it("rejects single character agent ID (regex requires at least 2 chars with start/end anchors)", () => {
    // The regex ^[a-z0-9][a-z0-9-]*[a-z0-9]$ requires at least 2 characters
    expect(() => AgentDSLSchema.parse(makeRaw("a"))).toThrow();
  });
});

// ---------------------------------------------------------------------------
// 4. Semver validation for version
// ---------------------------------------------------------------------------
describe("Version semver validation", () => {
  const makeRaw = (version: string) => ({
    agent: { id: "test-v1", name: "Test", domain: "appsec", version },
    intent: { goal: "Test" },
    reasoning: { mode: "deterministic" },
  });

  it("accepts valid semver: 1.0.0", () => {
    const dsl = AgentDSLSchema.parse(makeRaw("1.0.0"));
    expect(dsl.agent.version).toBe("1.0.0");
  });

  it("accepts valid semver: 10.20.30", () => {
    const dsl = AgentDSLSchema.parse(makeRaw("10.20.30"));
    expect(dsl.agent.version).toBe("10.20.30");
  });

  it("accepts valid semver: 0.0.1", () => {
    const dsl = AgentDSLSchema.parse(makeRaw("0.0.1"));
    expect(dsl.agent.version).toBe("0.0.1");
  });

  it("rejects version with only major.minor (no patch)", () => {
    expect(() => AgentDSLSchema.parse(makeRaw("1.0"))).toThrow();
  });

  it("rejects version with only major number", () => {
    expect(() => AgentDSLSchema.parse(makeRaw("1"))).toThrow();
  });

  it("rejects version with pre-release suffix", () => {
    // The regex is strict: ^\d+\.\d+\.\d+$, no extra suffixes allowed
    expect(() => AgentDSLSchema.parse(makeRaw("1.0.0-beta"))).toThrow();
  });

  it("rejects version with v prefix", () => {
    expect(() => AgentDSLSchema.parse(makeRaw("v1.0.0"))).toThrow();
  });

  it("rejects empty version string", () => {
    expect(() => AgentDSLSchema.parse(makeRaw(""))).toThrow();
  });
});

// ---------------------------------------------------------------------------
// 5. Red team requires offensive_isolated sandbox + verbose audit
// ---------------------------------------------------------------------------
describe("Red team cross-field validation", () => {
  it("rejects red team agent with standard sandbox", () => {
    expect(() =>
      loadAgentYaml(fixture("invalid-red-team.yaml"))
    ).toThrow();
  });

  it("validateAgent catches red team with wrong sandbox and audit", () => {
    const result = validateAgent(fixture("invalid-red-team.yaml"));
    expect(result.valid).toBe(false);
    // Should have errors about sandbox_profile and audit_level
    const errors = result.errors.join(" ");
    expect(errors).toContain("offensive_isolated");
    expect(errors).toContain("verbose");
  });

  it("rejects red team agent with offensive_isolated but minimal audit", () => {
    const raw = {
      agent: { id: "rt-test-v1", name: "RT Test", domain: "red_team", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: { mode: "deterministic" },
      safety: {
        sandbox_profile: "offensive_isolated",
        audit_level: "minimal",
      },
    };
    expect(() => AgentDSLSchema.parse(raw)).toThrow();
  });

  it("rejects red team agent with verbose audit but standard sandbox", () => {
    const raw = {
      agent: { id: "rt-test-v1", name: "RT Test", domain: "red_team", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: { mode: "deterministic" },
      safety: {
        sandbox_profile: "standard",
        audit_level: "verbose",
      },
    };
    expect(() => AgentDSLSchema.parse(raw)).toThrow();
  });

  it("accepts red team agent with offensive_isolated and verbose audit", () => {
    const raw = {
      agent: { id: "rt-test-v1", name: "RT Test", domain: "red_team", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: { mode: "deterministic" },
      safety: {
        sandbox_profile: "offensive_isolated",
        audit_level: "verbose",
      },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.safety.sandbox_profile).toBe("offensive_isolated");
    expect(dsl.safety.audit_level).toBe("verbose");
  });
});

// ---------------------------------------------------------------------------
// 6. fully_autonomous requires confidence >= 0.9
// ---------------------------------------------------------------------------
describe("fully_autonomous confidence threshold", () => {
  it("rejects fully_autonomous with confidence 0.5", () => {
    expect(() =>
      loadAgentYaml(fixture("invalid-autonomous.yaml"))
    ).toThrow();
  });

  it("validateAgent returns error for low confidence autonomous agent", () => {
    const result = validateAgent(fixture("invalid-autonomous.yaml"));
    expect(result.valid).toBe(false);
    const errors = result.errors.join(" ");
    expect(errors).toContain("fully_autonomous");
    expect(errors).toContain("0.9");
  });

  it("rejects fully_autonomous with confidence 0.89", () => {
    const raw = {
      agent: { id: "auto-v1", name: "Auto", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: {
        mode: "deterministic",
        autonomy_level: "fully_autonomous",
        confidence_threshold: 0.89,
      },
    };
    expect(() => AgentDSLSchema.parse(raw)).toThrow();
  });

  it("accepts fully_autonomous with confidence exactly 0.9", () => {
    const raw = {
      agent: { id: "auto-v1", name: "Auto", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: {
        mode: "deterministic",
        autonomy_level: "fully_autonomous",
        confidence_threshold: 0.9,
      },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.reasoning.confidence_threshold).toBe(0.9);
  });

  it("accepts fully_autonomous with confidence 0.95", () => {
    const raw = {
      agent: { id: "auto-v1", name: "Auto", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: {
        mode: "deterministic",
        autonomy_level: "fully_autonomous",
        confidence_threshold: 0.95,
      },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.reasoning.confidence_threshold).toBe(0.95);
  });

  it("accepts bounded autonomy with low confidence (no restriction)", () => {
    const raw = {
      agent: { id: "bounded-v1", name: "Bounded", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: {
        mode: "deterministic",
        autonomy_level: "bounded",
        confidence_threshold: 0.5,
      },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.reasoning.confidence_threshold).toBe(0.5);
  });
});

// ---------------------------------------------------------------------------
// 7. llm_react auto-populates LLM config
// ---------------------------------------------------------------------------
describe("llm_react auto-population of LLM config", () => {
  it("auto-populates LLM defaults when mode is llm_react and llm is null", () => {
    const raw = {
      agent: { id: "llm-test-v1", name: "LLM Test", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: {
        mode: "llm_react",
        autonomy_level: "bounded",
        confidence_threshold: 0.75,
        // llm not provided
      },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.reasoning.llm).not.toBeNull();
    expect(dsl.reasoning.llm!.provider).toBe("openai");
    expect(dsl.reasoning.llm!.model).toBe("gpt-4o");
    expect(dsl.reasoning.llm!.temperature).toBe(0.2);
    expect(dsl.reasoning.llm!.max_iterations).toBe(10);
    expect(dsl.reasoning.llm!.max_tokens).toBe(4096);
  });

  it("preserves explicit LLM config when provided", () => {
    const raw = {
      agent: { id: "llm-test-v1", name: "LLM Test", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: {
        mode: "llm_react",
        llm: {
          provider: "anthropic",
          model: "claude-opus-4-5",
          temperature: 0.5,
          max_iterations: 20,
          max_tokens: 8192,
        },
      },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.reasoning.llm).not.toBeNull();
    expect(dsl.reasoning.llm!.provider).toBe("anthropic");
    expect(dsl.reasoning.llm!.model).toBe("claude-opus-4-5");
    expect(dsl.reasoning.llm!.temperature).toBe(0.5);
    expect(dsl.reasoning.llm!.max_iterations).toBe(20);
    expect(dsl.reasoning.llm!.max_tokens).toBe(8192);
  });

  it("does not auto-populate LLM config for deterministic mode", () => {
    const raw = {
      agent: { id: "det-v1", name: "Deterministic", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: {
        mode: "deterministic",
      },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.reasoning.llm).toBeNull();
  });

  it("does not auto-populate LLM config for rule_based mode", () => {
    const raw = {
      agent: { id: "rb-v1", name: "RuleBased", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: {
        mode: "rule_based",
      },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.reasoning.llm).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 8. Allowed/denied actions overlap is rejected
// ---------------------------------------------------------------------------
describe("Allowed/denied actions overlap rejection", () => {
  it("rejects YAML with overlapping allowed/denied actions", () => {
    expect(() =>
      loadAgentYaml(fixture("invalid-overlap.yaml"))
    ).toThrow();
  });

  it("validateAgent returns overlap error details", () => {
    const result = validateAgent(fixture("invalid-overlap.yaml"));
    expect(result.valid).toBe(false);
    const errors = result.errors.join(" ");
    expect(errors).toContain("execute_python");
    expect(errors).toContain("allowed_actions");
    expect(errors).toContain("denied_actions");
  });

  it("rejects overlap via direct schema parse", () => {
    const raw = {
      agent: { id: "overlap-v1", name: "Overlap", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: { mode: "deterministic" },
      boundaries: {
        allowed_actions: ["read_asset", "delete_asset"],
        denied_actions: ["delete_asset"],
      },
    };
    expect(() => AgentDSLSchema.parse(raw)).toThrow();
  });

  it("accepts non-overlapping allowed and denied actions", () => {
    const raw = {
      agent: { id: "no-overlap-v1", name: "No Overlap", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: { mode: "deterministic" },
      boundaries: {
        allowed_actions: ["read_asset"],
        denied_actions: ["delete_asset"],
      },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.boundaries.allowed_actions).toEqual(["read_asset"]);
    expect(dsl.boundaries.denied_actions).toEqual(["delete_asset"]);
  });
});

// ---------------------------------------------------------------------------
// 9. validateAgent() returns structured ValidationResult
// ---------------------------------------------------------------------------
describe("validateAgent() structured ValidationResult", () => {
  it("returns valid=true with agentId for valid file", () => {
    const result = validateAgent(fixture("valid-generic.yaml"));
    expect(result.valid).toBe(true);
    expect(result.agentId).toBe("test-generic-v1");
    expect(result.errors).toEqual([]);
  });

  it("returns valid=true for valid red team agent", () => {
    const result = validateAgent(fixture("valid-red-team.yaml"));
    expect(result.valid).toBe(true);
    expect(result.agentId).toBe("red-team-scanner-v1");
    expect(result.errors).toEqual([]);
  });

  it("returns valid=false with errors for invalid file", () => {
    const result = validateAgent(fixture("invalid-missing-agent.yaml"));
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("returns valid=false for non-existent file", () => {
    const result = validateAgent(fixture("non-existent.yaml"));
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain("not found");
  });

  it("formatValidationResult produces success message for valid result", () => {
    const result = validateAgent(fixture("valid-generic.yaml"));
    const formatted = formatValidationResult(result);
    expect(formatted).toContain("test-generic-v1");
  });

  it("formatValidationResult produces error listing for invalid result", () => {
    const result = validateAgent(fixture("invalid-red-team.yaml"));
    const formatted = formatValidationResult(result);
    expect(formatted).toContain("error");
  });
});

// ---------------------------------------------------------------------------
// 10. validateAgentString() works with string input
// ---------------------------------------------------------------------------
describe("validateAgentString() string input", () => {
  it("returns valid=true for valid YAML string", () => {
    const yamlStr = readFileSync(fixture("valid-generic.yaml"), "utf-8");
    const result = validateAgentString(yamlStr);
    expect(result.valid).toBe(true);
    expect(result.agentId).toBe("test-generic-v1");
    expect(result.errors).toEqual([]);
  });

  it("returns valid=false for YAML string missing agent section", () => {
    const yamlStr = readFileSync(fixture("invalid-missing-agent.yaml"), "utf-8");
    const result = validateAgentString(yamlStr);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("returns valid=false for invalid YAML syntax", () => {
    const result = validateAgentString(":::not valid yaml:::");
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("returns valid=false for non-object YAML (scalar)", () => {
    const result = validateAgentString("just a string");
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("mapping");
  });

  it("returns valid=false for empty YAML", () => {
    const result = validateAgentString("");
    expect(result.valid).toBe(false);
  });

  it("preserves agentId in error result when agent section is present", () => {
    const yamlStr = readFileSync(fixture("invalid-red-team.yaml"), "utf-8");
    const result = validateAgentString(yamlStr);
    expect(result.valid).toBe(false);
    expect(result.agentId).toBe("bad-red-team-v1");
  });
});

// ---------------------------------------------------------------------------
// 11. loadAgentYaml() throws for missing files
// ---------------------------------------------------------------------------
describe("loadAgentYaml() missing file handling", () => {
  it("throws an error for non-existent file", () => {
    expect(() => loadAgentYaml("/tmp/does-not-exist.yaml")).toThrow(
      "Agent definition not found"
    );
  });

  it("throws for a path that points to nothing", () => {
    expect(() =>
      loadAgentYaml(fixture("this-file-does-not-exist.yaml"))
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// 12. loadAgentYamlString() works with string input
// ---------------------------------------------------------------------------
describe("loadAgentYamlString() string input", () => {
  it("parses a valid YAML string and returns AgentDSL", () => {
    const yamlStr = readFileSync(fixture("valid-generic.yaml"), "utf-8");
    const dsl = loadAgentYamlString(yamlStr);
    expect(dsl.agent.id).toBe("test-generic-v1");
    expect(dsl.agent.domain).toBe("appsec");
  });

  it("throws for an invalid YAML string", () => {
    const yamlStr = readFileSync(fixture("invalid-missing-agent.yaml"), "utf-8");
    expect(() => loadAgentYamlString(yamlStr)).toThrow();
  });

  it("throws for non-mapping YAML content", () => {
    expect(() => loadAgentYamlString("42")).toThrow("mapping");
  });

  it("throws for empty string", () => {
    expect(() => loadAgentYamlString("")).toThrow();
  });

  it("parses risk-quant YAML string correctly", () => {
    const yamlStr = readFileSync(fixture("valid-risk-quant.yaml"), "utf-8");
    const dsl = loadAgentYamlString(yamlStr);
    expect(dsl.agent.id).toBe("risk-quant-v1");
    expect(dsl.reasoning.mode).toBe("llm_react");
    expect(dsl.reasoning.llm).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 13. Defaults are applied correctly
// ---------------------------------------------------------------------------
describe("Schema defaults", () => {
  it("applies default priority of medium", () => {
    const raw = {
      agent: { id: "def-v1", name: "Default Test", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test defaults" },
      reasoning: { mode: "deterministic" },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.intent.priority).toBe("medium");
  });

  it("applies default autonomy_level of bounded", () => {
    const raw = {
      agent: { id: "def-v1", name: "Default Test", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test defaults" },
      reasoning: { mode: "deterministic" },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.reasoning.autonomy_level).toBe("bounded");
  });

  it("applies default confidence_threshold of 0.75", () => {
    const raw = {
      agent: { id: "def-v1", name: "Default Test", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test defaults" },
      reasoning: { mode: "deterministic" },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.reasoning.confidence_threshold).toBe(0.75);
  });

  it("applies default empty arrays for capabilities", () => {
    const raw = {
      agent: { id: "def-v1", name: "Default Test", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test defaults" },
      reasoning: { mode: "deterministic" },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.capabilities.tools).toEqual([]);
    expect(dsl.capabilities.data_access).toEqual([]);
    expect(dsl.capabilities.graph_access).toEqual([]);
  });

  it("applies default boundaries", () => {
    const raw = {
      agent: { id: "def-v1", name: "Default Test", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test defaults" },
      reasoning: { mode: "deterministic" },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.boundaries.risk_budget).toBe("medium");
    expect(dsl.boundaries.allowed_actions).toEqual([]);
    expect(dsl.boundaries.denied_actions).toEqual([]);
    expect(dsl.boundaries.environment_scope).toEqual([]);
    expect(dsl.boundaries.approval_gates).toEqual([]);
  });

  it("applies default safety settings", () => {
    const raw = {
      agent: { id: "def-v1", name: "Default Test", domain: "appsec", version: "1.0.0" },
      intent: { goal: "Test defaults" },
      reasoning: { mode: "deterministic" },
    };
    const dsl = AgentDSLSchema.parse(raw);
    expect(dsl.safety.guardrails).toEqual([]);
    expect(dsl.safety.sandbox_profile).toBe("standard");
    expect(dsl.safety.audit_level).toBe("standard");
  });
});

// ---------------------------------------------------------------------------
// 14. Domain enum validation
// ---------------------------------------------------------------------------
describe("Domain enum validation", () => {
  it("rejects invalid domain", () => {
    const raw = {
      agent: { id: "test-v1", name: "Test", domain: "invalid_domain", version: "1.0.0" },
      intent: { goal: "Test" },
      reasoning: { mode: "deterministic" },
    };
    expect(() => AgentDSLSchema.parse(raw)).toThrow();
  });

  it("accepts all core domains", () => {
    for (const domain of ["red_team", "appsec", "ai_security", "risk_quant", "supply_chain", "compliance"]) {
      const raw = {
        agent: { id: "test-v1", name: "Test", domain, version: "1.0.0" },
        intent: { goal: "Test" },
        reasoning: { mode: "deterministic" },
        // Red team needs special safety
        ...(domain === "red_team"
          ? { safety: { sandbox_profile: "offensive_isolated", audit_level: "verbose" } }
          : {}),
      };
      const dsl = AgentDSLSchema.parse(raw);
      expect(dsl.agent.domain).toBe(domain);
    }
  });
});

// ---------------------------------------------------------------------------
// 15. LLMConfig schema validation
// ---------------------------------------------------------------------------
describe("LLMConfig schema validation", () => {
  it("applies all defaults when parsed with empty object", () => {
    const config = LLMConfigSchema.parse({});
    expect(config.provider).toBe("openai");
    expect(config.model).toBe("gpt-4o");
    expect(config.temperature).toBe(0.2);
    expect(config.max_iterations).toBe(10);
    expect(config.max_tokens).toBe(4096);
  });

  it("rejects temperature above 2.0", () => {
    expect(() => LLMConfigSchema.parse({ temperature: 2.5 })).toThrow();
  });

  it("rejects temperature below 0.0", () => {
    expect(() => LLMConfigSchema.parse({ temperature: -0.1 })).toThrow();
  });

  it("rejects max_iterations above 50", () => {
    expect(() => LLMConfigSchema.parse({ max_iterations: 51 })).toThrow();
  });

  it("rejects max_iterations below 1", () => {
    expect(() => LLMConfigSchema.parse({ max_iterations: 0 })).toThrow();
  });

  it("rejects max_tokens below 256", () => {
    expect(() => LLMConfigSchema.parse({ max_tokens: 100 })).toThrow();
  });

  it("rejects max_tokens above 32768", () => {
    expect(() => LLMConfigSchema.parse({ max_tokens: 40000 })).toThrow();
  });
});
