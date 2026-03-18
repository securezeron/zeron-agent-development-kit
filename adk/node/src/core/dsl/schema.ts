/**
 * ZAK Core DSL — Zod schema models for the Universal Security Agent DSL (US-ADSL).
 *
 * Every agent definition is a YAML file that validates against these schemas.
 * This is the TypeScript equivalent of zak/core/dsl/schema.py.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/** Supported security agent domains. */
export const Domain = z.enum([
  "red_team",
  "appsec",
  "ai_security",
  "risk_quant",
  "supply_chain",
  "compliance",
  // Enterprise domains
  "api_security",
  "attack_surface",
  "cloud_posture",
  "container_security",
  "cyber_insurance",
  "data_privacy",
  "iac_security",
  "iam_drift",
  "identity_risk",
  "incident_response",
  "malware_analysis",
  "network_security",
  "pentest_auto",
  "threat_detection",
  "threat_intel",
  "vuln_triage",
  "usage_metrics",
]);
export type Domain = z.infer<typeof Domain>;

/** How the agent reasons and makes decisions. */
export const ReasoningMode = z.enum([
  "deterministic",
  "rule_based",
  "llm_assisted",
  "hybrid",
  "probabilistic",
  "llm_react",
]);
export type ReasoningMode = z.infer<typeof ReasoningMode>;

/** How much autonomous action the agent is permitted to take. */
export const AutonomyLevel = z.enum([
  "observe",
  "suggest",
  "bounded",
  "high",
  "fully_autonomous",
]);
export type AutonomyLevel = z.infer<typeof AutonomyLevel>;

/** Execution priority. */
export const Priority = z.enum(["low", "medium", "high", "critical"]);
export type Priority = z.infer<typeof Priority>;

/** Maximum acceptable risk level for autonomous actions. */
export const RiskBudget = z.enum(["low", "medium", "high"]);
export type RiskBudget = z.infer<typeof RiskBudget>;

/** Execution sandboxing profile. */
export const SandboxProfile = z.enum([
  "minimal",
  "standard",
  "strict",
  "offensive_isolated",
]);
export type SandboxProfile = z.infer<typeof SandboxProfile>;

/** Verbosity of the audit trail. */
export const AuditLevel = z.enum(["minimal", "standard", "verbose"]);
export type AuditLevel = z.infer<typeof AuditLevel>;

// ---------------------------------------------------------------------------
// Sub-models
// ---------------------------------------------------------------------------

/** Identifies the agent uniquely within the platform. */
export const AgentIdentitySchema = z.object({
  id: z
    .string()
    .regex(
      /^[a-z0-9][a-z0-9-]*[a-z0-9]$/,
      "Agent id must be lowercase alphanumeric with hyphens only (e.g. 'risk-quant-v1')"
    ),
  name: z.string().min(1, "Agent name is required"),
  domain: Domain,
  version: z
    .string()
    .regex(/^\d+\.\d+\.\d+$/, "Version must be semver format (e.g. '1.0.0')"),
});
export type AgentIdentity = z.infer<typeof AgentIdentitySchema>;

/** Describes what the agent is trying to achieve. */
export const AgentIntentSchema = z.object({
  goal: z.string().min(1, "Goal is required"),
  success_criteria: z.array(z.string()).default([]),
  priority: Priority.default("medium"),
});
export type AgentIntent = z.infer<typeof AgentIntentSchema>;

/** LLM provider configuration — used when reasoning.mode = llm_react. */
export const LLMConfigSchema = z.object({
  provider: z
    .string()
    .default("openai")
    .describe("LLM provider: openai | anthropic | google | local"),
  model: z
    .string()
    .default("gpt-4o")
    .describe("Model name (e.g. gpt-4o, claude-opus-4-5, gemini-1.5-pro)"),
  temperature: z
    .number()
    .min(0.0)
    .max(2.0)
    .default(0.2)
    .describe("Sampling temperature"),
  max_iterations: z
    .number()
    .int()
    .min(1)
    .max(50)
    .default(10)
    .describe("Maximum ReAct loop iterations"),
  max_tokens: z
    .number()
    .int()
    .min(256)
    .max(32768)
    .default(4096)
    .describe("Maximum tokens per LLM response"),
});
export type LLMConfig = z.infer<typeof LLMConfigSchema>;

/** Controls how the agent thinks and decides. */
export const ReasoningConfigSchema = z.object({
  mode: ReasoningMode,
  autonomy_level: AutonomyLevel.default("bounded"),
  confidence_threshold: z
    .number()
    .min(0.0)
    .max(1.0)
    .default(0.75)
    .describe("Minimum confidence required before acting"),
  llm: LLMConfigSchema.nullable().optional().default(null),
});
export type ReasoningConfig = z.infer<typeof ReasoningConfigSchema>;

/** What the agent is allowed to use/access. */
export const CapabilitiesConfigSchema = z.object({
  tools: z.array(z.string()).default([]),
  data_access: z.array(z.string()).default([]),
  graph_access: z.array(z.string()).default([]),
});
export type CapabilitiesConfig = z.infer<typeof CapabilitiesConfigSchema>;

/** Hard constraints on agent behaviour. */
export const BoundariesConfigSchema = z
  .object({
    risk_budget: RiskBudget.default("medium"),
    allowed_actions: z.array(z.string()).default([]),
    denied_actions: z.array(z.string()).default([]),
    environment_scope: z.array(z.string()).default([]),
    approval_gates: z.array(z.string()).default([]),
  })
  .superRefine((data, ctx) => {
    const overlap = data.allowed_actions.filter((a) =>
      data.denied_actions.includes(a)
    );
    if (overlap.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `Actions [${overlap.join(", ")}] appear in both allowed_actions and denied_actions. Denied actions always take precedence — remove them from allowed_actions.`,
        path: ["allowed_actions"],
      });
    }
  });
export type BoundariesConfig = z.infer<typeof BoundariesConfigSchema>;

/** Safety guardrails applied to every execution. */
export const SafetyConfigSchema = z.object({
  guardrails: z.array(z.string()).default([]),
  sandbox_profile: SandboxProfile.default("standard"),
  audit_level: AuditLevel.default("standard"),
});
export type SafetyConfig = z.infer<typeof SafetyConfigSchema>;

// ---------------------------------------------------------------------------
// Top-level AgentDSL model
// ---------------------------------------------------------------------------

/**
 * The complete validated representation of a US-ADSL agent definition.
 *
 * Parsed from YAML by loadAgentYaml().
 *
 * Cross-field validators:
 * 1. Red team agents MUST use offensive_isolated sandbox + verbose audit
 * 2. llm_react mode auto-populates LLM config if missing
 * 3. fully_autonomous requires confidence >= 0.9
 */
export const AgentDSLSchema = z
  .object({
    agent: AgentIdentitySchema,
    intent: AgentIntentSchema,
    reasoning: ReasoningConfigSchema,
    capabilities: CapabilitiesConfigSchema.default({
      tools: [],
      data_access: [],
      graph_access: [],
    }),
    boundaries: BoundariesConfigSchema.default({
      risk_budget: "medium",
      allowed_actions: [],
      denied_actions: [],
      environment_scope: [],
      approval_gates: [],
    }),
    safety: SafetyConfigSchema.default({
      guardrails: [],
      sandbox_profile: "standard",
      audit_level: "standard",
    }),
  })
  .superRefine((data, ctx) => {
    // Rule 1: Red team agents MUST use offensive_isolated + verbose
    if (data.agent.domain === "red_team") {
      if (data.safety.sandbox_profile !== "offensive_isolated") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "Red team agents MUST use sandbox_profile: offensive_isolated. Safety requirement cannot be overridden.",
          path: ["safety", "sandbox_profile"],
        });
      }
      if (data.safety.audit_level !== "verbose") {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "Red team agents MUST use audit_level: verbose. Safety requirement cannot be overridden.",
          path: ["safety", "audit_level"],
        });
      }
    }

    // Rule 3: fully_autonomous requires confidence >= 0.9
    if (data.reasoning.autonomy_level === "fully_autonomous") {
      if (data.reasoning.confidence_threshold < 0.9) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "fully_autonomous autonomy level requires confidence_threshold >= 0.9",
          path: ["reasoning", "confidence_threshold"],
        });
      }
    }
  })
  .transform((data) => {
    // Rule 2: llm_react mode auto-populates LLM config if missing
    if (data.reasoning.mode === "llm_react" && !data.reasoning.llm) {
      return {
        ...data,
        reasoning: {
          ...data.reasoning,
          llm: LLMConfigSchema.parse({}),
        },
      };
    }
    return data;
  });

export type AgentDSL = z.infer<typeof AgentDSLSchema>;
