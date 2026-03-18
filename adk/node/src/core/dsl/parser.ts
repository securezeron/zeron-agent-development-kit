/**
 * ZAK DSL Parser — loads and validates US-ADSL YAML agent definitions.
 *
 * TypeScript equivalent of zak/core/dsl/parser.py.
 */

import { readFileSync, existsSync } from "node:fs";
import yaml from "js-yaml";
import { ZodError } from "zod";
import { AgentDSLSchema, type AgentDSL } from "./schema.js";

// ---------------------------------------------------------------------------
// Validation Result
// ---------------------------------------------------------------------------

export interface ValidationResult {
  valid: boolean;
  agentId: string | null;
  errors: string[];
}

export function formatValidationResult(result: ValidationResult): string {
  if (result.valid) {
    return `\u2705 Valid agent definition: ${result.agentId}`;
  }
  const lines = [
    `\u274C Invalid agent definition \u2014 ${result.errors.length} error(s):`,
  ];
  result.errors.forEach((err, i) => {
    lines.push(`  ${i + 1}. ${err}`);
  });
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Load and validate a US-ADSL agent YAML file.
 *
 * @param path - Path to the YAML file.
 * @returns Validated AgentDSL instance.
 * @throws Error if the file is not found, not valid YAML, or fails schema validation.
 */
export function loadAgentYaml(path: string): AgentDSL {
  if (!existsSync(path)) {
    throw new Error(`Agent definition not found: ${path}`);
  }

  const content = readFileSync(path, "utf-8");
  const raw = yaml.load(content);

  if (raw === null || raw === undefined || typeof raw !== "object") {
    throw new Error(
      `Expected a YAML mapping at root level, got ${typeof raw}`
    );
  }

  return AgentDSLSchema.parse(raw);
}

/**
 * Load and validate a US-ADSL agent definition from a raw string.
 *
 * @param yamlContent - YAML string content.
 * @returns Validated AgentDSL instance.
 * @throws Error if the content is not valid YAML or fails schema validation.
 */
export function loadAgentYamlString(yamlContent: string): AgentDSL {
  const raw = yaml.load(yamlContent);

  if (raw === null || raw === undefined || typeof raw !== "object") {
    throw new Error(
      `Expected a YAML mapping at root level, got ${typeof raw}`
    );
  }

  return AgentDSLSchema.parse(raw);
}

/**
 * Validate an agent YAML file and return a structured result.
 * Unlike loadAgentYaml(), this never throws — errors are captured in ValidationResult.
 *
 * @param path - Path to the YAML file.
 * @returns ValidationResult with valid=true or a list of human-readable errors.
 */
export function validateAgent(path: string): ValidationResult {
  // File existence check
  if (!existsSync(path)) {
    return { valid: false, agentId: null, errors: [`File not found: ${path}`] };
  }

  // YAML parse check
  let raw: unknown;
  try {
    const content = readFileSync(path, "utf-8");
    raw = yaml.load(content);
  } catch (e) {
    return {
      valid: false,
      agentId: null,
      errors: [`YAML syntax error: ${e instanceof Error ? e.message : String(e)}`],
    };
  }

  if (raw === null || raw === undefined || typeof raw !== "object") {
    return {
      valid: false,
      agentId: null,
      errors: [`Root YAML element must be a mapping, got ${typeof raw}`],
    };
  }

  // Schema validation
  try {
    const dsl = AgentDSLSchema.parse(raw);
    return { valid: true, agentId: dsl.agent.id, errors: [] };
  } catch (e) {
    if (e instanceof ZodError) {
      const errors = e.errors.map((err) => {
        const loc = err.path.join(" \u2192 ");
        return `[${loc}] ${err.message}`;
      });
      const agentId =
        typeof raw === "object" &&
        raw !== null &&
        "agent" in raw &&
        typeof (raw as Record<string, unknown>).agent === "object" &&
        (raw as Record<string, unknown>).agent !== null
          ? ((raw as Record<string, Record<string, unknown>>).agent.id as string) ?? null
          : null;
      return { valid: false, agentId, errors };
    }
    return {
      valid: false,
      agentId: null,
      errors: [e instanceof Error ? e.message : String(e)],
    };
  }
}

/**
 * Validate an agent YAML string and return a structured result.
 *
 * @param yamlContent - YAML string content.
 * @returns ValidationResult with valid=true or a list of human-readable errors.
 */
export function validateAgentString(yamlContent: string): ValidationResult {
  let raw: unknown;
  try {
    raw = yaml.load(yamlContent);
  } catch (e) {
    return {
      valid: false,
      agentId: null,
      errors: [`YAML syntax error: ${e instanceof Error ? e.message : String(e)}`],
    };
  }

  if (raw === null || raw === undefined || typeof raw !== "object") {
    return {
      valid: false,
      agentId: null,
      errors: [`Root YAML element must be a mapping, got ${typeof raw}`],
    };
  }

  try {
    const dsl = AgentDSLSchema.parse(raw);
    return { valid: true, agentId: dsl.agent.id, errors: [] };
  } catch (e) {
    if (e instanceof ZodError) {
      const errors = e.errors.map((err) => {
        const loc = err.path.join(" \u2192 ");
        return `[${loc}] ${err.message}`;
      });
      const agentId =
        typeof raw === "object" &&
        raw !== null &&
        "agent" in raw &&
        typeof (raw as Record<string, unknown>).agent === "object" &&
        (raw as Record<string, unknown>).agent !== null
          ? ((raw as Record<string, Record<string, unknown>>).agent.id as string) ?? null
          : null;
      return { valid: false, agentId, errors };
    }
    return {
      valid: false,
      agentId: null,
      errors: [e instanceof Error ? e.message : String(e)],
    };
  }
}
