/**
 * ZAK Policy Engine — in-process policy enforcement.
 *
 * Evaluates agent actions against a set of rules derived from the AgentDSL
 * boundaries and safety config. No external OPA dependency.
 *
 * TypeScript equivalent of zak/core/policy/engine.py.
 */

import type { AgentDSL } from "../dsl/schema.js";

// ---------------------------------------------------------------------------
// Policy Decision
// ---------------------------------------------------------------------------

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
}

export function permit(reason = "Action permitted by policy"): PolicyDecision {
  return { allowed: true, reason };
}

export function deny(reason: string): PolicyDecision {
  return { allowed: false, reason };
}

// ---------------------------------------------------------------------------
// Mutating verb prefixes (observe-only agents cannot use these)
// ---------------------------------------------------------------------------

const MUTATING_VERBS = [
  "write",
  "delete",
  "update",
  "create",
  "modify",
  "execute",
] as const;

// High-risk actions that require at least medium risk budget
const HIGH_RISK_ACTIONS = new Set([
  "execute_exploit",
  "deploy_payload",
  "modify_production",
]);

// ---------------------------------------------------------------------------
// Policy Engine
// ---------------------------------------------------------------------------

/**
 * Evaluates whether an action is permitted for a given agent in a tenant context.
 *
 * Rules applied in order (first deny wins):
 * 1. Explicit deny-list check
 * 2. Explicit allow-list check (if allow-list is non-empty)
 * 3. Autonomy level constraints
 * 4. Risk budget constraints
 * 5. Environment scope constraints
 * 6. Offensive agent safety constraints
 */
export class PolicyEngine {
  /**
   * Evaluate whether `action` is permitted under `dsl` constraints.
   *
   * @param dsl         The agent's parsed DSL definition.
   * @param action      Identifier of the action being requested.
   * @param environment Environment the action targets (e.g. 'production').
   * @param metadata    Optional additional context (unused in Phase 1).
   * @returns PolicyDecision with allowed=true/false and a human-readable reason.
   */
  evaluate(
    dsl: AgentDSL,
    action: string,
    environment?: string | null,
    _metadata?: Record<string, unknown> | null
  ): PolicyDecision {
    const boundaries = dsl.boundaries;

    // Rule 1 — Explicit deny-list (always wins)
    if (boundaries.denied_actions.includes(action)) {
      return deny(
        `Action '${action}' is explicitly denied by agent boundaries.`
      );
    }

    // Rule 2 — Explicit allow-list (if defined, action must be in it)
    if (
      boundaries.allowed_actions.length > 0 &&
      !boundaries.allowed_actions.includes(action)
    ) {
      return deny(
        `Action '${action}' is not in the agent's allow-list. ` +
          `Allowed: ${JSON.stringify(boundaries.allowed_actions)}`
      );
    }

    // Rule 3 — Observe-only agents cannot write/mutate anything
    if (dsl.reasoning.autonomy_level === "observe") {
      const lowerAction = action.toLowerCase();
      if (MUTATING_VERBS.some((verb) => lowerAction.startsWith(verb))) {
        return deny(
          `Action '${action}' is a mutating operation. ` +
            "Agents with autonomy_level 'observe' are read-only."
        );
      }
    }

    // Rule 4 — Risk budget: high-budget actions require sufficient risk budget
    if (HIGH_RISK_ACTIONS.has(action) && boundaries.risk_budget === "low") {
      return deny(
        `Action '${action}' requires at least risk_budget: medium. ` +
          `Current budget: ${boundaries.risk_budget}`
      );
    }

    // Rule 5 — Environment scope
    if (environment && boundaries.environment_scope.length > 0) {
      if (!boundaries.environment_scope.includes(environment)) {
        return deny(
          `Environment '${environment}' is not in scope for this agent. ` +
            `Allowed environments: ${JSON.stringify(boundaries.environment_scope)}`
        );
      }
    }

    // Rule 6 — Offensive agents: production access denied unless explicitly scoped
    if (dsl.agent.domain === "red_team") {
      if (
        environment === "production" &&
        !boundaries.environment_scope.includes("production")
      ) {
        return deny(
          "Red team agents are not permitted to target production " +
            "unless 'production' is explicitly in environment_scope."
        );
      }
    }

    return permit();
  }

  /**
   * Returns true if `action` requires human approval before execution.
   */
  checkApprovalGate(dsl: AgentDSL, action: string): boolean {
    return dsl.boundaries.approval_gates.includes(action);
  }
}
