/**
 * ZAK Runtime — BaseAgent, AgentContext, AgentResult.
 *
 * All security agents in ZAK inherit from BaseAgent and receive an AgentContext
 * at execution time. Results are always wrapped in AgentResult.
 *
 * TypeScript equivalent of zak/core/runtime/agent.py.
 */

import type { AgentDSL } from "../dsl/schema.js";

// ---------------------------------------------------------------------------
// AgentContext
// ---------------------------------------------------------------------------

/**
 * Runtime context injected into every agent execution.
 *
 * Carries tenant identity, trace ID, and the validated DSL for the agent.
 * This is the single source of truth for 'who is running, under which tenant,
 * with what permissions'.
 */
export interface AgentContext {
  tenantId: string;
  traceId: string;
  dsl: AgentDSL;
  environment: string;
  metadata: Record<string, unknown>;
  startedAt: Date;
}

/**
 * Create an AgentContext with defaults.
 */
export function createAgentContext(opts: {
  tenantId: string;
  traceId: string;
  dsl: AgentDSL;
  environment?: string;
  metadata?: Record<string, unknown>;
}): AgentContext {
  return {
    tenantId: opts.tenantId,
    traceId: opts.traceId,
    dsl: opts.dsl,
    environment: opts.environment ?? "staging",
    metadata: opts.metadata ?? {},
    startedAt: new Date(),
  };
}

/**
 * Get the agent ID from a context (convenience accessor).
 */
export function getAgentId(ctx: AgentContext): string {
  return ctx.dsl.agent.id;
}

// ---------------------------------------------------------------------------
// AgentResult
// ---------------------------------------------------------------------------

/**
 * Typed result envelope returned by every agent execution.
 */
export interface AgentResult {
  success: boolean;
  agentId: string;
  tenantId: string;
  traceId: string;
  output: Record<string, unknown>;
  errors: string[];
  durationMs: number;
  completedAt: Date;
}

/**
 * Create a successful AgentResult.
 */
export function agentResultOk(
  context: AgentContext,
  output: Record<string, unknown>,
  durationMs = 0
): AgentResult {
  return {
    success: true,
    agentId: getAgentId(context),
    tenantId: context.tenantId,
    traceId: context.traceId,
    output,
    errors: [],
    durationMs,
    completedAt: new Date(),
  };
}

/**
 * Create a failed AgentResult.
 */
export function agentResultFail(
  context: AgentContext,
  errors: string[],
  durationMs = 0
): AgentResult {
  return {
    success: false,
    agentId: getAgentId(context),
    tenantId: context.tenantId,
    traceId: context.traceId,
    output: {},
    errors,
    durationMs,
    completedAt: new Date(),
  };
}

// ---------------------------------------------------------------------------
// BaseAgent
// ---------------------------------------------------------------------------

/**
 * Abstract base class for all ZAK security agents.
 *
 * Every agent must implement:
 * - execute(context) → AgentResult
 *
 * Optionally override:
 * - preRun(context)  — setup / validation before main execution
 * - postRun(context, result) — cleanup / result enrichment
 */
export abstract class BaseAgent {
  /**
   * Human-readable agent name (defaults to constructor name).
   */
  get name(): string {
    return this.constructor.name;
  }

  /**
   * Optional hook called before execute(). Override for setup logic.
   */
  preRun(_context: AgentContext): void {
    // No-op by default
  }

  /**
   * Core agent logic. Must be implemented by every concrete agent.
   */
  abstract execute(context: AgentContext): AgentResult | Promise<AgentResult>;

  /**
   * Optional hook called after execute(). Override for cleanup logic.
   */
  postRun(_context: AgentContext, _result: AgentResult): void {
    // No-op by default
  }
}
