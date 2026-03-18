/**
 * ZAK AgentExecutor — orchestrates the full agent lifecycle:
 *   pre_run → ([policy check] → execute) → post_run → audit
 *
 * The executor is the only place where policy enforcement and audit emission happen.
 * Agents themselves are never responsible for these cross-cutting concerns.
 *
 * TypeScript equivalent of zak/core/runtime/executor.py.
 */

import {
  agentCompletedEvent,
  agentFailedEvent,
  agentStartedEvent,
  policyBlockedEvent,
  AuditEventType,
} from "../audit/events.js";
import { AuditLogger } from "../audit/logger.js";
import { PolicyEngine, type PolicyDecision } from "../policy/engine.js";
import type { AgentContext, AgentResult, BaseAgent } from "./agent.js";
import { agentResultFail, getAgentId } from "./agent.js";

// ---------------------------------------------------------------------------
// AgentExecutor
// ---------------------------------------------------------------------------

/**
 * Executes an agent within a tenant-scoped context.
 *
 * Flow:
 *   1. Emit agent.started audit event
 *   2. Call agent.preRun()
 *   3. Evaluate pre-execution policy
 *   4. Call agent.execute()
 *   5. Call agent.postRun()
 *   6. Emit agent.completed or agent.failed audit event
 */
export class AgentExecutor {
  private _policy: PolicyEngine;

  constructor() {
    this._policy = new PolicyEngine();
  }

  /**
   * Execute `agent` within `context`, enforcing policy and emitting audit events.
   */
  async run(agent: BaseAgent, context: AgentContext): Promise<AgentResult> {
    const agentId = getAgentId(context);
    const logger = new AuditLogger(context.tenantId, agentId, context.traceId);

    // 1. Emit agent.started
    logger.emit(
      agentStartedEvent(agentId, context.tenantId, context.traceId, {
        domain: context.dsl.agent.domain,
        version: context.dsl.agent.version,
      })
    );

    const start = performance.now();

    try {
      // 2. Pre-run hook
      agent.preRun(context);

      // 3. Pre-execution policy evaluation
      const policyCheck = this._policy.evaluate(
        context.dsl,
        "agent_execute",
        context.environment
      );

      if (!policyCheck.allowed) {
        logger.emit(
          policyBlockedEvent(
            agentId,
            context.tenantId,
            context.traceId,
            "agent_execute",
            policyCheck.reason
          )
        );
        const durationMs = performance.now() - start;
        return agentResultFail(
          context,
          [`Policy denied: ${policyCheck.reason}`],
          durationMs
        );
      }

      // 4. Main execution (supports sync and async agents)
      let result = agent.execute(context);
      if (result instanceof Promise) {
        result = await result;
      }
      result.durationMs = performance.now() - start;

      // 5. Post-run hook
      agent.postRun(context, result);

      // 6. Emit completion/failure audit event
      if (result.success) {
        logger.emit(
          agentCompletedEvent(
            agentId,
            context.tenantId,
            context.traceId,
            true,
            result.durationMs
          )
        );
      } else {
        logger.emit(
          agentFailedEvent(
            agentId,
            context.tenantId,
            context.traceId,
            result.errors.join("; ")
          )
        );
      }

      return result;
    } catch (err) {
      const durationMs = performance.now() - start;
      const errorMsg = err instanceof Error ? err.message : String(err);

      logger.emit(
        agentFailedEvent(agentId, context.tenantId, context.traceId, errorMsg)
      );

      return agentResultFail(context, [errorMsg], durationMs);
    }
  }

  /**
   * Mid-execution policy check for a specific action.
   * Agents should call this before performing sensitive operations.
   */
  checkAction(
    context: AgentContext,
    action: string,
    environment?: string
  ): PolicyDecision {
    const agentId = getAgentId(context);
    const logger = new AuditLogger(context.tenantId, agentId, context.traceId);

    const decision = this._policy.evaluate(
      context.dsl,
      action,
      environment ?? context.environment
    );

    if (decision.allowed) {
      logger.logRaw(AuditEventType.POLICY_ALLOWED, { action });
    } else {
      logger.emit(
        policyBlockedEvent(
          agentId,
          context.tenantId,
          context.traceId,
          action,
          decision.reason
        )
      );
    }

    return decision;
  }
}
