/**
 * ZAK Tool: spawnAgent -- allows agents to spawn sub-agents by domain name.
 *
 * This tool uses the AgentRegistry to resolve the agent class for a given
 * security domain, creates a fresh AgentContext, and runs the sub-agent via
 * AgentExecutor.
 *
 * This enables hierarchical agent orchestration where a top-level coordinator
 * agent can delegate work to specialized domain agents.
 */

import type { AgentContext, AgentResult } from "../runtime/agent.js";
import { createAgentContext, getAgentId } from "../runtime/agent.js";
import { AgentExecutor } from "../runtime/executor.js";
import { AgentRegistry } from "../runtime/registry.js";
import { zakTool, type ToolFunction } from "./substrate.js";

/**
 * Spawn a sub-agent by security domain name.
 *
 * The sub-agent is resolved from the AgentRegistry, receives a fresh
 * AgentContext (inheriting tenantId and traceId from the parent), and
 * is executed via AgentExecutor with full policy + audit enforcement.
 *
 * @param context   Parent agent's execution context.
 * @param domain    The security domain of the sub-agent to spawn (e.g. "risk_quant").
 * @param goal      Optional override for the sub-agent's goal description.
 * @returns JSON string with the sub-agent's AgentResult.
 */
export const spawnAgent = zakTool({
  name: "spawn_agent",
  description:
    "Spawn a sub-agent by domain name. Resolves from AgentRegistry, " +
    "creates a child context, and runs via AgentExecutor.",
  actionId: "spawn_agent",
  tags: ["orchestration", "agent", "spawn"],
})(
  ((
    context: unknown,
    domain: unknown,
    goal?: unknown,
  ): string => {
    const ctx = context as AgentContext;
    const domainStr = String(domain);
    const goalStr = goal !== undefined ? String(goal) : undefined;

    // Resolve the agent class from registry
    let AgentClass;
    try {
      AgentClass = AgentRegistry.get().resolve(domainStr);
    } catch (err) {
      return JSON.stringify({
        success: false,
        error: `Failed to resolve agent for domain '${domainStr}': ${err instanceof Error ? err.message : String(err)}`,
      });
    }

    // Create the sub-agent instance
    const subAgent = new AgentClass();

    // Build child DSL -- inherit parent DSL but override the domain
    const childDSL = {
      ...ctx.dsl,
      agent: {
        ...ctx.dsl.agent,
        domain: domainStr as typeof ctx.dsl.agent.domain,
      },
      intent: {
        ...ctx.dsl.intent,
        ...(goalStr ? { goal: goalStr } : {}),
      },
    };

    // Create child context (inherits tenantId + traceId from parent)
    const childContext = createAgentContext({
      tenantId: ctx.tenantId,
      traceId: ctx.traceId,
      dsl: childDSL,
      environment: ctx.environment,
      metadata: {
        ...ctx.metadata,
        parentAgentId: getAgentId(ctx),
        spawnedBy: "spawn_agent",
      },
    });

    // Execute via AgentExecutor
    const executor = new AgentExecutor();

    // We cannot truly await here in a synchronous tool call.
    // Return a promise result representation that the LLM can interpret.
    let result: AgentResult | undefined;
    let error: string | undefined;

    // Use a synchronous execution approach
    const promise = executor.run(subAgent, childContext);
    promise.then(
      (r) => {
        result = r;
      },
      (e) => {
        error = e instanceof Error ? e.message : String(e);
      },
    );

    // If the sub-agent execute() was synchronous, result will be available
    if (result) {
      return JSON.stringify({
        success: result.success,
        agentId: result.agentId,
        domain: domainStr,
        output: result.output,
        errors: result.errors,
        durationMs: result.durationMs,
      });
    }

    if (error) {
      return JSON.stringify({
        success: false,
        domain: domainStr,
        error: `Sub-agent execution failed: ${error}`,
      });
    }

    // If the promise hasn't resolved yet (truly async agent), return a pending status.
    return JSON.stringify({
      success: false,
      domain: domainStr,
      error:
        "Sub-agent returned an async result that cannot be awaited in a synchronous tool call. " +
        "Use an LLMAgent sub-agent or implement spawnAgentAsync for async orchestration.",
    });
  }) as ToolFunction,
);
