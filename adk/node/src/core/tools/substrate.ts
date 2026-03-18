/**
 * ZAK Tool Substrate — zakTool() higher-order function and ToolRegistry.
 *
 * Design:
 * - zakTool(opts)(fn) marks a function as a ZAK tool
 * - Tools are policy-aware: before execution, the tool checks action_id against the PolicyEngine
 * - Tools emit audit events on call and result
 * - ToolExecutor is the call entry point for agents (handles policy + audit)
 *
 * TypeScript equivalent of zak/core/tools/substrate.py.
 */

import { AuditEventType, toolCalledEvent } from "../audit/events.js";
import { AuditLogger } from "../audit/logger.js";
import { PolicyEngine } from "../policy/engine.js";
import type { AgentContext } from "../runtime/agent.js";
import { getAgentId } from "../runtime/agent.js";

// ---------------------------------------------------------------------------
// ToolMetadata
// ---------------------------------------------------------------------------

export interface ToolMetadata {
  name: string;
  description: string;
  actionId: string;
  requiresContext: boolean;
  tags: string[];
}

// ---------------------------------------------------------------------------
// Tool function type
// ---------------------------------------------------------------------------

/**
 * A tool function that optionally receives AgentContext as first arg.
 */
export type ToolFunction = (...args: unknown[]) => unknown;

/**
 * A decorated tool function with metadata attached.
 */
export interface ZakToolFunction extends ToolFunction {
  _zakTool: ToolMetadata;
}

// ---------------------------------------------------------------------------
// ToolRegistry
// ---------------------------------------------------------------------------

let _toolRegistryInstance: ToolRegistryImpl | null = null;

class ToolRegistryImpl {
  private _tools = new Map<string, [ToolMetadata, ToolFunction]>();

  register(metadata: ToolMetadata, fn: ToolFunction): void {
    this._tools.set(metadata.actionId, [metadata, fn]);
  }

  getTool(actionId: string): [ToolMetadata, ToolFunction] | undefined {
    return this._tools.get(actionId);
  }

  allTools(): ToolMetadata[] {
    return [...this._tools.values()].map(([m]) => m);
  }

  isRegistered(actionId: string): boolean {
    return this._tools.has(actionId);
  }

  clear(): void {
    this._tools.clear();
  }

  summary(): string {
    if (this._tools.size === 0) {
      return "No tools registered.";
    }
    const lines = ["Registered tools:"];
    for (const [meta] of this._tools.values()) {
      lines.push(
        `  ${meta.actionId.padEnd(30)} \u2014 ${meta.description}`
      );
    }
    return lines.join("\n");
  }
}

/**
 * Singleton registry of all zakTool-decorated functions.
 */
export class ToolRegistry {
  static get(): ToolRegistryImpl {
    if (_toolRegistryInstance === null) {
      _toolRegistryInstance = new ToolRegistryImpl();
    }
    return _toolRegistryInstance;
  }
}

// ---------------------------------------------------------------------------
// zakTool() — higher-order function
// ---------------------------------------------------------------------------

/**
 * Marks a function as a ZAK tool and registers it in the ToolRegistry.
 *
 * @param opts - Tool metadata options.
 * @returns A decorator that registers and wraps the function.
 *
 * @example
 * ```ts
 * const readAsset = zakTool({
 *   name: "read_asset",
 *   description: "Read an asset node from the SIF graph",
 * })((context: AgentContext, assetId: string) => {
 *   // ... implementation
 * });
 * ```
 */
export function zakTool(opts: {
  name: string;
  description?: string;
  actionId?: string;
  tags?: string[];
  requiresContext?: boolean;
}) {
  const actionId = opts.actionId ?? opts.name.toLowerCase().replace(/ /g, "_");

  return <T extends ToolFunction>(fn: T): T & { _zakTool: ToolMetadata } => {
    const meta: ToolMetadata = {
      name: opts.name,
      description: opts.description ?? "",
      actionId,
      requiresContext: opts.requiresContext ?? true,
      tags: opts.tags ?? [],
    };

    ToolRegistry.get().register(meta, fn);

    // Attach metadata to the function
    const wrapped = fn as T & { _zakTool: ToolMetadata };
    wrapped._zakTool = meta;
    return wrapped;
  };
}

// ---------------------------------------------------------------------------
// ToolExecutor
// ---------------------------------------------------------------------------

const _executorPolicy = new PolicyEngine();

/**
 * Policy-aware tool call executor.
 *
 * Always use this instead of calling tools directly so that:
 * - Policy is enforced before the tool runs
 * - Audit events are emitted on call and result
 * - Tool capability check validates the tool is in the agent's allowed tools list
 */
export class ToolExecutor {
  /**
   * Execute a zakTool function with full policy and audit wrapping.
   *
   * @param toolFn  The zakTool-decorated function to call.
   * @param context Agent execution context.
   * @param kwargs  Arguments to pass to the tool function.
   * @returns The return value of toolFn.
   * @throws PermissionError if policy denies the tool's action_id.
   * @throws Error if the tool is not a zakTool or not in capabilities.
   */
  static call(
    toolFn: ZakToolFunction,
    context: AgentContext,
    kwargs: Record<string, unknown> = {}
  ): unknown {
    const meta = toolFn._zakTool;
    if (!meta) {
      throw new Error(
        `'${toolFn.name || "anonymous"}' is not a zakTool. ` +
          "Decorate it with zakTool() before using ToolExecutor.call()."
      );
    }

    const agentId = getAgentId(context);
    const logger = new AuditLogger(context.tenantId, agentId, context.traceId);

    // Capability check — tool must be declared in agent's capabilities.tools
    const agentTools = context.dsl.capabilities.tools;
    if (agentTools.length > 0 && !agentTools.includes(meta.actionId)) {
      throw new Error(
        `Tool '${meta.actionId}' is not declared in agent capabilities.tools. ` +
          `Declared tools: [${agentTools.join(", ")}]`
      );
    }

    // Policy check against the tool's action_id
    const decision = _executorPolicy.evaluate(
      context.dsl,
      meta.actionId,
      context.environment
    );

    if (!decision.allowed) {
      logger.logRaw(AuditEventType.POLICY_BLOCKED, {
        action: meta.actionId,
        reason: decision.reason,
        tool: meta.name,
      });
      throw new Error(
        `Policy denied tool '${meta.name}' (actionId=${meta.actionId}): ` +
          decision.reason
      );
    }

    // Emit tool_called audit event
    logger.emit(
      toolCalledEvent(
        agentId,
        context.tenantId,
        context.traceId,
        meta.name,
        JSON.stringify(kwargs).slice(0, 200)
      )
    );

    // Execute — inject context if the tool requires it
    let result: unknown;
    if (meta.requiresContext) {
      result = toolFn(context, ...Object.values(kwargs));
    } else {
      result = toolFn(...Object.values(kwargs));
    }

    // Emit tool_result audit event
    logger.logRaw(AuditEventType.TOOL_RESULT, {
      tool: meta.name,
      resultType: typeof result,
    });

    return result;
  }
}
