/**
 * ZAK Runtime -- LLMAgent base class.
 *
 * The LLMAgent implements the ReAct (Reason + Act) pattern, adding a proper
 * LLM reasoning loop on top of ZAK's existing governance infrastructure:
 *
 *   Perceive (read context) -> Reason (LLM call) -> Act (ToolExecutor) -> Observe -> repeat
 *
 * Key design principles:
 *   - Existing PolicyEngine / AuditLogger / TenantIsolation are fully preserved
 *   - Every LLM tool call routes through ToolExecutor (policy + audit fires)
 *   - max_iterations cap prevents runaway agents
 *   - LLM provider / model / temperature read from DSL's reasoning.llm block
 *   - Agents opt-in by subclassing LLMAgent instead of BaseAgent
 *
 * TypeScript equivalent of zak/core/runtime/llm_agent.py.
 */

import { AuditEventType } from "../audit/events.js";
import { AuditLogger } from "../audit/logger.js";
import type { ChatMessage, ToolSchema } from "../llm/base.js";
import { getLLMClient } from "../llm/registry.js";
import { ToolExecutor, type ZakToolFunction } from "../tools/substrate.js";
import {
  BaseAgent,
  agentResultFail,
  agentResultOk,
  getAgentId,
  type AgentContext,
  type AgentResult,
} from "./agent.js";

// ---------------------------------------------------------------------------
// Stream event types
// ---------------------------------------------------------------------------

export type StreamEvent =
  | { type: "start"; traceId: string; tenantId: string }
  | { type: "iteration"; iteration: number }
  | {
      type: "tool_call";
      iteration: number;
      tool: string;
      arguments: Record<string, unknown>;
    }
  | {
      type: "tool_result";
      iteration: number;
      tool: string;
      resultPreview: string;
      error: boolean;
    }
  | { type: "reasoning"; iteration: number; content: string }
  | {
      type: "complete";
      output: Record<string, unknown>;
      iterations: number;
      llmUsage: Record<string, number>;
    }
  | { type: "error"; message: string };

// ---------------------------------------------------------------------------
// Schema generation -- @zakTool -> OpenAI function-call JSON schema
// ---------------------------------------------------------------------------

/** Type map from common JavaScript constructor names to JSON Schema types. */
const _jsTypeMap: Record<string, string> = {
  string: "string",
  number: "number",
  boolean: "boolean",
  object: "object",
  array: "array",
};

/**
 * Auto-generate OpenAI function-calling schemas from zakTool-decorated functions.
 *
 * Reads the tool metadata to build the schema. Parameter info is derived from
 * the metadata and from the function itself (parameter names, defaults).
 *
 * @param tools List of zakTool-decorated functions.
 * @returns Array of OpenAI-compatible tool schemas.
 */
export function buildOpenAISchema(
  tools: ZakToolFunction[],
): ToolSchema[] {
  const schemas: ToolSchema[] = [];

  for (const toolFn of tools) {
    const meta = toolFn._zakTool;
    if (!meta) continue;

    // Extract parameter info from the function
    const fnStr = toolFn.toString();
    const paramNames = _extractParamNames(fnStr);

    // Filter out 'context'/'_context' and 'self' parameters
    // Both 'context' and '_context' are used for the AgentContext injection
    const filteredParams = paramNames.filter(
      (p) =>
        p.name !== "context" &&
        p.name !== "_context" &&
        p.name !== "self",
    );

    const properties: Record<string, { type: string; description: string }> =
      {};
    const required: string[] = [];

    for (const param of filteredParams) {
      properties[param.name] = {
        type: param.type ?? "string",
        description: `${param.name} parameter`,
      };
      if (!param.hasDefault) {
        required.push(param.name);
      }
    }

    schemas.push({
      type: "function",
      function: {
        name: meta.actionId,
        description: meta.description || meta.name,
        parameters: {
          type: "object",
          properties,
          required,
        },
      },
    });
  }

  return schemas;
}

/** Extracted parameter info */
interface ParamInfo {
  name: string;
  type: string | undefined;
  hasDefault: boolean;
}

/**
 * Extract parameter names from a function string representation.
 * This is a best-effort parser for function signatures.
 */
function _extractParamNames(fnStr: string): ParamInfo[] {
  // Match function parameters between parentheses
  const match = fnStr.match(/\(([^)]*)\)/);
  if (!match || !match[1]) return [];

  const paramStr = match[1].trim();
  if (paramStr.length === 0) return [];

  // Split by comma, handling nested types
  const params: ParamInfo[] = [];
  let depth = 0;
  let current = "";

  for (const ch of paramStr) {
    if (ch === "<" || ch === "{" || ch === "[" || ch === "(") {
      depth++;
      current += ch;
    } else if (ch === ">" || ch === "}" || ch === "]" || ch === ")") {
      depth--;
      current += ch;
    } else if (ch === "," && depth === 0) {
      params.push(_parseParam(current.trim()));
      current = "";
    } else {
      current += ch;
    }
  }

  if (current.trim()) {
    params.push(_parseParam(current.trim()));
  }

  return params;
}

/**
 * Parse a single parameter string like "name: string" or "name = 'default'"
 */
function _parseParam(param: string): ParamInfo {
  const hasDefault = param.includes("=");

  // Strip default value
  let withoutDefault = param;
  if (hasDefault) {
    withoutDefault = param.split("=")[0].trim();
  }

  // Split by colon for type annotation
  const colonIdx = withoutDefault.indexOf(":");
  if (colonIdx >= 0) {
    const name = withoutDefault.slice(0, colonIdx).trim();
    const rawType = withoutDefault.slice(colonIdx + 1).trim().toLowerCase();
    const jsonType = _jsTypeMap[rawType] ?? "string";
    return { name, type: jsonType, hasDefault };
  }

  return { name: withoutDefault.trim(), type: "string", hasDefault };
}

// ---------------------------------------------------------------------------
// LLMAgent base class
// ---------------------------------------------------------------------------

/**
 * LLM-powered agent base class using the ReAct (Reason + Act) loop.
 *
 * Subclasses define:
 *   - systemPrompt(context) -> string    -- the agent's goal and persona
 *   - tools (property) -> list           -- zakTool functions the agent can call
 *
 * The ReAct loop, tool schema generation, and policy routing are handled
 * automatically. Existing governance infrastructure is fully preserved.
 */
export abstract class LLMAgent extends BaseAgent {
  /** Default maximum ReAct iterations (override in subclass or DSL). */
  maxIterations = 10;

  /**
   * Define the agent's goal and persona.
   *
   * This is the system prompt sent to the LLM. It should:
   * - State the agent's security objective clearly
   * - Describe the expected tool call sequence
   * - Specify the desired output format (structured JSON)
   * - Remind the LLM to base every claim on tool output
   */
  abstract systemPrompt(context: AgentContext): string;

  /**
   * Return the list of zakTool functions this agent may call.
   *
   * These functions must also be declared in the agent's DSL
   * capabilities.tools list (otherwise ToolExecutor will reject them).
   */
  abstract get tools(): ZakToolFunction[];

  /**
   * Core execution using the ReAct loop.
   *
   * Flow:
   *   1. Build initial messages (system + user goal)
   *   2. Call LLM -> receive reasoning + tool calls
   *   3. Execute tool calls via ToolExecutor (policy + audit)
   *   4. Append tool results to conversation
   *   5. Repeat until LLM says "stop" or max_iterations reached
   */
  async execute(context: AgentContext): Promise<AgentResult> {
    // -- LLM config from DSL reasoning.llm block --
    const llmCfg = _extractLLMConfig(context);
    const provider = llmCfg.provider;
    const model = llmCfg.model;
    const temperature = llmCfg.temperature;
    const maxIter = llmCfg.maxIterations ?? this.maxIterations;
    const maxTokens = llmCfg.maxTokens;

    const client = getLLMClient({ provider, model });

    // -- Build initial conversation --
    const messages: ChatMessage[] = [
      { role: "system", content: this.systemPrompt(context) },
      {
        role: "user",
        content:
          `Execute your security analysis goal for tenant '${context.tenantId}'. ` +
          `Environment: ${context.environment}. Trace ID: ${context.traceId}. ` +
          "Use your available tools to gather data, then provide a structured summary.",
      },
    ];

    const toolsSchema = buildOpenAISchema(this.tools);
    const agentId = getAgentId(context);
    const audit = new AuditLogger(context.tenantId, agentId, context.traceId);

    const totalUsage: Record<string, number> = {
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
    };
    const reasoningTrace: Array<Record<string, unknown>> = [];

    // -- ReAct loop --
    for (let iteration = 0; iteration < maxIter; iteration++) {
      audit.logRaw(AuditEventType.TOOL_CALLED, {
        phase: "llm_reason",
        iteration: iteration + 1,
        messagesInContext: messages.length,
      });

      const response = await client.chat(
        messages,
        toolsSchema,
        maxTokens,
        temperature,
      );

      // Accumulate token usage
      for (const k of Object.keys(totalUsage)) {
        totalUsage[k] += response.usage[k] ?? 0;
      }

      // -- LLM decided it's done (finishReason == "stop") --
      if (response.finishReason === "stop" || response.toolCalls.length === 0) {
        const conclusion = response.content ?? "Task completed successfully.";
        reasoningTrace.push({
          iteration: iteration + 1,
          type: "conclusion",
          content: conclusion,
        });

        audit.logRaw(AuditEventType.TOOL_RESULT, {
          phase: "llm_conclusion",
          iteration: iteration + 1,
          tokensUsed: totalUsage.totalTokens,
        });

        return agentResultOk(context, {
          summary: conclusion,
          reasoning_trace: reasoningTrace,
          iterations: iteration + 1,
          llm_usage: totalUsage,
          provider: provider ?? "openai",
          model: model ?? null,
        });
      }

      // -- Process tool calls --
      const toolResults: ChatMessage[] = [];

      for (const toolCall of response.toolCalls) {
        const traceEntry: Record<string, unknown> = {
          iteration: iteration + 1,
          type: "tool_call",
          tool: toolCall.name,
          arguments: toolCall.arguments,
        };
        reasoningTrace.push(traceEntry);

        const toolFn = this._resolveTool(toolCall.name);
        if (!toolFn) {
          const err = { error: `Unknown tool: ${toolCall.name}` };
          traceEntry.result = err;
          toolResults.push(_toolResultMsg(toolCall, err));
          continue;
        }

        try {
          const result = ToolExecutor.call(toolFn, context, toolCall.arguments);
          traceEntry.result = result;
          toolResults.push(_toolResultMsg(toolCall, result));
        } catch (exc) {
          const err = {
            error: exc instanceof Error ? exc.message : String(exc),
          };
          traceEntry.result = err;
          toolResults.push(_toolResultMsg(toolCall, err));
        }
      }

      // Append assistant message + all tool results to context
      messages.push({
        role: "assistant",
        content: response.content,
        tool_calls: response.toolCalls.map((tc) => ({
          id: tc.id,
          type: "function",
          function: {
            name: tc.name,
            arguments: JSON.stringify(tc.arguments),
          },
        })),
      });
      messages.push(...toolResults);
    }

    // -- Max iterations reached without natural conclusion --
    return agentResultFail(context, [
      `LLM agent reached max_iterations (${maxIter}) without a conclusion. ` +
        "Consider increasing max_iterations in the DSL reasoning.llm block.",
    ]);
  }

  /**
   * Streaming variant of execute(). Yields event objects at each ReAct step
   * so callers can push them to an SSE endpoint in real time.
   */
  async *executeStream(context: AgentContext): AsyncGenerator<StreamEvent> {
    // -- LLM config from DSL --
    const llmCfg = _extractLLMConfig(context);
    const provider = llmCfg.provider;
    const model = llmCfg.model;
    const temperature = llmCfg.temperature;
    const maxIter = llmCfg.maxIterations ?? this.maxIterations;
    const maxTokens = llmCfg.maxTokens;

    let client;
    try {
      client = getLLMClient({ provider, model });
    } catch (exc) {
      yield {
        type: "error",
        message: `LLM client init failed: ${exc instanceof Error ? exc.message : String(exc)}`,
      };
      return;
    }

    yield {
      type: "start",
      traceId: context.traceId,
      tenantId: context.tenantId,
    };

    // -- Build initial conversation --
    const messages: ChatMessage[] = [
      { role: "system", content: this.systemPrompt(context) },
      {
        role: "user",
        content:
          `Execute your security analysis goal for tenant '${context.tenantId}'. ` +
          `Environment: ${context.environment}. Trace ID: ${context.traceId}. ` +
          "Use your available tools to gather data, then provide a structured summary.",
      },
    ];

    const toolsSchema = buildOpenAISchema(this.tools);
    const agentId = getAgentId(context);
    const audit = new AuditLogger(context.tenantId, agentId, context.traceId);

    const totalUsage: Record<string, number> = {
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
    };
    const reasoningTrace: Array<Record<string, unknown>> = [];

    // -- ReAct loop --
    for (let iteration = 0; iteration < maxIter; iteration++) {
      yield { type: "iteration", iteration: iteration + 1 };

      audit.logRaw(AuditEventType.TOOL_CALLED, {
        phase: "llm_reason",
        iteration: iteration + 1,
        messagesInContext: messages.length,
      });

      let response;
      try {
        response = await client.chat(
          messages,
          toolsSchema,
          maxTokens,
          temperature,
        );
      } catch (exc) {
        yield {
          type: "error",
          message: `LLM call failed at iteration ${iteration + 1}: ${exc instanceof Error ? exc.message : String(exc)}`,
        };
        return;
      }

      for (const k of Object.keys(totalUsage)) {
        totalUsage[k] += response.usage[k] ?? 0;
      }

      // -- LLM decided it's done --
      if (response.finishReason === "stop" || response.toolCalls.length === 0) {
        const conclusion = response.content ?? "Task completed successfully.";
        reasoningTrace.push({
          iteration: iteration + 1,
          type: "conclusion",
          content: conclusion,
        });

        yield {
          type: "reasoning",
          iteration: iteration + 1,
          content: conclusion.slice(0, 1000),
        };

        audit.logRaw(AuditEventType.TOOL_RESULT, {
          phase: "llm_conclusion",
          iteration: iteration + 1,
          tokensUsed: totalUsage.totalTokens,
        });

        const output = {
          summary: conclusion,
          reasoning_trace: reasoningTrace,
          iterations: iteration + 1,
          llm_usage: totalUsage,
          provider: provider ?? "openai",
          model: model ?? null,
        };

        yield {
          type: "complete",
          output,
          iterations: iteration + 1,
          llmUsage: totalUsage,
        };
        return;
      }

      // -- Process tool calls --
      const toolResults: ChatMessage[] = [];

      for (const toolCall of response.toolCalls) {
        yield {
          type: "tool_call",
          iteration: iteration + 1,
          tool: toolCall.name,
          arguments: toolCall.arguments,
        };

        const traceEntry: Record<string, unknown> = {
          iteration: iteration + 1,
          type: "tool_call",
          tool: toolCall.name,
          arguments: toolCall.arguments,
        };
        reasoningTrace.push(traceEntry);

        const toolFn = this._resolveTool(toolCall.name);
        if (!toolFn) {
          const err = { error: `Unknown tool: ${toolCall.name}` };
          traceEntry.result = err;
          toolResults.push(_toolResultMsg(toolCall, err));
          yield {
            type: "tool_result",
            iteration: iteration + 1,
            tool: toolCall.name,
            resultPreview: JSON.stringify(err).slice(0, 300),
            error: true,
          };
          continue;
        }

        try {
          const result = ToolExecutor.call(toolFn, context, toolCall.arguments);
          traceEntry.result = result;
          toolResults.push(_toolResultMsg(toolCall, result));
          yield {
            type: "tool_result",
            iteration: iteration + 1,
            tool: toolCall.name,
            resultPreview: String(result).slice(0, 300),
            error: false,
          };
        } catch (exc) {
          const errMsg = exc instanceof Error ? exc.message : String(exc);
          const err = { error: errMsg };
          traceEntry.result = err;
          toolResults.push(_toolResultMsg(toolCall, err));
          yield {
            type: "tool_result",
            iteration: iteration + 1,
            tool: toolCall.name,
            resultPreview: JSON.stringify(err).slice(0, 300),
            error: true,
          };
        }
      }

      // Append assistant + tool results to context
      messages.push({
        role: "assistant",
        content: response.content,
        tool_calls: response.toolCalls.map((tc) => ({
          id: tc.id,
          type: "function",
          function: {
            name: tc.name,
            arguments: JSON.stringify(tc.arguments),
          },
        })),
      });
      messages.push(...toolResults);
    }

    // -- Max iterations reached --
    yield {
      type: "error",
      message:
        `LLM agent reached max_iterations (${maxIter}) without a conclusion. ` +
        "Consider increasing max_iterations in the DSL reasoning.llm block.",
    };
  }

  // -- Helpers --

  /**
   * Find the zakTool function by its actionId from this agent's tool list.
   */
  private _resolveTool(actionId: string): ZakToolFunction | undefined {
    for (const fn of this.tools) {
      const meta = fn._zakTool;
      if (meta && meta.actionId === actionId) {
        return fn;
      }
    }
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Extract LLM configuration from the DSL reasoning.llm block.
 */
function _extractLLMConfig(context: AgentContext): {
  provider: string | undefined;
  model: string | undefined;
  temperature: number;
  maxIterations: number | undefined;
  maxTokens: number;
} {
  const reasoning = context.dsl.reasoning;
  const llmBlock = reasoning?.llm;

  if (!llmBlock || typeof llmBlock !== "object") {
    return {
      provider: undefined,
      model: undefined,
      temperature: 0.2,
      maxIterations: undefined,
      maxTokens: 4096,
    };
  }

  const cfg = llmBlock as Record<string, unknown>;
  return {
    provider: (cfg.provider as string) ?? undefined,
    model: (cfg.model as string) ?? undefined,
    temperature: typeof cfg.temperature === "number" ? cfg.temperature : 0.2,
    maxIterations:
      typeof cfg.max_iterations === "number" ? cfg.max_iterations : undefined,
    maxTokens: typeof cfg.max_tokens === "number" ? cfg.max_tokens : 4096,
  };
}

/**
 * Format a tool result as an OpenAI-compatible tool message.
 */
function _toolResultMsg(
  toolCall: { id: string; name: string },
  result: unknown,
): ChatMessage {
  return {
    role: "tool",
    content: typeof result === "string" ? result : JSON.stringify(result),
    tool_call_id: toolCall.id,
  };
}
