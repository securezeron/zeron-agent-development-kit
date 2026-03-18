/**
 * ZAK LLM Base -- Abstract LLMClient interface and shared response types.
 *
 * All provider implementations must implement LLMClient.chat() and return
 * an LLMResponse. This keeps agents decoupled from any specific LLM SDK.
 *
 * TypeScript equivalent of zak/core/llm/base.py.
 */

// ---------------------------------------------------------------------------
// ToolCall
// ---------------------------------------------------------------------------

/**
 * A single tool call issued by the LLM.
 */
export interface ToolCall {
  /** Unique identifier for this tool call (provider-generated). */
  id: string;
  /** The name of the tool/function the LLM wants to invoke. */
  name: string;
  /** Parsed arguments for the tool call. */
  arguments: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// LLMResponse
// ---------------------------------------------------------------------------

/**
 * Unified response from any LLM provider.
 */
export interface LLMResponse {
  /** Text content (null if pure tool-call response). */
  content: string | null;
  /** Tool calls requested by the LLM. */
  toolCalls: ToolCall[];
  /** "stop" | "tool_calls" | "max_tokens" | "error" */
  finishReason: string;
  /** Token usage stats: promptTokens, completionTokens, totalTokens. */
  usage: Record<string, number>;
}

// ---------------------------------------------------------------------------
// ChatMessage
// ---------------------------------------------------------------------------

/**
 * A message in the conversation history (OpenAI-compatible format).
 */
export interface ChatMessage {
  role: string;
  content: string | null;
  tool_calls?: Array<{
    id: string;
    type: string;
    function: {
      name: string;
      arguments: string;
    };
  }>;
  tool_call_id?: string;
}

// ---------------------------------------------------------------------------
// ToolSchema
// ---------------------------------------------------------------------------

/**
 * OpenAI function-calling tool schema.
 */
export interface ToolSchema {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<string, { type: string; description: string }>;
      required: string[];
    };
  };
}

// ---------------------------------------------------------------------------
// LLMClient
// ---------------------------------------------------------------------------

/**
 * Abstract LLM client interface.
 *
 * All providers (OpenAI, Anthropic, Google, Ollama) implement this interface
 * so agents are not coupled to any specific SDK.
 */
export abstract class LLMClient {
  /**
   * Send a chat request to the LLM.
   *
   * @param messages    Conversation history in OpenAI message format.
   * @param tools       List of tool schemas in OpenAI function-call format.
   * @param maxTokens   Maximum tokens in the response.
   * @param temperature Sampling temperature (0.0 = deterministic, 1.0 = creative).
   * @returns LLMResponse with content, toolCalls, finishReason, and usage stats.
   */
  abstract chat(
    messages: ChatMessage[],
    tools: ToolSchema[],
    maxTokens?: number,
    temperature?: number,
  ): Promise<LLMResponse>;
}
