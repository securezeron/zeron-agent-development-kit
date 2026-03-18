/**
 * ZAK LLM Registry -- Provider factory.
 *
 * Reads LLM_PROVIDER, LLM_MODEL, LLM_API_KEY from environment variables and
 * returns the appropriate LLMClient implementation.
 *
 * Supported providers:
 *   openai     -- OpenAI GPT-4o, GPT-4-turbo, etc.  (requires openai>=4.x)
 *   anthropic  -- Anthropic Claude models            (requires @anthropic-ai/sdk)
 *   google     -- Google Gemini models               (requires @google/generative-ai)
 *   local      -- Local Ollama deployment            (no extra dependencies)
 *   mock       -- In-memory mock client for testing
 *
 * TypeScript equivalent of zak/core/llm/registry.py.
 */

import {
  LLMClient,
  type ChatMessage,
  type LLMResponse,
  type ToolSchema,
} from "./base.js";

// ---------------------------------------------------------------------------
// MockLLMClient
// ---------------------------------------------------------------------------

/**
 * A simple mock LLM client for testing. Returns configurable responses.
 */
export class MockLLMClient extends LLMClient {
  /** Queued responses -- each chat() call shifts one off the front. */
  private _responses: LLMResponse[];
  /** Record of all chat() calls received (for assertions). */
  readonly calls: Array<{
    messages: ChatMessage[];
    tools: ToolSchema[];
    maxTokens: number;
    temperature: number;
  }> = [];

  constructor(responses?: LLMResponse | LLMResponse[]) {
    super();
    if (!responses) {
      // Default: single "stop" response
      this._responses = [
        {
          content: "Mock response: analysis complete.",
          toolCalls: [],
          finishReason: "stop",
          usage: { promptTokens: 10, completionTokens: 5, totalTokens: 15 },
        },
      ];
    } else if (Array.isArray(responses)) {
      this._responses = [...responses];
    } else {
      this._responses = [responses];
    }
  }

  async chat(
    messages: ChatMessage[],
    tools: ToolSchema[],
    maxTokens = 4096,
    temperature = 0.2,
  ): Promise<LLMResponse> {
    this.calls.push({ messages, tools, maxTokens, temperature });

    if (this._responses.length === 0) {
      // If no more queued responses, return a default stop
      return {
        content: "Mock: no more responses queued.",
        toolCalls: [],
        finishReason: "stop",
        usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
      };
    }

    return this._responses.shift()!;
  }

  /**
   * Add one or more responses to the end of the queue.
   */
  enqueue(...responses: LLMResponse[]): void {
    this._responses.push(...responses);
  }
}

// ---------------------------------------------------------------------------
// getLLMClient() factory
// ---------------------------------------------------------------------------

export interface LLMClientOptions {
  provider?: string;
  model?: string;
  apiKey?: string;
  baseUrl?: string;
}

/**
 * Return an LLMClient for the requested provider.
 *
 * Falls back to environment variables:
 *   LLM_PROVIDER -- openai | anthropic | google | local | mock (default: openai)
 *   LLM_MODEL    -- model name (provider-specific default if unset)
 *   LLM_API_KEY  -- API key (provider-specific env var if unset)
 *
 * @throws {Error} If the provider is unsupported or SDK is not installed.
 */
export function getLLMClient(opts: LLMClientOptions = {}): LLMClient {
  const resolvedProvider =
    opts.provider ?? process.env.LLM_PROVIDER ?? "openai";

  switch (resolvedProvider) {
    case "openai":
      throw new Error(
        "OpenAI LLM client is not yet implemented in the Node.js SDK. " +
          "Install openai and implement OpenAIClient, or use provider='mock' for testing."
      );

    case "anthropic":
      throw new Error(
        "Anthropic LLM client is not yet implemented in the Node.js SDK. " +
          "Install @anthropic-ai/sdk and implement AnthropicClient, or use provider='mock' for testing."
      );

    case "google":
      throw new Error(
        "Google LLM client is not yet implemented in the Node.js SDK. " +
          "Install @google/generative-ai and implement GoogleClient, or use provider='mock' for testing."
      );

    case "local":
      throw new Error(
        "Local (Ollama) LLM client is not yet implemented in the Node.js SDK. " +
          "Use provider='mock' for testing."
      );

    case "mock":
      return new MockLLMClient();

    default:
      throw new Error(
        `Unsupported LLM provider: '${resolvedProvider}'. ` +
          "Supported: openai, anthropic, google, local, mock"
      );
  }
}
