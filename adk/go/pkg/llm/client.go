// Package llm provides the abstract LLMClient interface and shared response
// types. All provider implementations must implement LLMClient.Chat() and
// return an LLMResponse. This keeps agents decoupled from any specific LLM SDK.
package llm

// ToolCall represents a single tool/function call issued by the LLM.
type ToolCall struct {
	// ID is the unique identifier for this tool call (assigned by the LLM).
	ID string `json:"id"`
	// Name is the function/tool name the LLM wants to invoke.
	Name string `json:"name"`
	// Arguments are the parsed key-value arguments for the tool call.
	Arguments map[string]interface{} `json:"arguments"`
}

// LLMResponse is the unified response from any LLM provider.
type LLMResponse struct {
	// Content is the text content returned by the LLM.
	// nil when the response is a pure tool-call response.
	Content *string `json:"content,omitempty"`
	// ToolCalls are the tool/function calls requested by the LLM.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// FinishReason indicates why the LLM stopped generating.
	// Common values: "stop", "tool_calls", "max_tokens", "error".
	FinishReason string `json:"finish_reason"`
	// Usage contains token usage statistics (e.g. prompt_tokens,
	// completion_tokens, total_tokens).
	Usage map[string]int `json:"usage,omitempty"`
}

// LLMClient is the abstract interface for all LLM providers.
//
// All providers (OpenAI, Anthropic, Google, Ollama) implement this interface
// so agents are not coupled to any specific SDK.
type LLMClient interface {
	// Chat sends a chat request to the LLM and returns a unified response.
	//
	// Parameters:
	//   messages    - Conversation history in OpenAI message format.
	//   tools       - List of tool schemas in OpenAI function-call format.
	//   maxTokens   - Maximum tokens in the response.
	//   temperature - Sampling temperature (0.0 = deterministic, 1.0 = creative).
	//
	// Returns an LLMResponse with content, tool_calls, finish_reason, and
	// usage stats, or an error if the call fails.
	Chat(
		messages []map[string]interface{},
		tools []map[string]interface{},
		maxTokens int,
		temperature float64,
	) (*LLMResponse, error)
}

// StringPtr is a helper to create a *string from a string literal.
func StringPtr(s string) *string {
	return &s
}
