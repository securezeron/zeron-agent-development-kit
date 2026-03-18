package llm

import (
	"fmt"
	"os"
	"sync"
)

// ---------------------------------------------------------------------------
// MockLLMClient — used for testing
// ---------------------------------------------------------------------------

// MockLLMClient is a test-double LLMClient whose responses can be scripted.
type MockLLMClient struct {
	// Model is the model name passed during construction.
	Model string
	// Responses is a queue of canned responses. Each call to Chat pops the
	// first element. If the queue is empty, Chat returns a default "stop"
	// response with no content.
	Responses []*LLMResponse
	// Calls records every set of messages passed to Chat, for assertions.
	Calls [][]map[string]interface{}

	mu sync.Mutex
}

// Chat returns the next scripted response or a default stop response.
func (m *MockLLMClient) Chat(
	messages []map[string]interface{},
	tools []map[string]interface{},
	maxTokens int,
	temperature float64,
) (*LLMResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Record the call for later assertions.
	copied := make([]map[string]interface{}, len(messages))
	copy(copied, messages)
	m.Calls = append(m.Calls, copied)

	if len(m.Responses) > 0 {
		resp := m.Responses[0]
		m.Responses = m.Responses[1:]
		return resp, nil
	}

	// Default: return a stop response with placeholder content.
	content := "Mock response — no scripted responses remaining."
	return &LLMResponse{
		Content:      &content,
		ToolCalls:    nil,
		FinishReason: "stop",
		Usage: map[string]int{
			"prompt_tokens":     10,
			"completion_tokens": 5,
			"total_tokens":      15,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// GetLLMClient — provider factory
// ---------------------------------------------------------------------------

// GetLLMClient returns an LLMClient for the requested provider.
//
// Resolution order for each parameter:
//   - Explicit argument (if non-empty)
//   - Environment variable: LLM_PROVIDER, LLM_MODEL, LLM_API_KEY
//   - Default: provider="openai", model="" (provider-specific default)
//
// Currently only the "mock" provider is fully implemented. All other
// providers return an error indicating they are not yet implemented.
func GetLLMClient(provider, model, apiKey, baseURL string) (LLMClient, error) {
	// Resolve provider from env if not supplied.
	if provider == "" {
		provider = os.Getenv("LLM_PROVIDER")
	}
	if provider == "" {
		provider = "openai"
	}

	// Resolve model from env if not supplied.
	if model == "" {
		model = os.Getenv("LLM_MODEL")
	}

	// Resolve API key from env if not supplied.
	if apiKey == "" {
		apiKey = os.Getenv("LLM_API_KEY")
	}

	switch provider {
	case "mock":
		return &MockLLMClient{Model: model}, nil

	case "openai":
		return nil, fmt.Errorf("provider 'openai' is not yet implemented in the Go SDK")

	case "anthropic":
		return nil, fmt.Errorf("provider 'anthropic' is not yet implemented in the Go SDK")

	case "google":
		return nil, fmt.Errorf("provider 'google' is not yet implemented in the Go SDK")

	case "local":
		return nil, fmt.Errorf("provider 'local' (Ollama) is not yet implemented in the Go SDK")

	default:
		return nil, fmt.Errorf(
			"unsupported LLM provider: '%s'. Supported: openai, anthropic, google, local, mock",
			provider,
		)
	}
}
