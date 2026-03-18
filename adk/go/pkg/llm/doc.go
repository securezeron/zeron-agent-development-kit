// Package llm provides the LLM client interface and provider registry for the
// ZAK Agent Development Kit.
//
// This package defines the [LLMClient] interface that all LLM providers must
// implement, and provides a factory registry for creating provider instances.
//
// # Supported Providers
//
// Out of the box, the registry supports:
//   - openai — OpenAI GPT-4o / Azure OpenAI
//   - anthropic — Anthropic Claude
//   - google — Google Gemini
//   - ollama — Local models via Ollama
//   - mock — Scriptable mock for testing
//
// # Usage
//
//	client, err := llm.GetLLMClient("openai", map[string]any{
//	    "api_key": os.Getenv("OPENAI_API_KEY"),
//	    "model":   "gpt-4o",
//	})
//
// # Testing
//
// Use [MockLLMClient] for deterministic testing:
//
//	mock := llm.NewMockLLMClient()
//	mock.QueueResponse(llm.LLMResponse{Content: "Hello"})
//	resp, _ := mock.Chat(ctx, messages, nil)
package llm
