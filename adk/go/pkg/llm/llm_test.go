package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// ToolCall / LLMResponse struct tests
// ===========================================================================

func TestToolCall_Fields(t *testing.T) {
	tc := ToolCall{
		ID:   "call_123",
		Name: "read_asset",
		Arguments: map[string]interface{}{
			"asset_id": "web-server-01",
		},
	}

	assert.Equal(t, "call_123", tc.ID)
	assert.Equal(t, "read_asset", tc.Name)
	assert.Equal(t, "web-server-01", tc.Arguments["asset_id"])
}

func TestLLMResponse_WithContent(t *testing.T) {
	content := "Analysis complete. 3 high-risk findings."
	resp := LLMResponse{
		Content:      &content,
		ToolCalls:    nil,
		FinishReason: "stop",
		Usage: map[string]int{
			"prompt_tokens":     100,
			"completion_tokens": 50,
			"total_tokens":      150,
		},
	}

	require.NotNil(t, resp.Content)
	assert.Equal(t, "Analysis complete. 3 high-risk findings.", *resp.Content)
	assert.Equal(t, "stop", resp.FinishReason)
	assert.Empty(t, resp.ToolCalls)
	assert.Equal(t, 150, resp.Usage["total_tokens"])
}

func TestLLMResponse_WithToolCalls(t *testing.T) {
	resp := LLMResponse{
		Content: nil,
		ToolCalls: []ToolCall{
			{ID: "tc1", Name: "list_assets", Arguments: map[string]interface{}{}},
			{ID: "tc2", Name: "read_asset", Arguments: map[string]interface{}{"asset_id": "srv-1"}},
		},
		FinishReason: "tool_calls",
		Usage: map[string]int{
			"prompt_tokens":     80,
			"completion_tokens": 20,
			"total_tokens":      100,
		},
	}

	assert.Nil(t, resp.Content)
	assert.Len(t, resp.ToolCalls, 2)
	assert.Equal(t, "tool_calls", resp.FinishReason)
	assert.Equal(t, "list_assets", resp.ToolCalls[0].Name)
	assert.Equal(t, "srv-1", resp.ToolCalls[1].Arguments["asset_id"])
}

func TestStringPtr_Helper(t *testing.T) {
	s := StringPtr("hello")
	require.NotNil(t, s)
	assert.Equal(t, "hello", *s)
}

// ===========================================================================
// MockLLMClient tests
// ===========================================================================

func TestMockLLMClient_DefaultResponse(t *testing.T) {
	client := &MockLLMClient{Model: "test-model"}

	resp, err := client.Chat(
		[]map[string]interface{}{{"role": "user", "content": "hello"}},
		nil,
		4096,
		0.2,
	)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Content)
	assert.Contains(t, *resp.Content, "Mock response")
	assert.Equal(t, "stop", resp.FinishReason)
	assert.Empty(t, resp.ToolCalls)
	assert.Equal(t, 15, resp.Usage["total_tokens"])
}

func TestMockLLMClient_ScriptedResponses(t *testing.T) {
	content1 := "First response"
	content2 := "Second response"
	client := &MockLLMClient{
		Model: "scripted",
		Responses: []*LLMResponse{
			{Content: &content1, FinishReason: "tool_calls", ToolCalls: []ToolCall{
				{ID: "tc1", Name: "list_assets", Arguments: map[string]interface{}{}},
			}, Usage: map[string]int{"total_tokens": 50}},
			{Content: &content2, FinishReason: "stop", Usage: map[string]int{"total_tokens": 30}},
		},
	}

	// First call returns the first scripted response.
	resp1, err := client.Chat(nil, nil, 0, 0)
	require.NoError(t, err)
	assert.Equal(t, "First response", *resp1.Content)
	assert.Equal(t, "tool_calls", resp1.FinishReason)
	assert.Len(t, resp1.ToolCalls, 1)

	// Second call returns the second scripted response.
	resp2, err := client.Chat(nil, nil, 0, 0)
	require.NoError(t, err)
	assert.Equal(t, "Second response", *resp2.Content)
	assert.Equal(t, "stop", resp2.FinishReason)

	// Third call falls back to default (queue exhausted).
	resp3, err := client.Chat(nil, nil, 0, 0)
	require.NoError(t, err)
	assert.Contains(t, *resp3.Content, "Mock response")
}

func TestMockLLMClient_RecordsCalls(t *testing.T) {
	client := &MockLLMClient{}

	msgs1 := []map[string]interface{}{{"role": "system", "content": "You are a bot"}}
	msgs2 := []map[string]interface{}{{"role": "user", "content": "List assets"}}

	_, _ = client.Chat(msgs1, nil, 0, 0)
	_, _ = client.Chat(msgs2, nil, 0, 0)

	require.Len(t, client.Calls, 2)
	assert.Equal(t, "You are a bot", client.Calls[0][0]["content"])
	assert.Equal(t, "List assets", client.Calls[1][0]["content"])
}

func TestMockLLMClient_ImplementsInterface(t *testing.T) {
	var _ LLMClient = (*MockLLMClient)(nil)
}

// ===========================================================================
// GetLLMClient registry tests
// ===========================================================================

func TestGetLLMClient_MockProvider(t *testing.T) {
	client, err := GetLLMClient("mock", "test-model", "", "")

	require.NoError(t, err)
	require.NotNil(t, client)

	mock, ok := client.(*MockLLMClient)
	require.True(t, ok)
	assert.Equal(t, "test-model", mock.Model)
}

func TestGetLLMClient_OpenAI_NotImplemented(t *testing.T) {
	_, err := GetLLMClient("openai", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestGetLLMClient_Anthropic_NotImplemented(t *testing.T) {
	_, err := GetLLMClient("anthropic", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestGetLLMClient_Google_NotImplemented(t *testing.T) {
	_, err := GetLLMClient("google", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestGetLLMClient_Local_NotImplemented(t *testing.T) {
	_, err := GetLLMClient("local", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestGetLLMClient_UnsupportedProvider(t *testing.T) {
	_, err := GetLLMClient("deepseek", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported LLM provider")
	assert.Contains(t, err.Error(), "deepseek")
}

func TestGetLLMClient_DefaultProvider_IsOpenAI(t *testing.T) {
	// When no provider is set and no env var, default is openai.
	t.Setenv("LLM_PROVIDER", "")
	_, err := GetLLMClient("", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "openai")
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestGetLLMClient_EnvVarProvider(t *testing.T) {
	t.Setenv("LLM_PROVIDER", "mock")
	t.Setenv("LLM_MODEL", "env-model")

	client, err := GetLLMClient("", "", "", "")
	require.NoError(t, err)
	require.NotNil(t, client)

	mock, ok := client.(*MockLLMClient)
	require.True(t, ok)
	assert.Equal(t, "env-model", mock.Model)
}

func TestGetLLMClient_ExplicitOverridesEnv(t *testing.T) {
	t.Setenv("LLM_PROVIDER", "openai")
	t.Setenv("LLM_MODEL", "env-model")

	// Explicit "mock" should override env "openai".
	client, err := GetLLMClient("mock", "explicit-model", "", "")
	require.NoError(t, err)

	mock, ok := client.(*MockLLMClient)
	require.True(t, ok)
	assert.Equal(t, "explicit-model", mock.Model)
}

// ===========================================================================
// MockLLMClient edge cases
// ===========================================================================

func TestMockLLMClient_EmptyArguments(t *testing.T) {
	tc := ToolCall{
		ID:        "tc-empty",
		Name:      "list_assets",
		Arguments: map[string]interface{}{},
	}
	assert.NotNil(t, tc.Arguments)
	assert.Empty(t, tc.Arguments)
}

func TestMockLLMClient_NilToolCallsInResponse(t *testing.T) {
	content := "Done"
	resp := &LLMResponse{
		Content:      &content,
		ToolCalls:    nil,
		FinishReason: "stop",
		Usage:        map[string]int{"total_tokens": 10},
	}
	assert.Nil(t, resp.ToolCalls)
	assert.Equal(t, 0, len(resp.ToolCalls))
}

func TestLLMResponse_EmptyUsage(t *testing.T) {
	resp := &LLMResponse{
		Content:      nil,
		FinishReason: "error",
		Usage:        map[string]int{},
	}
	assert.Equal(t, 0, resp.Usage["total_tokens"])
}
