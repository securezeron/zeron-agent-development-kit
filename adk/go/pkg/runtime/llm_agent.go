package runtime

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/audit"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/llm"
)

// ---------------------------------------------------------------------------
// LLMAgent interface
// ---------------------------------------------------------------------------

// LLMAgent extends BaseAgent with LLM-powered ReAct (Reason + Act) support.
//
// Implementations provide:
//   - SystemPrompt(ctx) — the agent's goal and persona as a system message
//   - Tools()           — the list of ZakTool pointers the agent may call
//
// The ReAct loop, tool schema generation, and tool execution are handled
// automatically by RunLLMAgent.
type LLMAgent interface {
	// SystemPrompt returns the system prompt that defines the agent's persona,
	// goal, and expected output format for the given execution context.
	SystemPrompt(ctx *AgentContext) string

	// Tools returns the list of tools this agent is allowed to invoke.
	// Each tool carries metadata and a function pointer.
	Tools() []*LLMAgentTool
}

// LLMAgentTool is a lightweight tool descriptor used by the LLM agent.
// It mirrors the fields needed for OpenAI function-call schema generation
// and tool dispatch without importing the tools package (to avoid cycles).
type LLMAgentTool struct {
	// ActionID is the unique identifier used in function-call schemas.
	ActionID string
	// Name is the human-readable tool name.
	Name string
	// Description is a short sentence describing what the tool does.
	Description string
	// Parameters describes the JSON Schema properties for the tool.
	// Keys are parameter names; values are maps with "type" and "description".
	Parameters []LLMToolParam
	// Fn is the function to execute when the tool is called.
	Fn func(ctx *AgentContext, args map[string]interface{}) (interface{}, error)
}

// LLMToolParam describes a single parameter for an LLMAgentTool.
type LLMToolParam struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "string", "integer", "number", "boolean", "array", "object"
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// ---------------------------------------------------------------------------
// BuildOpenAISchema — convert tools to OpenAI function-call JSON
// ---------------------------------------------------------------------------

// BuildOpenAISchema converts a list of LLMAgentTool pointers into the
// OpenAI function-calling schema format (list of {"type":"function",...}).
func BuildOpenAISchema(tools []*LLMAgentTool) []map[string]interface{} {
	schemas := make([]map[string]interface{}, 0, len(tools))
	for _, tool := range tools {
		props := make(map[string]interface{})
		required := make([]string, 0)

		for _, p := range tool.Parameters {
			props[p.Name] = map[string]interface{}{
				"type":        p.Type,
				"description": p.Description,
			}
			if p.Required {
				required = append(required, p.Name)
			}
		}

		schemas = append(schemas, map[string]interface{}{
			"type": "function",
			"function": map[string]interface{}{
				"name":        tool.ActionID,
				"description": tool.Description,
				"parameters": map[string]interface{}{
					"type":       "object",
					"properties": props,
					"required":   required,
				},
			},
		})
	}
	return schemas
}

// ---------------------------------------------------------------------------
// RunLLMAgent — the ReAct loop
// ---------------------------------------------------------------------------

// RunLLMAgent executes an LLMAgent using the ReAct (Reason + Act) loop.
//
// Loop:
//  1. Build initial messages (system + user goal).
//  2. Call LLM -> receive reasoning + tool calls.
//  3. Execute tool calls (via the tool's Fn).
//  4. Append tool results to conversation.
//  5. Repeat until LLM says "stop" or max_iterations reached.
//
// The LLM client, temperature, max_tokens, and max_iterations are read from
// the DSL's reasoning.llm block. If no LLM config is present, defaults are
// used (provider=mock, temperature=0.2, max_tokens=4096, max_iterations=10).
func RunLLMAgent(agent LLMAgent, ctx *AgentContext) *AgentResult {
	start := time.Now()

	// ── Resolve LLM config from DSL ──────────────────────────────────────
	provider := ""
	model := ""
	temperature := 0.2
	maxIter := 10
	maxTokens := 4096

	if ctx.DSL != nil && ctx.DSL.Reasoning.LLM != nil {
		llmCfg := ctx.DSL.Reasoning.LLM
		if llmCfg.Provider != "" {
			provider = llmCfg.Provider
		}
		if llmCfg.Model != "" {
			model = llmCfg.Model
		}
		if llmCfg.Temperature > 0 {
			temperature = llmCfg.Temperature
		}
		if llmCfg.MaxIterations > 0 {
			maxIter = llmCfg.MaxIterations
		}
		if llmCfg.MaxTokens > 0 {
			maxTokens = llmCfg.MaxTokens
		}
	}

	// ── Get LLM client ───────────────────────────────────────────────────
	client, err := llm.GetLLMClient(provider, model, "", "")
	if err != nil {
		durationMs := float64(time.Since(start).Milliseconds())
		return ResultFail(ctx, []string{fmt.Sprintf("LLM client init failed: %s", err)}, durationMs)
	}

	// ── Build initial conversation ───────────────────────────────────────
	messages := []map[string]interface{}{
		{"role": "system", "content": agent.SystemPrompt(ctx)},
		{
			"role": "user",
			"content": fmt.Sprintf(
				"Execute your security analysis goal for tenant '%s'. "+
					"Environment: %s. Trace ID: %s. "+
					"Use your available tools to gather data, then provide a structured summary.",
				ctx.TenantID, ctx.Environment, ctx.TraceID,
			),
		},
	}

	toolsSchema := BuildOpenAISchema(agent.Tools())

	// Build a lookup map for tool dispatch.
	toolMap := make(map[string]*LLMAgentTool)
	for _, t := range agent.Tools() {
		toolMap[t.ActionID] = t
	}

	logger := audit.NewLogger(ctx.TenantID, ctx.AgentID(), ctx.TraceID)

	totalUsage := map[string]int{
		"prompt_tokens":     0,
		"completion_tokens": 0,
		"total_tokens":      0,
	}
	reasoningTrace := make([]map[string]interface{}, 0)

	// ── ReAct loop ───────────────────────────────────────────────────────
	for iteration := 0; iteration < maxIter; iteration++ {
		logger.LogRaw(audit.ToolCalled, map[string]interface{}{
			"phase":              "llm_reason",
			"iteration":          iteration + 1,
			"messages_in_context": len(messages),
		})

		response, err := client.Chat(messages, toolsSchema, maxTokens, temperature)
		if err != nil {
			durationMs := float64(time.Since(start).Milliseconds())
			return ResultFail(ctx, []string{
				fmt.Sprintf("LLM call failed at iteration %d: %s", iteration+1, err),
			}, durationMs)
		}

		// Accumulate token usage.
		for k := range totalUsage {
			totalUsage[k] += response.Usage[k]
		}

		// ── LLM decided it is done (finish_reason == "stop") ─────────
		if response.FinishReason == "stop" || len(response.ToolCalls) == 0 {
			conclusion := "Task completed successfully."
			if response.Content != nil && *response.Content != "" {
				conclusion = *response.Content
			}
			reasoningTrace = append(reasoningTrace, map[string]interface{}{
				"iteration": iteration + 1,
				"type":      "conclusion",
				"content":   conclusion,
			})

			logger.LogRaw(audit.ToolResult, map[string]interface{}{
				"phase":       "llm_conclusion",
				"iteration":   iteration + 1,
				"tokens_used": totalUsage["total_tokens"],
			})

			durationMs := float64(time.Since(start).Milliseconds())
			return ResultOk(ctx, map[string]interface{}{
				"summary":         conclusion,
				"reasoning_trace": reasoningTrace,
				"iterations":      iteration + 1,
				"llm_usage":       totalUsage,
				"provider":        provider,
				"model":           model,
			}, durationMs)
		}

		// ── Process tool calls ───────────────────────────────────────
		toolResults := make([]map[string]interface{}, 0)

		for _, tc := range response.ToolCalls {
			traceEntry := map[string]interface{}{
				"iteration": iteration + 1,
				"type":      "tool_call",
				"tool":      tc.Name,
				"arguments": tc.Arguments,
			}
			reasoningTrace = append(reasoningTrace, traceEntry)

			toolDef, found := toolMap[tc.Name]
			if !found {
				errResult := map[string]interface{}{"error": fmt.Sprintf("Unknown tool: %s", tc.Name)}
				traceEntry["result"] = errResult
				toolResults = append(toolResults, toolResultMsg(tc, errResult))
				continue
			}

			result, execErr := toolDef.Fn(ctx, tc.Arguments)
			if execErr != nil {
				errResult := map[string]interface{}{"error": execErr.Error()}
				traceEntry["result"] = errResult
				toolResults = append(toolResults, toolResultMsg(tc, errResult))
			} else {
				traceEntry["result"] = result
				toolResults = append(toolResults, toolResultMsg(tc, result))
			}
		}

		// Append assistant message + all tool results to context.
		assistantToolCalls := make([]interface{}, 0, len(response.ToolCalls))
		for _, tc := range response.ToolCalls {
			argsJSON, _ := json.Marshal(tc.Arguments)
			assistantToolCalls = append(assistantToolCalls, map[string]interface{}{
				"id":   tc.ID,
				"type": "function",
				"function": map[string]interface{}{
					"name":      tc.Name,
					"arguments": string(argsJSON),
				},
			})
		}

		contentVal := interface{}(nil)
		if response.Content != nil {
			contentVal = *response.Content
		}
		messages = append(messages, map[string]interface{}{
			"role":       "assistant",
			"content":    contentVal,
			"tool_calls": assistantToolCalls,
		})
		for _, tr := range toolResults {
			messages = append(messages, tr)
		}
	}

	// ── Max iterations reached ───────────────────────────────────────────
	durationMs := float64(time.Since(start).Milliseconds())
	return ResultFail(ctx, []string{
		fmt.Sprintf(
			"LLM agent reached max_iterations (%d) without a conclusion. "+
				"Consider increasing max_iterations in the DSL reasoning.llm block.",
			maxIter,
		),
	}, durationMs)
}

// toolResultMsg formats a tool result as an OpenAI-compatible tool message.
func toolResultMsg(tc llm.ToolCall, result interface{}) map[string]interface{} {
	var content string
	switch v := result.(type) {
	case string:
		content = v
	default:
		b, err := json.Marshal(result)
		if err != nil {
			content = fmt.Sprintf("%v", result)
		} else {
			content = string(b)
		}
	}

	return map[string]interface{}{
		"role":         "tool",
		"tool_call_id": tc.ID,
		"content":      content,
	}
}
