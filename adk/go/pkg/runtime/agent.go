// Package runtime provides the core agent lifecycle types:
// BaseAgent, AgentContext, and AgentResult.
package runtime

import (
	"time"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
)

// AgentContext is the runtime context injected into every agent execution.
// It carries tenant identity, trace ID, and the validated DSL.
type AgentContext struct {
	TenantID    string                 `json:"tenant_id"`
	TraceID     string                 `json:"trace_id"`
	DSL         *dsl.AgentDSL          `json:"dsl"`
	Environment string                 `json:"environment"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
}

// NewAgentContext creates an AgentContext with defaults.
func NewAgentContext(tenantID, traceID string, agentDSL *dsl.AgentDSL) *AgentContext {
	return &AgentContext{
		TenantID:    tenantID,
		TraceID:     traceID,
		DSL:         agentDSL,
		Environment: "staging",
		Metadata:    make(map[string]interface{}),
		StartedAt:   time.Now().UTC(),
	}
}

// AgentID returns the agent's ID from the DSL.
func (c *AgentContext) AgentID() string {
	return c.DSL.Agent.ID
}

// AgentResult is the typed result envelope returned by every agent execution.
type AgentResult struct {
	Success     bool                   `json:"success"`
	AgentID     string                 `json:"agent_id"`
	TenantID    string                 `json:"tenant_id"`
	TraceID     string                 `json:"trace_id"`
	Output      map[string]interface{} `json:"output,omitempty"`
	Errors      []string               `json:"errors,omitempty"`
	DurationMs  float64                `json:"duration_ms"`
	CompletedAt time.Time              `json:"completed_at"`
}

// ResultOk creates a successful AgentResult.
func ResultOk(ctx *AgentContext, output map[string]interface{}, durationMs float64) *AgentResult {
	return &AgentResult{
		Success:     true,
		AgentID:     ctx.AgentID(),
		TenantID:    ctx.TenantID,
		TraceID:     ctx.TraceID,
		Output:      output,
		Errors:      []string{},
		DurationMs:  durationMs,
		CompletedAt: time.Now().UTC(),
	}
}

// ResultFail creates a failed AgentResult.
func ResultFail(ctx *AgentContext, errors []string, durationMs float64) *AgentResult {
	return &AgentResult{
		Success:     false,
		AgentID:     ctx.AgentID(),
		TenantID:    ctx.TenantID,
		TraceID:     ctx.TraceID,
		Output:      map[string]interface{}{},
		Errors:      errors,
		DurationMs:  durationMs,
		CompletedAt: time.Now().UTC(),
	}
}

// BaseAgent is the interface that all ZAK security agents must implement.
type BaseAgent interface {
	// Execute is the core agent logic.
	Execute(ctx *AgentContext) (*AgentResult, error)
}

// PreRunner is an optional interface for agents that need setup before execution.
type PreRunner interface {
	PreRun(ctx *AgentContext) error
}

// PostRunner is an optional interface for agents that need cleanup after execution.
type PostRunner interface {
	PostRun(ctx *AgentContext, result *AgentResult) error
}

// Named is an optional interface for agents that want a custom name.
type Named interface {
	Name() string
}
