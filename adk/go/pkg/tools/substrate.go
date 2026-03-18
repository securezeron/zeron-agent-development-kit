// Package tools provides the ZAK tool substrate: ZakTool registration,
// ToolRegistry, and ToolExecutor with policy + audit integration.
package tools

import (
	"fmt"
	"strings"
	"sync"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/audit"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/policy"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/runtime"
)

// ToolMetadata holds metadata for a registered tool.
type ToolMetadata struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	ActionID        string   `json:"action_id"`
	RequiresContext bool     `json:"requires_context"`
	Tags            []string `json:"tags"`
}

// ToolFunc is a function that implements a ZAK tool.
// It receives the AgentContext and arbitrary arguments,
// and returns a result or error.
type ToolFunc func(ctx *runtime.AgentContext, args map[string]interface{}) (interface{}, error)

// ZakTool pairs metadata with a tool function.
type ZakTool struct {
	Meta ToolMetadata
	Fn   ToolFunc
}

// NewZakTool creates and registers a new ZAK tool.
func NewZakTool(name, description string, fn ToolFunc, opts ...ToolOption) *ZakTool {
	cfg := &toolConfig{
		actionID:        strings.ToLower(strings.ReplaceAll(name, " ", "_")),
		requiresContext: true,
	}
	for _, o := range opts {
		o(cfg)
	}

	tool := &ZakTool{
		Meta: ToolMetadata{
			Name:            name,
			Description:     description,
			ActionID:        cfg.actionID,
			RequiresContext: cfg.requiresContext,
			Tags:            cfg.tags,
		},
		Fn: fn,
	}

	ToolRegistryGet().Register(tool)
	return tool
}

// ToolOption configures tool creation.
type ToolOption func(*toolConfig)

type toolConfig struct {
	actionID        string
	requiresContext bool
	tags            []string
}

// WithActionID sets a custom action_id for the tool.
func WithActionID(id string) ToolOption {
	return func(c *toolConfig) { c.actionID = id }
}

// WithTags sets categorization tags for the tool.
func WithTags(tags ...string) ToolOption {
	return func(c *toolConfig) { c.tags = tags }
}

// WithoutContext marks the tool as not requiring AgentContext.
func WithoutContext() ToolOption {
	return func(c *toolConfig) { c.requiresContext = false }
}

// ---------------------------------------------------------------------------
// ToolRegistry
// ---------------------------------------------------------------------------

type toolRegistry struct {
	mu    sync.RWMutex
	tools map[string]*ZakTool
}

var (
	globalToolRegistry     *toolRegistry
	globalToolRegistryOnce sync.Once
)

// ToolRegistryGet returns the global tool registry singleton.
func ToolRegistryGet() *toolRegistry {
	globalToolRegistryOnce.Do(func() {
		globalToolRegistry = &toolRegistry{
			tools: make(map[string]*ZakTool),
		}
	})
	return globalToolRegistry
}

// Register adds a tool to the registry.
func (r *toolRegistry) Register(tool *ZakTool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[tool.Meta.ActionID] = tool
}

// GetTool returns a tool by action_id.
func (r *toolRegistry) GetTool(actionID string) (*ZakTool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[actionID]
	return t, ok
}

// AllTools returns metadata for all registered tools.
func (r *toolRegistry) AllTools() []ToolMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ToolMetadata, 0, len(r.tools))
	for _, t := range r.tools {
		result = append(result, t.Meta)
	}
	return result
}

// IsRegistered returns true if a tool with the given action_id exists.
func (r *toolRegistry) IsRegistered(actionID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.tools[actionID]
	return ok
}

// Clear removes all registered tools (for tests).
func (r *toolRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools = make(map[string]*ZakTool)
}

// Summary returns a human-readable summary of all registered tools.
func (r *toolRegistry) Summary() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.tools) == 0 {
		return "No tools registered."
	}
	lines := []string{"Registered tools:"}
	for _, t := range r.tools {
		lines = append(lines, fmt.Sprintf("  %-30s — %s", t.Meta.ActionID, t.Meta.Description))
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// ToolExecutor
// ---------------------------------------------------------------------------

// Executor provides policy-aware tool execution.
type Executor struct {
	policy *policy.Engine
}

// NewExecutor creates a new ToolExecutor.
func NewExecutor() *Executor {
	return &Executor{
		policy: policy.NewEngine(),
	}
}

// Call executes a ZakTool with full policy and audit wrapping.
func (e *Executor) Call(
	tool *ZakTool,
	ctx *runtime.AgentContext,
	args map[string]interface{},
) (interface{}, error) {
	if tool == nil {
		return nil, fmt.Errorf("tool is nil")
	}

	meta := tool.Meta
	agentID := ctx.AgentID()
	logger := audit.NewLogger(ctx.TenantID, agentID, ctx.TraceID)

	// Capability check — tool must be declared in agent's capabilities.tools
	agentTools := ctx.DSL.Capabilities.Tools
	if len(agentTools) > 0 {
		found := false
		for _, t := range agentTools {
			if t == meta.ActionID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf(
				"tool '%s' is not declared in agent capabilities.tools. Declared tools: %v",
				meta.ActionID, agentTools)
		}
	}

	// Policy check
	decision := e.policy.Evaluate(ctx.DSL, meta.ActionID, ctx.Environment, nil)
	if !decision.Allowed {
		logger.LogRaw(audit.PolicyBlocked, map[string]interface{}{
			"action": meta.ActionID,
			"reason": decision.Reason,
			"tool":   meta.Name,
		})
		return nil, fmt.Errorf(
			"policy denied tool '%s' (action_id=%s): %s",
			meta.Name, meta.ActionID, decision.Reason)
	}

	// Emit tool_called audit event
	inputSummary := fmt.Sprintf("%v", args)
	if len(inputSummary) > 200 {
		inputSummary = inputSummary[:200]
	}
	logger.Emit(audit.ToolCalledEvent(agentID, ctx.TenantID, ctx.TraceID, meta.Name, inputSummary))

	// Execute
	result, err := tool.Fn(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("tool '%s' execution failed: %w", meta.Name, err)
	}

	// Emit tool_result audit event
	logger.LogRaw(audit.ToolResult, map[string]interface{}{
		"tool":        meta.Name,
		"result_type": fmt.Sprintf("%T", result),
	})

	return result, nil
}
