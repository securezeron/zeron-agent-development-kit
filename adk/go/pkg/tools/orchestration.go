package tools

import (
	"fmt"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/runtime"
)

// SpawnAgentTool is a meta-tool that spawns a sub-agent by domain name.
//
// In the ReAct loop, the orchestrating agent can call this tool to delegate
// a subtask to a specialised domain agent. The spawned agent runs within
// the same tenant and trace context.
//
// Required argument: "domain" (string) — the domain name to resolve.
// Optional argument: "goal" (string) — override the sub-agent's goal.
var SpawnAgentTool = NewZakTool(
	"Spawn Agent",
	"Spawn a sub-agent by domain name to handle a specialised security task",
	spawnAgentFn,
	WithActionID("spawn_agent"),
	WithTags("orchestration", "agent"),
)

func spawnAgentFn(ctx *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	domain, _ := args["domain"].(string)
	if domain == "" {
		return nil, fmt.Errorf("spawn_agent requires 'domain' argument")
	}

	// Resolve the agent factory from the global registry.
	reg := runtime.AgentRegistryGet()
	factory, err := reg.Resolve(domain)
	if err != nil {
		return nil, fmt.Errorf("spawn_agent: failed to resolve domain '%s': %w", domain, err)
	}

	// Create the sub-agent.
	subAgent := factory()

	// Build a child context that inherits tenant + trace from the parent.
	childDSL := ctx.DSL // inherit DSL from parent for now
	childCtx := runtime.NewAgentContext(ctx.TenantID, ctx.TraceID, childDSL)
	childCtx.Environment = ctx.Environment
	childCtx.Metadata["parent_agent_id"] = ctx.AgentID()
	childCtx.Metadata["spawned_domain"] = domain

	// Override goal if provided.
	if goal, ok := args["goal"].(string); ok && goal != "" {
		childCtx.Metadata["override_goal"] = goal
	}

	// Execute the sub-agent via the standard executor.
	executor := runtime.NewExecutor()
	result := executor.Run(subAgent, childCtx)

	return map[string]interface{}{
		"domain":      domain,
		"success":     result.Success,
		"agent_id":    result.AgentID,
		"output":      result.Output,
		"errors":      result.Errors,
		"duration_ms": result.DurationMs,
	}, nil
}
