package tools

import (
	"fmt"
	"testing"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testAgentDSL builds a valid *dsl.AgentDSL with specific tools in capabilities.
func testAgentDSL(tools ...string) *dsl.AgentDSL {
	toolsYAML := ""
	allowedYAML := ""
	for _, t := range tools {
		toolsYAML += fmt.Sprintf("\n    - %s", t)
		allowedYAML += fmt.Sprintf("\n    - %s", t)
	}
	if toolsYAML == "" {
		toolsYAML = " []"
		allowedYAML = " []"
	}

	raw := fmt.Sprintf(`
agent:
  id: tool-test-v1
  name: Tool Test Agent
  domain: appsec
  version: "1.0.0"

intent:
  goal: Test tool execution

reasoning:
  mode: deterministic
  autonomy_level: bounded
  confidence_threshold: 0.75

capabilities:
  tools:%s
  data_access: []
  graph_access: []

boundaries:
  risk_budget: medium
  allowed_actions:%s
  denied_actions: []
  environment_scope:
    - staging
    - dev
  approval_gates: []

safety:
  guardrails: []
  sandbox_profile: standard
  audit_level: standard
`, toolsYAML, allowedYAML)

	agentDSL, err := dsl.LoadAgentYamlString(raw)
	if err != nil {
		panic(fmt.Sprintf("testAgentDSL failed to parse: %v", err))
	}
	return agentDSL
}

// testDeniedToolDSL creates a DSL where a specific action is in the denied list.
func testDeniedToolDSL(toolActionID string) *dsl.AgentDSL {
	raw := fmt.Sprintf(`
agent:
  id: denied-tool-v1
  name: Denied Tool Agent
  domain: appsec
  version: "1.0.0"

intent:
  goal: Test tool policy denial

reasoning:
  mode: deterministic
  autonomy_level: bounded
  confidence_threshold: 0.75

capabilities:
  tools:
    - %s
  data_access: []
  graph_access: []

boundaries:
  risk_budget: medium
  allowed_actions: []
  denied_actions:
    - %s
  environment_scope:
    - staging
  approval_gates: []

safety:
  guardrails: []
  sandbox_profile: standard
  audit_level: standard
`, toolActionID, toolActionID)

	agentDSL, err := dsl.LoadAgentYamlString(raw)
	if err != nil {
		panic(fmt.Sprintf("testDeniedToolDSL failed to parse: %v", err))
	}
	return agentDSL
}

func toolRegistryCleanup(t *testing.T) {
	t.Cleanup(func() {
		ToolRegistryGet().Clear()
	})
}

// echoToolFunc is a simple tool function that echoes back the args.
func echoToolFunc(ctx *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"echo":      args,
		"agent_id":  ctx.AgentID(),
		"tenant_id": ctx.TenantID,
	}, nil
}

// failingToolFunc always returns an error.
func failingToolFunc(ctx *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	return nil, fmt.Errorf("tool execution error: something went wrong")
}

// ===========================================================================
// NewZakTool registration tests
// ===========================================================================

func TestNewZakTool_RegistersInRegistry(t *testing.T) {
	toolRegistryCleanup(t)

	tool := NewZakTool("Read Asset", "Reads an asset from inventory", echoToolFunc)

	require.NotNil(t, tool)
	assert.Equal(t, "Read Asset", tool.Meta.Name)
	assert.Equal(t, "Reads an asset from inventory", tool.Meta.Description)
	assert.Equal(t, "read_asset", tool.Meta.ActionID, "action_id should be lowercase with underscores")
	assert.True(t, tool.Meta.RequiresContext, "default RequiresContext should be true")
	assert.Nil(t, tool.Meta.Tags)

	// Verify it is registered in the global registry.
	assert.True(t, ToolRegistryGet().IsRegistered("read_asset"))
}

func TestNewZakTool_WithOptions(t *testing.T) {
	toolRegistryCleanup(t)

	tool := NewZakTool(
		"Scan Network",
		"Scans the network for open ports",
		echoToolFunc,
		WithActionID("custom_scan_action"),
		WithTags("network", "scanning"),
		WithoutContext(),
	)

	assert.Equal(t, "custom_scan_action", tool.Meta.ActionID)
	assert.Equal(t, []string{"network", "scanning"}, tool.Meta.Tags)
	assert.False(t, tool.Meta.RequiresContext)
	assert.True(t, ToolRegistryGet().IsRegistered("custom_scan_action"))
}

func TestNewZakTool_DefaultActionID(t *testing.T) {
	toolRegistryCleanup(t)

	tool := NewZakTool("List Active Hosts", "Lists active hosts", echoToolFunc)

	assert.Equal(t, "list_active_hosts", tool.Meta.ActionID,
		"spaces should be replaced with underscores and lowercased")
}

// ===========================================================================
// ToolRegistry tests
// ===========================================================================

func TestToolRegistry_AllTools(t *testing.T) {
	toolRegistryCleanup(t)

	NewZakTool("Tool Alpha", "Alpha description", echoToolFunc, WithActionID("alpha"))
	NewZakTool("Tool Beta", "Beta description", echoToolFunc, WithActionID("beta"))

	allTools := ToolRegistryGet().AllTools()
	assert.Len(t, allTools, 2)

	actionIDs := make([]string, len(allTools))
	for i, m := range allTools {
		actionIDs[i] = m.ActionID
	}
	assert.Contains(t, actionIDs, "alpha")
	assert.Contains(t, actionIDs, "beta")
}

func TestToolRegistry_IsRegistered(t *testing.T) {
	toolRegistryCleanup(t)

	assert.False(t, ToolRegistryGet().IsRegistered("nonexistent"))

	NewZakTool("My Tool", "desc", echoToolFunc, WithActionID("my_tool"))
	assert.True(t, ToolRegistryGet().IsRegistered("my_tool"))
	assert.False(t, ToolRegistryGet().IsRegistered("other_tool"))
}

func TestToolRegistry_GetTool(t *testing.T) {
	toolRegistryCleanup(t)

	NewZakTool("Lookup Tool", "Looks things up", echoToolFunc, WithActionID("lookup"))

	tool, ok := ToolRegistryGet().GetTool("lookup")
	assert.True(t, ok)
	require.NotNil(t, tool)
	assert.Equal(t, "Lookup Tool", tool.Meta.Name)

	_, ok = ToolRegistryGet().GetTool("missing")
	assert.False(t, ok)
}

func TestToolRegistry_Clear(t *testing.T) {
	toolRegistryCleanup(t)

	NewZakTool("Tool A", "desc A", echoToolFunc, WithActionID("tool_a"))
	NewZakTool("Tool B", "desc B", echoToolFunc, WithActionID("tool_b"))
	require.Len(t, ToolRegistryGet().AllTools(), 2)

	ToolRegistryGet().Clear()
	assert.Empty(t, ToolRegistryGet().AllTools())
	assert.False(t, ToolRegistryGet().IsRegistered("tool_a"))
}

func TestToolRegistry_Summary_Empty(t *testing.T) {
	toolRegistryCleanup(t)

	summary := ToolRegistryGet().Summary()
	assert.Equal(t, "No tools registered.", summary)
}

func TestToolRegistry_Summary_WithTools(t *testing.T) {
	toolRegistryCleanup(t)

	NewZakTool("My Tool", "Does something", echoToolFunc, WithActionID("my_tool"))

	summary := ToolRegistryGet().Summary()
	assert.Contains(t, summary, "Registered tools:")
	assert.Contains(t, summary, "my_tool")
	assert.Contains(t, summary, "Does something")
}

func TestToolRegistry_Register_OverwritesSameActionID(t *testing.T) {
	toolRegistryCleanup(t)

	NewZakTool("Tool V1", "Version 1", echoToolFunc, WithActionID("versioned_tool"))
	NewZakTool("Tool V2", "Version 2", echoToolFunc, WithActionID("versioned_tool"))

	tool, ok := ToolRegistryGet().GetTool("versioned_tool")
	require.True(t, ok)
	assert.Equal(t, "Tool V2", tool.Meta.Name, "later registration should overwrite")
	assert.Len(t, ToolRegistryGet().AllTools(), 1, "should still be 1 tool")
}

// ===========================================================================
// Executor.Call() tests
// ===========================================================================

func TestExecutor_Call_InvokesToolWithContext(t *testing.T) {
	toolRegistryCleanup(t)

	tool := NewZakTool("Read Asset", "Reads an asset", echoToolFunc, WithActionID("read_asset"))

	agentDSL := testAgentDSL("read_asset")
	ctx := runtime.NewAgentContext("tenant-tool", "trace-tool", agentDSL)

	executor := NewExecutor()
	result, err := executor.Call(tool, ctx, map[string]interface{}{"id": "asset-42"})

	require.NoError(t, err)
	require.NotNil(t, result)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "tool-test-v1", resultMap["agent_id"])
	assert.Equal(t, "tenant-tool", resultMap["tenant_id"])

	echoData, ok := resultMap["echo"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "asset-42", echoData["id"])
}

func TestExecutor_Call_RejectsToolNotInCapabilities(t *testing.T) {
	toolRegistryCleanup(t)

	tool := NewZakTool("Unauthorized Tool", "Not allowed", echoToolFunc, WithActionID("unauthorized_tool"))

	// The DSL only allows "read_asset" in capabilities.tools
	agentDSL := testAgentDSL("read_asset")
	ctx := runtime.NewAgentContext("tenant-1", "trace-1", agentDSL)

	executor := NewExecutor()
	_, err := executor.Call(tool, ctx, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized_tool")
	assert.Contains(t, err.Error(), "not declared in agent capabilities.tools")
}

func TestExecutor_Call_RejectsPolicyDeniedAction(t *testing.T) {
	toolRegistryCleanup(t)

	tool := NewZakTool("Denied Tool", "Will be denied by policy", echoToolFunc, WithActionID("denied_action"))

	agentDSL := testDeniedToolDSL("denied_action")
	ctx := runtime.NewAgentContext("tenant-deny", "trace-deny", agentDSL)

	executor := NewExecutor()
	_, err := executor.Call(tool, ctx, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy denied")
}

func TestExecutor_Call_NilTool_ReturnsError(t *testing.T) {
	agentDSL := testAgentDSL("read_asset")
	ctx := runtime.NewAgentContext("t1", "tr1", agentDSL)

	executor := NewExecutor()
	_, err := executor.Call(nil, ctx, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "tool is nil")
}

func TestExecutor_Call_ToolExecutionError(t *testing.T) {
	toolRegistryCleanup(t)

	tool := NewZakTool("Failing Tool", "Always fails", failingToolFunc, WithActionID("failing_tool"))

	agentDSL := testAgentDSL("failing_tool")
	ctx := runtime.NewAgentContext("tenant-fail", "trace-fail", agentDSL)

	executor := NewExecutor()
	_, err := executor.Call(tool, ctx, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "execution failed")
	assert.Contains(t, err.Error(), "something went wrong")
}

func TestExecutor_Call_EmptyCapabilitiesToolsAllowsAny(t *testing.T) {
	toolRegistryCleanup(t)

	tool := NewZakTool("Any Tool", "Should pass with empty capabilities", echoToolFunc, WithActionID("any_tool"))

	// No specific tools declared in capabilities (empty list).
	agentDSL := testAgentDSL() // empty tools list
	ctx := runtime.NewAgentContext("t1", "tr1", agentDSL)

	executor := NewExecutor()
	result, err := executor.Call(tool, ctx, map[string]interface{}{"key": "val"})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestExecutor_Call_NilArgs(t *testing.T) {
	toolRegistryCleanup(t)

	called := false
	tool := NewZakTool("Nil Args Tool", "Handles nil args", func(ctx *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}, WithActionID("nil_args_tool"))

	agentDSL := testAgentDSL("nil_args_tool")
	ctx := runtime.NewAgentContext("t1", "tr1", agentDSL)

	executor := NewExecutor()
	result, err := executor.Call(tool, ctx, nil)

	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, "ok", result)
}

func TestExecutor_Call_MultipleToolsWithDifferentCapabilities(t *testing.T) {
	toolRegistryCleanup(t)

	toolA := NewZakTool("Tool A", "Allowed tool", echoToolFunc, WithActionID("tool_a"))
	toolB := NewZakTool("Tool B", "Not allowed tool", echoToolFunc, WithActionID("tool_b"))

	agentDSL := testAgentDSL("tool_a")
	ctx := runtime.NewAgentContext("t1", "tr1", agentDSL)

	executor := NewExecutor()

	// Tool A should succeed.
	_, err := executor.Call(toolA, ctx, nil)
	assert.NoError(t, err)

	// Tool B should fail capabilities check.
	_, err = executor.Call(toolB, ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tool_b")
}

func TestNewExecutor_ReturnsExecutor(t *testing.T) {
	executor := NewExecutor()
	assert.NotNil(t, executor)
}
