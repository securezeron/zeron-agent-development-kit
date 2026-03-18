package runtime

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/edition"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testAgentDSL builds a valid *dsl.AgentDSL for use in tests.
func testAgentDSL() *dsl.AgentDSL {
	raw := `
agent:
  id: test-generic-v1
  name: Test Generic Agent
  domain: appsec
  version: "1.0.0"

intent:
  goal: Perform a basic application security scan
  success_criteria:
    - Identify OWASP Top 10 vulnerabilities
    - Generate a findings report
  priority: medium

reasoning:
  mode: deterministic
  autonomy_level: bounded
  confidence_threshold: 0.75

capabilities:
  tools:
    - read_asset
    - list_assets
  data_access:
    - asset_inventory
  graph_access:
    - Asset
    - Vulnerability

boundaries:
  risk_budget: medium
  allowed_actions:
    - read_asset
    - list_assets
    - agent_execute
  denied_actions: []
  environment_scope:
    - staging
    - dev
  approval_gates: []

safety:
  guardrails:
    - no_data_exfiltration
  sandbox_profile: standard
  audit_level: standard
`
	agentDSL, err := dsl.LoadAgentYamlString(raw)
	if err != nil {
		panic(fmt.Sprintf("testAgentDSL failed to parse: %v", err))
	}
	return agentDSL
}

// testDeniedAgentDSL returns a DSL where "agent_execute" is denied.
func testDeniedAgentDSL() *dsl.AgentDSL {
	raw := `
agent:
  id: denied-agent-v1
  name: Denied Agent
  domain: appsec
  version: "1.0.0"

intent:
  goal: Testing policy denial

reasoning:
  mode: deterministic
  autonomy_level: bounded
  confidence_threshold: 0.75

capabilities:
  tools:
    - read_asset
  data_access: []
  graph_access: []

boundaries:
  risk_budget: medium
  allowed_actions:
    - read_asset
  denied_actions:
    - agent_execute
  environment_scope:
    - staging
  approval_gates: []

safety:
  guardrails: []
  sandbox_profile: standard
  audit_level: standard
`
	agentDSL, err := dsl.LoadAgentYamlString(raw)
	if err != nil {
		panic(fmt.Sprintf("testDeniedAgentDSL failed to parse: %v", err))
	}
	return agentDSL
}

// simpleAgent implements BaseAgent only.
type simpleAgent struct {
	executeFunc func(ctx *AgentContext) (*AgentResult, error)
}

func (a *simpleAgent) Execute(ctx *AgentContext) (*AgentResult, error) {
	if a.executeFunc != nil {
		return a.executeFunc(ctx)
	}
	return ResultOk(ctx, map[string]interface{}{"status": "done"}, 42.0), nil
}

// hookAgent implements BaseAgent, PreRunner, and PostRunner.
type hookAgent struct {
	preRunCalled  bool
	postRunCalled bool
	preRunErr     error
	postRunErr    error
	executeFunc   func(ctx *AgentContext) (*AgentResult, error)
}

func (a *hookAgent) Execute(ctx *AgentContext) (*AgentResult, error) {
	if a.executeFunc != nil {
		return a.executeFunc(ctx)
	}
	return ResultOk(ctx, map[string]interface{}{"status": "hooked"}, 10.0), nil
}

func (a *hookAgent) PreRun(ctx *AgentContext) error {
	a.preRunCalled = true
	return a.preRunErr
}

func (a *hookAgent) PostRun(ctx *AgentContext, result *AgentResult) error {
	a.postRunCalled = true
	return a.postRunErr
}

// ===========================================================================
// Agent tests (agent.go)
// ===========================================================================

func TestNewAgentContext_Defaults(t *testing.T) {
	agentDSL := testAgentDSL()
	ctx := NewAgentContext("tenant-abc", "trace-123", agentDSL)

	assert.Equal(t, "tenant-abc", ctx.TenantID)
	assert.Equal(t, "trace-123", ctx.TraceID)
	assert.Equal(t, agentDSL, ctx.DSL)
	assert.Equal(t, "staging", ctx.Environment, "default environment should be 'staging'")
	assert.NotNil(t, ctx.Metadata, "Metadata map should be initialized")
	assert.Empty(t, ctx.Metadata, "Metadata should be empty by default")
	assert.False(t, ctx.StartedAt.IsZero(), "StartedAt should be set")
}

func TestAgentContext_AgentID(t *testing.T) {
	agentDSL := testAgentDSL()
	ctx := NewAgentContext("t1", "tr1", agentDSL)

	assert.Equal(t, "test-generic-v1", ctx.AgentID())
}

func TestResultOk_CreatesSuccessfulResult(t *testing.T) {
	agentDSL := testAgentDSL()
	ctx := NewAgentContext("tenant-1", "trace-1", agentDSL)
	output := map[string]interface{}{"findings": 3}

	result := ResultOk(ctx, output, 123.45)

	assert.True(t, result.Success)
	assert.Equal(t, "test-generic-v1", result.AgentID)
	assert.Equal(t, "tenant-1", result.TenantID)
	assert.Equal(t, "trace-1", result.TraceID)
	assert.Equal(t, output, result.Output)
	assert.Empty(t, result.Errors, "Errors should be empty for successful result")
	assert.InDelta(t, 123.45, result.DurationMs, 0.001)
	assert.False(t, result.CompletedAt.IsZero(), "CompletedAt should be set")
}

func TestResultFail_CreatesFailedResult(t *testing.T) {
	agentDSL := testAgentDSL()
	ctx := NewAgentContext("tenant-2", "trace-2", agentDSL)
	errs := []string{"connection timeout", "retry exhausted"}

	result := ResultFail(ctx, errs, 999.0)

	assert.False(t, result.Success)
	assert.Equal(t, "test-generic-v1", result.AgentID)
	assert.Equal(t, "tenant-2", result.TenantID)
	assert.Equal(t, "trace-2", result.TraceID)
	assert.Empty(t, result.Output, "Output should be empty for failed result")
	assert.Equal(t, errs, result.Errors)
	assert.InDelta(t, 999.0, result.DurationMs, 0.001)
	assert.False(t, result.CompletedAt.IsZero())
}

// ===========================================================================
// Registry tests (registry.go)
// ===========================================================================

func registryCleanup(t *testing.T) {
	t.Cleanup(func() {
		AgentRegistryGet().Clear()
	})
}

func TestRegistry_Register_AddsAgent(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	registration := reg.Register("appsec", factory, WithDescription("Test agent"), WithVersion("2.0.0"))

	assert.Equal(t, "appsec", registration.Domain)
	assert.Equal(t, "Test agent", registration.Description)
	assert.Equal(t, "2.0.0", registration.Version)
	assert.Equal(t, "enterprise", registration.Edition, "default edition should be 'enterprise'")
	assert.Equal(t, "Agent", registration.ClassName, "default className should be 'Agent'")
}

func TestRegistry_Register_DefaultValues(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	registration := reg.Register("compliance", factory)

	assert.Equal(t, "1.0.0", registration.Version, "default version should be 1.0.0")
	assert.Equal(t, "enterprise", registration.Edition)
	assert.Equal(t, "Agent", registration.ClassName)
	assert.Equal(t, "", registration.Description)
}

func TestRegistry_Resolve_ReturnsFactory(t *testing.T) {
	registryCleanup(t)
	// Enterprise edition required to resolve enterprise agents.
	t.Setenv("ZAK_EDITION", "enterprise")

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }
	reg.Register("appsec", factory, WithEdition("enterprise"))

	resolved, err := reg.Resolve("appsec")
	require.NoError(t, err)
	require.NotNil(t, resolved)

	agent := resolved()
	assert.NotNil(t, agent)
}

func TestRegistry_Resolve_OpenSourceAgentInOSSMode(t *testing.T) {
	registryCleanup(t)
	t.Setenv("ZAK_EDITION", "open-source")

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }
	reg.Register("compliance", factory, WithEdition("open-source"))

	resolved, err := reg.Resolve("compliance")
	require.NoError(t, err)
	require.NotNil(t, resolved)
}

func TestRegistry_Resolve_ErrorForUnknownDomain(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	_, err := reg.Resolve("nonexistent-domain")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no agent registered for domain 'nonexistent-domain'")
}

func TestRegistry_Resolve_ErrorForEnterpriseAgentInOSSMode(t *testing.T) {
	registryCleanup(t)
	t.Setenv("ZAK_EDITION", "open-source")

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }
	reg.Register("ai_security", factory, WithEdition("enterprise"))

	_, err := reg.Resolve("ai_security")
	require.Error(t, err)

	var edErr *edition.Error
	assert.True(t, errors.As(err, &edErr), "error should be an edition.Error")
}

func TestRegistry_AllDomains_ReturnsSorted(t *testing.T) {
	registryCleanup(t)
	t.Setenv("ZAK_EDITION", "enterprise")

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	reg.Register("compliance", factory, WithEdition("enterprise"))
	reg.Register("appsec", factory, WithEdition("enterprise"))
	reg.Register("risk_quant", factory, WithEdition("enterprise"))

	domains := reg.AllDomains()
	require.Len(t, domains, 3)
	assert.Equal(t, []string{"appsec", "compliance", "risk_quant"}, domains)
}

func TestRegistry_AllDomains_FiltersEdition(t *testing.T) {
	registryCleanup(t)
	t.Setenv("ZAK_EDITION", "open-source")

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	reg.Register("oss-domain", factory, WithEdition("open-source"))
	reg.Register("ent-domain", factory, WithEdition("enterprise"))

	domains := reg.AllDomains()
	assert.Contains(t, domains, "oss-domain")
	assert.NotContains(t, domains, "ent-domain")
}

func TestRegistry_IsRegistered(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	assert.False(t, reg.IsRegistered("appsec"))

	reg.Register("appsec", factory)
	assert.True(t, reg.IsRegistered("appsec"))
	assert.False(t, reg.IsRegistered("nonexistent"))
}

func TestRegistry_Unregister_RemovesAgent(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	reg.Register("appsec", factory)
	require.True(t, reg.IsRegistered("appsec"))

	reg.Unregister("appsec")
	assert.False(t, reg.IsRegistered("appsec"))
}

func TestRegistry_Clear_EmptiesRegistry(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	reg.Register("appsec", factory)
	reg.Register("compliance", factory)
	require.True(t, reg.IsRegistered("appsec"))
	require.True(t, reg.IsRegistered("compliance"))

	reg.Clear()
	assert.False(t, reg.IsRegistered("appsec"))
	assert.False(t, reg.IsRegistered("compliance"))
}

func TestRegistry_Override_MakesAgentPrimary(t *testing.T) {
	registryCleanup(t)
	t.Setenv("ZAK_EDITION", "enterprise")

	reg := AgentRegistryGet()

	originalFactory := func() BaseAgent {
		return &simpleAgent{executeFunc: func(ctx *AgentContext) (*AgentResult, error) {
			return ResultOk(ctx, map[string]interface{}{"source": "original"}, 1.0), nil
		}}
	}
	overrideFactory := func() BaseAgent {
		return &simpleAgent{executeFunc: func(ctx *AgentContext) (*AgentResult, error) {
			return ResultOk(ctx, map[string]interface{}{"source": "override"}, 1.0), nil
		}}
	}

	reg.Register("appsec", originalFactory)
	reg.Register("appsec", overrideFactory, WithOverride())

	// Resolve should return the override factory (first in list)
	resolved, err := reg.Resolve("appsec")
	require.NoError(t, err)

	agentDSL := testAgentDSL()
	ctx := NewAgentContext("t1", "tr1", agentDSL)
	agent := resolved()
	result, err := agent.Execute(ctx)
	require.NoError(t, err)
	assert.Equal(t, "override", result.Output["source"])
}

func TestRegistry_Override_ResolveAllShowsBoth(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	factory1 := func() BaseAgent { return &simpleAgent{} }
	factory2 := func() BaseAgent { return &simpleAgent{} }

	reg.Register("appsec", factory1, WithClassName("Original"))
	reg.Register("appsec", factory2, WithOverride(), WithClassName("Override"))

	all := reg.ResolveAll("appsec")
	require.Len(t, all, 2)
	assert.Equal(t, "Override", all[0].ClassName, "override should be first")
	assert.Equal(t, "Original", all[1].ClassName)
}

func TestRegisterAgent_ConvenienceFunction(t *testing.T) {
	registryCleanup(t)

	factory := func() BaseAgent { return &simpleAgent{} }
	registration := RegisterAgent("supply_chain", factory, WithDescription("Supply chain scanner"))

	assert.Equal(t, "supply_chain", registration.Domain)
	assert.Equal(t, "Supply chain scanner", registration.Description)
	assert.True(t, AgentRegistryGet().IsRegistered("supply_chain"))
}

func TestRegistry_Summary_EmptyRegistry(t *testing.T) {
	registryCleanup(t)

	summary := AgentRegistryGet().Summary()
	assert.Equal(t, "No agents registered.", summary)
}

func TestRegistry_Summary_WithAgents(t *testing.T) {
	registryCleanup(t)
	t.Setenv("ZAK_EDITION", "enterprise")

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	reg.Register("appsec", factory, WithClassName("AppSecAgent"))
	reg.Register("compliance", factory, WithClassName("ComplianceAgent"))

	summary := reg.Summary()
	assert.Contains(t, summary, "Registered agents:")
	assert.Contains(t, summary, "appsec")
	assert.Contains(t, summary, "AppSecAgent")
	assert.Contains(t, summary, "compliance")
	assert.Contains(t, summary, "ComplianceAgent")
}

func TestRegistry_Summary_WithAlternatives(t *testing.T) {
	registryCleanup(t)
	t.Setenv("ZAK_EDITION", "enterprise")

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	reg.Register("appsec", factory, WithClassName("Primary"))
	reg.Register("appsec", factory, WithClassName("Alt1"))
	reg.Register("appsec", factory, WithClassName("Alt2"))

	summary := reg.Summary()
	assert.Contains(t, summary, "+2 alternatives")
}

func TestRegistry_AllRegistrations_FiltersByEdition(t *testing.T) {
	registryCleanup(t)
	t.Setenv("ZAK_EDITION", "open-source")

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	reg.Register("oss-agent", factory, WithEdition("open-source"))
	reg.Register("ent-agent", factory, WithEdition("enterprise"))

	all := reg.AllRegistrations()
	for _, r := range all {
		assert.Equal(t, "open-source", r.Edition,
			"OSS mode should only show open-source registrations")
	}
}

func TestRegistry_AllRegistrationsUnfiltered_ReturnsAll(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	reg.Register("oss-agent", factory, WithEdition("open-source"))
	reg.Register("ent-agent", factory, WithEdition("enterprise"))

	all := reg.AllRegistrationsUnfiltered()
	assert.Len(t, all, 2)
}

func TestRegistry_Resolve_ErrorListsAvailableDomains(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	reg.Register("appsec", factory)
	reg.Register("compliance", factory)

	_, err := reg.Resolve("nonexistent")
	require.Error(t, err)
	errStr := err.Error()
	assert.Contains(t, errStr, "Available domains:")
	assert.Contains(t, errStr, "appsec")
	assert.Contains(t, errStr, "compliance")
}

func TestRegistry_WithOptions(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	registration := reg.Register("appsec", factory,
		WithDescription("My agent"),
		WithVersion("3.2.1"),
		WithEdition("open-source"),
		WithClassName("MyCustomAgent"),
	)

	assert.Equal(t, "My agent", registration.Description)
	assert.Equal(t, "3.2.1", registration.Version)
	assert.Equal(t, "open-source", registration.Edition)
	assert.Equal(t, "MyCustomAgent", registration.ClassName)
}

// ===========================================================================
// Executor tests (executor.go)
// ===========================================================================

func TestExecutor_SuccessfulExecution(t *testing.T) {
	registryCleanup(t)

	agentDSL := testAgentDSL()
	ctx := NewAgentContext("tenant-exec", "trace-exec", agentDSL)
	agent := &simpleAgent{
		executeFunc: func(ctx *AgentContext) (*AgentResult, error) {
			return ResultOk(ctx, map[string]interface{}{"findings": 5}, 50.0), nil
		},
	}

	executor := NewExecutor()
	result := executor.Run(agent, ctx)

	assert.True(t, result.Success)
	assert.Equal(t, "test-generic-v1", result.AgentID)
	assert.Equal(t, "tenant-exec", result.TenantID)
	assert.Equal(t, "trace-exec", result.TraceID)
	assert.Equal(t, 5, result.Output["findings"])
	assert.Empty(t, result.Errors)
	assert.GreaterOrEqual(t, result.DurationMs, float64(0), "DurationMs should be non-negative")
}

func TestExecutor_WithPreRunnerAndPostRunner(t *testing.T) {
	registryCleanup(t)

	agentDSL := testAgentDSL()
	ctx := NewAgentContext("tenant-hook", "trace-hook", agentDSL)
	agent := &hookAgent{
		executeFunc: func(ctx *AgentContext) (*AgentResult, error) {
			return ResultOk(ctx, map[string]interface{}{"stage": "executed"}, 20.0), nil
		},
	}

	executor := NewExecutor()
	result := executor.Run(agent, ctx)

	assert.True(t, result.Success)
	assert.True(t, agent.preRunCalled, "PreRun should have been called")
	assert.True(t, agent.postRunCalled, "PostRun should have been called")
}

func TestExecutor_PreRunError_ReturnsFailed(t *testing.T) {
	registryCleanup(t)

	agentDSL := testAgentDSL()
	ctx := NewAgentContext("tenant-pre", "trace-pre", agentDSL)
	agent := &hookAgent{
		preRunErr: errors.New("initialization failed"),
	}

	executor := NewExecutor()
	result := executor.Run(agent, ctx)

	assert.False(t, result.Success)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "pre_run failed")
	assert.Contains(t, result.Errors[0], "initialization failed")
}

func TestExecutor_PostRunError_NonFatal(t *testing.T) {
	registryCleanup(t)

	agentDSL := testAgentDSL()
	ctx := NewAgentContext("tenant-post", "trace-post", agentDSL)
	agent := &hookAgent{
		postRunErr: errors.New("cleanup warning"),
		executeFunc: func(ctx *AgentContext) (*AgentResult, error) {
			return ResultOk(ctx, map[string]interface{}{"done": true}, 5.0), nil
		},
	}

	executor := NewExecutor()
	result := executor.Run(agent, ctx)

	// Post-run errors are logged but non-fatal, so the result should still be success.
	assert.True(t, result.Success, "PostRun error should not cause failure")
	assert.True(t, agent.postRunCalled)
}

func TestExecutor_ExecuteError_ReturnsFailed(t *testing.T) {
	registryCleanup(t)

	agentDSL := testAgentDSL()
	ctx := NewAgentContext("tenant-err", "trace-err", agentDSL)
	agent := &simpleAgent{
		executeFunc: func(ctx *AgentContext) (*AgentResult, error) {
			return nil, errors.New("unexpected crash")
		},
	}

	executor := NewExecutor()
	result := executor.Run(agent, ctx)

	assert.False(t, result.Success)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "unexpected crash")
}

func TestExecutor_PolicyDenied_ReturnsFailed(t *testing.T) {
	registryCleanup(t)

	agentDSL := testDeniedAgentDSL()
	ctx := NewAgentContext("tenant-policy", "trace-policy", agentDSL)
	agent := &simpleAgent{}

	executor := NewExecutor()
	result := executor.Run(agent, ctx)

	assert.False(t, result.Success)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "Policy denied")
}

func TestExecutor_CheckAction_Allowed(t *testing.T) {
	agentDSL := testAgentDSL()
	ctx := NewAgentContext("t1", "tr1", agentDSL)

	executor := NewExecutor()
	decision := executor.CheckAction(ctx, "read_asset", "staging")

	assert.True(t, decision.Allowed)
}

func TestExecutor_CheckAction_Denied(t *testing.T) {
	agentDSL := testDeniedAgentDSL()
	ctx := NewAgentContext("t1", "tr1", agentDSL)

	executor := NewExecutor()
	decision := executor.CheckAction(ctx, "agent_execute", "staging")

	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "agent_execute")
}

func TestExecutor_CheckAction_UsesContextEnvironment(t *testing.T) {
	agentDSL := testAgentDSL()
	ctx := NewAgentContext("t1", "tr1", agentDSL)
	ctx.Environment = "staging"

	executor := NewExecutor()
	// Pass empty string for environment; it should fall back to ctx.Environment
	decision := executor.CheckAction(ctx, "read_asset", "")

	assert.True(t, decision.Allowed)
}

func TestExecutor_FailedResult_EmitsErrors(t *testing.T) {
	registryCleanup(t)

	agentDSL := testAgentDSL()
	ctx := NewAgentContext("tenant-fail", "trace-fail", agentDSL)
	agent := &simpleAgent{
		executeFunc: func(ctx *AgentContext) (*AgentResult, error) {
			return ResultFail(ctx, []string{"error one", "error two"}, 5.0), nil
		},
	}

	executor := NewExecutor()
	result := executor.Run(agent, ctx)

	assert.False(t, result.Success)
	assert.Len(t, result.Errors, 2)
}

// ---------------------------------------------------------------------------
// Verify interface implementation at compile time
// ---------------------------------------------------------------------------

var _ BaseAgent = (*simpleAgent)(nil)
var _ BaseAgent = (*hookAgent)(nil)
var _ PreRunner = (*hookAgent)(nil)
var _ PostRunner = (*hookAgent)(nil)

// Verify the policy.Decision type is used correctly
var _ = policy.Decision{}

// Verify the edition package is available (used in registry tests)
var _ = edition.OpenSource

// ---------------------------------------------------------------------------
// Edge case: multiple domains and concurrent registration
// ---------------------------------------------------------------------------

func TestRegistry_MultipleDomains_Independent(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	f1 := func() BaseAgent { return &simpleAgent{} }
	f2 := func() BaseAgent { return &simpleAgent{} }

	reg.Register("appsec", f1)
	reg.Register("compliance", f2)

	assert.True(t, reg.IsRegistered("appsec"))
	assert.True(t, reg.IsRegistered("compliance"))

	reg.Unregister("appsec")
	assert.False(t, reg.IsRegistered("appsec"))
	assert.True(t, reg.IsRegistered("compliance"), "unregistering one domain should not affect others")
}

func TestRegistry_ResolveAll_EmptyDomain(t *testing.T) {
	registryCleanup(t)

	reg := AgentRegistryGet()
	all := reg.ResolveAll("nonexistent")
	assert.Empty(t, all)
}

func TestNewAgentContext_MetadataIsMutable(t *testing.T) {
	agentDSL := testAgentDSL()
	ctx := NewAgentContext("t1", "tr1", agentDSL)

	ctx.Metadata["key1"] = "value1"
	ctx.Metadata["key2"] = 42

	assert.Equal(t, "value1", ctx.Metadata["key1"])
	assert.Equal(t, 42, ctx.Metadata["key2"])
}

func TestResultOk_NilOutput(t *testing.T) {
	agentDSL := testAgentDSL()
	ctx := NewAgentContext("t1", "tr1", agentDSL)

	result := ResultOk(ctx, nil, 0.0)
	assert.True(t, result.Success)
	assert.Nil(t, result.Output)
}

func TestResultFail_EmptyErrors(t *testing.T) {
	agentDSL := testAgentDSL()
	ctx := NewAgentContext("t1", "tr1", agentDSL)

	result := ResultFail(ctx, []string{}, 0.0)
	assert.False(t, result.Success)
	assert.Empty(t, result.Errors)
}

func TestExecutor_Run_SetsCorrectDuration(t *testing.T) {
	agentDSL := testAgentDSL()
	ctx := NewAgentContext("t1", "tr1", agentDSL)
	agent := &simpleAgent{
		executeFunc: func(ctx *AgentContext) (*AgentResult, error) {
			return ResultOk(ctx, map[string]interface{}{}, 0.0), nil
		},
	}

	executor := NewExecutor()
	result := executor.Run(agent, ctx)

	// The executor overrides DurationMs with its own timing
	assert.True(t, result.Success)
	assert.GreaterOrEqual(t, result.DurationMs, float64(0))
}

func TestRegistry_Summary_ContainsAlternativeCount(t *testing.T) {
	registryCleanup(t)
	t.Setenv("ZAK_EDITION", "enterprise")

	reg := AgentRegistryGet()
	factory := func() BaseAgent { return &simpleAgent{} }

	reg.Register("appsec", factory, WithClassName("V1"))
	reg.Register("appsec", factory, WithClassName("V2"))

	summary := reg.Summary()
	assert.True(t, strings.Contains(summary, "+1 alternatives") || strings.Contains(summary, "+1 alternative"),
		"Summary should mention the alternative count")
}
