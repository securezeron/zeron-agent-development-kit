package policy

import (
	"testing"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers — build test AgentDSL structs
// ---------------------------------------------------------------------------

// baseAgent returns a minimal valid AgentDSL for policy testing.
func baseAgent() *dsl.AgentDSL {
	return &dsl.AgentDSL{
		Agent: dsl.AgentIdentity{
			ID:      "policy-test-v1",
			Name:    "Policy Test Agent",
			Domain:  dsl.DomainAppSec,
			Version: "1.0.0",
		},
		Intent: dsl.AgentIntent{
			Goal:     "Test policy engine",
			Priority: dsl.PriorityMedium,
		},
		Reasoning: dsl.ReasoningConfig{
			Mode:                dsl.ReasoningDeterministic,
			AutonomyLevel:       dsl.AutonomyBounded,
			ConfidenceThreshold: 0.75,
		},
		Boundaries: dsl.BoundariesConfig{
			RiskBudget:       dsl.RiskBudgetMedium,
			AllowedActions:   []string{},
			DeniedActions:    []string{},
			EnvironmentScope: []string{},
			ApprovalGates:    []string{},
		},
		Safety: dsl.SafetyConfig{
			SandboxProfile: dsl.SandboxStandard,
			AuditLevel:     dsl.AuditStandard,
		},
	}
}

// withDeniedActions returns an agent with specific denied actions.
func withDeniedActions(actions ...string) *dsl.AgentDSL {
	a := baseAgent()
	a.Boundaries.DeniedActions = actions
	return a
}

// withAllowedActions returns an agent with specific allowed actions.
func withAllowedActions(actions ...string) *dsl.AgentDSL {
	a := baseAgent()
	a.Boundaries.AllowedActions = actions
	return a
}

// withAutonomyLevel returns an agent with a specific autonomy level.
func withAutonomyLevel(level dsl.AutonomyLevel) *dsl.AgentDSL {
	a := baseAgent()
	a.Reasoning.AutonomyLevel = level
	return a
}

// withRiskBudget returns an agent with a specific risk budget.
func withRiskBudget(budget dsl.RiskBudget) *dsl.AgentDSL {
	a := baseAgent()
	a.Boundaries.RiskBudget = budget
	return a
}

// withEnvironmentScope returns an agent scoped to specific environments.
func withEnvironmentScope(envs ...string) *dsl.AgentDSL {
	a := baseAgent()
	a.Boundaries.EnvironmentScope = envs
	return a
}

// redTeamAgent returns a red team agent scoped to the given environments.
func redTeamAgent(envs ...string) *dsl.AgentDSL {
	a := baseAgent()
	a.Agent.Domain = dsl.DomainRedTeam
	a.Safety.SandboxProfile = dsl.SandboxOffensiveIsolated
	a.Safety.AuditLevel = dsl.AuditVerbose
	a.Boundaries.EnvironmentScope = envs
	return a
}

// withApprovalGates returns an agent with specific approval gates.
func withApprovalGates(gates ...string) *dsl.AgentDSL {
	a := baseAgent()
	a.Boundaries.ApprovalGates = gates
	return a
}

// ---------------------------------------------------------------------------
// Rule 1 — Denied actions are blocked
// ---------------------------------------------------------------------------

func TestRule1_DeniedActionIsBlocked(t *testing.T) {
	engine := NewEngine()
	agent := withDeniedActions("execute_python", "deploy_payload")

	dec := engine.Evaluate(agent, "execute_python", "staging", nil)
	assert.False(t, dec.Allowed)
	assert.Contains(t, dec.Reason, "explicitly denied")
	assert.Contains(t, dec.Reason, "execute_python")
}

func TestRule1_DeniedActionSecondEntry(t *testing.T) {
	engine := NewEngine()
	agent := withDeniedActions("execute_python", "deploy_payload")

	dec := engine.Evaluate(agent, "deploy_payload", "staging", nil)
	assert.False(t, dec.Allowed)
	assert.Contains(t, dec.Reason, "deploy_payload")
}

func TestRule1_NonDeniedActionPasses(t *testing.T) {
	engine := NewEngine()
	agent := withDeniedActions("execute_python")

	dec := engine.Evaluate(agent, "read_asset", "staging", nil)
	assert.True(t, dec.Allowed)
}

// ---------------------------------------------------------------------------
// Rule 2 — Allow-list enforcement
// ---------------------------------------------------------------------------

func TestRule2_ActionNotInAllowListBlocked(t *testing.T) {
	engine := NewEngine()
	agent := withAllowedActions("read_asset", "list_assets")

	dec := engine.Evaluate(agent, "execute_python", "staging", nil)
	assert.False(t, dec.Allowed)
	assert.Contains(t, dec.Reason, "allow-list")
}

func TestRule2_ActionInAllowListPermitted(t *testing.T) {
	engine := NewEngine()
	agent := withAllowedActions("read_asset", "list_assets")

	dec := engine.Evaluate(agent, "read_asset", "staging", nil)
	assert.True(t, dec.Allowed)
}

func TestRule2_EmptyAllowListPermitsAll(t *testing.T) {
	engine := NewEngine()
	agent := baseAgent() // empty allow list

	dec := engine.Evaluate(agent, "any_action", "staging", nil)
	assert.True(t, dec.Allowed)
}

// ---------------------------------------------------------------------------
// Rule 3 — Observe-only agents cannot mutate
// ---------------------------------------------------------------------------

func TestRule3_ObserveAgentBlocksMutatingActions(t *testing.T) {
	engine := NewEngine()
	agent := withAutonomyLevel(dsl.AutonomyObserve)

	mutatingActions := []string{
		"write_report",
		"delete_finding",
		"update_config",
		"create_ticket",
		"modify_rule",
		"execute_scan",
	}

	for _, action := range mutatingActions {
		t.Run(action, func(t *testing.T) {
			dec := engine.Evaluate(agent, action, "staging", nil)
			assert.False(t, dec.Allowed, "observe-only agent should block %s", action)
			assert.Contains(t, dec.Reason, "mutating")
			assert.Contains(t, dec.Reason, "observe")
		})
	}
}

func TestRule3_ObserveAgentPermitsReadActions(t *testing.T) {
	engine := NewEngine()
	agent := withAutonomyLevel(dsl.AutonomyObserve)

	readActions := []string{
		"read_asset",
		"list_findings",
		"get_report",
		"scan_status",
	}

	for _, action := range readActions {
		t.Run(action, func(t *testing.T) {
			dec := engine.Evaluate(agent, action, "staging", nil)
			assert.True(t, dec.Allowed, "observe agent should permit %s", action)
		})
	}
}

func TestRule3_BoundedAgentPermitsMutations(t *testing.T) {
	engine := NewEngine()
	agent := withAutonomyLevel(dsl.AutonomyBounded)

	dec := engine.Evaluate(agent, "write_report", "staging", nil)
	assert.True(t, dec.Allowed, "bounded agent should permit mutations")
}

// ---------------------------------------------------------------------------
// Rule 4 — Risk budget enforcement
// ---------------------------------------------------------------------------

func TestRule4_LowBudgetBlocksHighRiskAction(t *testing.T) {
	engine := NewEngine()
	agent := withRiskBudget(dsl.RiskBudgetLow)

	highRiskActions := []string{"execute_exploit", "deploy_payload", "modify_production"}

	for _, action := range highRiskActions {
		t.Run(action, func(t *testing.T) {
			dec := engine.Evaluate(agent, action, "staging", nil)
			assert.False(t, dec.Allowed, "low budget should block %s", action)
			assert.Contains(t, dec.Reason, "risk_budget")
		})
	}
}

func TestRule4_MediumBudgetPermitsHighRiskAction(t *testing.T) {
	engine := NewEngine()
	agent := withRiskBudget(dsl.RiskBudgetMedium)

	dec := engine.Evaluate(agent, "execute_exploit", "staging", nil)
	assert.True(t, dec.Allowed, "medium budget should permit high risk actions")
}

func TestRule4_HighBudgetPermitsHighRiskAction(t *testing.T) {
	engine := NewEngine()
	agent := withRiskBudget(dsl.RiskBudgetHigh)

	dec := engine.Evaluate(agent, "deploy_payload", "staging", nil)
	assert.True(t, dec.Allowed, "high budget should permit high risk actions")
}

func TestRule4_LowBudgetPermitsNonHighRiskAction(t *testing.T) {
	engine := NewEngine()
	agent := withRiskBudget(dsl.RiskBudgetLow)

	dec := engine.Evaluate(agent, "read_asset", "staging", nil)
	assert.True(t, dec.Allowed, "low budget should permit non-high-risk actions")
}

// ---------------------------------------------------------------------------
// Rule 5 — Environment scope enforcement
// ---------------------------------------------------------------------------

func TestRule5_ActionBlockedOutsideScope(t *testing.T) {
	engine := NewEngine()
	agent := withEnvironmentScope("staging", "dev")

	dec := engine.Evaluate(agent, "read_asset", "production", nil)
	assert.False(t, dec.Allowed)
	assert.Contains(t, dec.Reason, "production")
	assert.Contains(t, dec.Reason, "not in scope")
}

func TestRule5_ActionAllowedInScope(t *testing.T) {
	engine := NewEngine()
	agent := withEnvironmentScope("staging", "dev")

	dec := engine.Evaluate(agent, "read_asset", "staging", nil)
	assert.True(t, dec.Allowed)
}

func TestRule5_EmptyEnvironmentScopePermitsAll(t *testing.T) {
	engine := NewEngine()
	agent := baseAgent() // empty environment scope

	dec := engine.Evaluate(agent, "read_asset", "production", nil)
	assert.True(t, dec.Allowed, "empty scope should permit all environments")
}

func TestRule5_EmptyEnvironmentStringPermitsWhenScoped(t *testing.T) {
	engine := NewEngine()
	agent := withEnvironmentScope("staging")

	dec := engine.Evaluate(agent, "read_asset", "", nil)
	assert.True(t, dec.Allowed, "empty env string should skip scope check")
}

// ---------------------------------------------------------------------------
// Rule 6 — Red team production restriction
// ---------------------------------------------------------------------------

func TestRule6_RedTeamBlockedFromProductionByDefault(t *testing.T) {
	engine := NewEngine()
	// Use empty environment scope so Rule 5 is skipped and Rule 6 fires.
	agent := redTeamAgent() // no environments scoped

	dec := engine.Evaluate(agent, "scan_target", "production", nil)
	assert.False(t, dec.Allowed)
	assert.Contains(t, dec.Reason, "Red team")
	assert.Contains(t, dec.Reason, "production")
}

func TestRule6_RedTeamBlockedFromProductionViaScopeRule(t *testing.T) {
	engine := NewEngine()
	// When scoped to staging only, Rule 5 fires first (environment scope).
	agent := redTeamAgent("staging")

	dec := engine.Evaluate(agent, "scan_target", "production", nil)
	assert.False(t, dec.Allowed)
	assert.Contains(t, dec.Reason, "not in scope")
}

func TestRule6_RedTeamAllowedInProductionWhenExplicitlyScoped(t *testing.T) {
	engine := NewEngine()
	agent := redTeamAgent("staging", "production") // explicitly scoped

	dec := engine.Evaluate(agent, "scan_target", "production", nil)
	assert.True(t, dec.Allowed)
}

func TestRule6_RedTeamAllowedInStaging(t *testing.T) {
	engine := NewEngine()
	agent := redTeamAgent("staging")

	dec := engine.Evaluate(agent, "scan_target", "staging", nil)
	assert.True(t, dec.Allowed)
}

func TestRule6_NonRedTeamNotRestrictedFromProduction(t *testing.T) {
	engine := NewEngine()
	agent := baseAgent() // appsec domain, no env scope restriction

	dec := engine.Evaluate(agent, "read_asset", "production", nil)
	assert.True(t, dec.Allowed, "non-red-team agents should not have Rule 6 restriction")
}

// ---------------------------------------------------------------------------
// Approval gate detection
// ---------------------------------------------------------------------------

func TestCheckApprovalGate_GateMatches(t *testing.T) {
	engine := NewEngine()
	agent := withApprovalGates("execute_exploit", "deploy_payload")

	assert.True(t, engine.CheckApprovalGate(agent, "execute_exploit"))
	assert.True(t, engine.CheckApprovalGate(agent, "deploy_payload"))
}

func TestCheckApprovalGate_GateDoesNotMatch(t *testing.T) {
	engine := NewEngine()
	agent := withApprovalGates("execute_exploit")

	assert.False(t, engine.CheckApprovalGate(agent, "read_asset"))
}

func TestCheckApprovalGate_NoGatesDefined(t *testing.T) {
	engine := NewEngine()
	agent := baseAgent() // empty approval gates

	assert.False(t, engine.CheckApprovalGate(agent, "execute_exploit"))
}

// ---------------------------------------------------------------------------
// Action permitted when all rules pass
// ---------------------------------------------------------------------------

func TestAllRulesPass_ActionPermitted(t *testing.T) {
	engine := NewEngine()

	agent := baseAgent()
	agent.Boundaries.AllowedActions = []string{"read_asset", "list_assets"}
	agent.Boundaries.DeniedActions = []string{"deploy_payload"}
	agent.Boundaries.EnvironmentScope = []string{"staging", "dev"}
	agent.Boundaries.RiskBudget = dsl.RiskBudgetMedium

	dec := engine.Evaluate(agent, "read_asset", "staging", nil)
	require.True(t, dec.Allowed)
	assert.Contains(t, dec.Reason, "permitted")
}

func TestAllRulesPass_NoConstraintsDefaultPermit(t *testing.T) {
	engine := NewEngine()
	agent := baseAgent()

	dec := engine.Evaluate(agent, "arbitrary_action", "", nil)
	assert.True(t, dec.Allowed)
}

// ---------------------------------------------------------------------------
// Decision constructors
// ---------------------------------------------------------------------------

func TestPermit_DefaultReason(t *testing.T) {
	d := Permit()
	assert.True(t, d.Allowed)
	assert.Equal(t, "Action permitted by policy", d.Reason)
}

func TestPermit_CustomReason(t *testing.T) {
	d := Permit("custom reason")
	assert.True(t, d.Allowed)
	assert.Equal(t, "custom reason", d.Reason)
}

func TestDeny_Reason(t *testing.T) {
	d := Deny("blocked by policy")
	assert.False(t, d.Allowed)
	assert.Equal(t, "blocked by policy", d.Reason)
}

// ---------------------------------------------------------------------------
// Rule interaction: deny takes precedence over allow
// ---------------------------------------------------------------------------

func TestDenyPrecedenceOverAllow(t *testing.T) {
	engine := NewEngine()
	agent := baseAgent()
	agent.Boundaries.AllowedActions = []string{"execute_python"}
	agent.Boundaries.DeniedActions = []string{"execute_python"}

	dec := engine.Evaluate(agent, "execute_python", "staging", nil)
	assert.False(t, dec.Allowed, "denied list should take precedence over allowed list")
	assert.Contains(t, dec.Reason, "explicitly denied")
}
