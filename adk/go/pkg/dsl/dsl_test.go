package dsl

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixturesDir resolves the path to the shared test fixtures directory.
func fixturesDir() string {
	return filepath.Join("..", "..", "..", "..", "tests", "fixtures")
}

func fixturePath(name string) string {
	return filepath.Join(fixturesDir(), name)
}

// ---------------------------------------------------------------------------
// LoadAgentYaml — valid fixtures
// ---------------------------------------------------------------------------

func TestLoadAgentYaml_ValidGeneric(t *testing.T) {
	dsl, err := LoadAgentYaml(fixturePath("valid-generic.yaml"))
	require.NoError(t, err, "valid-generic.yaml should parse without error")
	require.NotNil(t, dsl)

	assert.Equal(t, "test-generic-v1", dsl.Agent.ID)
	assert.Equal(t, "Test Generic Agent", dsl.Agent.Name)
	assert.Equal(t, DomainAppSec, dsl.Agent.Domain)
	assert.Equal(t, "1.0.0", dsl.Agent.Version)

	assert.Equal(t, "Perform a basic application security scan", dsl.Intent.Goal)
	assert.Equal(t, PriorityMedium, dsl.Intent.Priority)
	assert.Len(t, dsl.Intent.SuccessCriteria, 2)

	assert.Equal(t, ReasoningDeterministic, dsl.Reasoning.Mode)
	assert.Equal(t, AutonomyBounded, dsl.Reasoning.AutonomyLevel)
	assert.InDelta(t, 0.75, dsl.Reasoning.ConfidenceThreshold, 0.001)
	assert.Nil(t, dsl.Reasoning.LLM, "deterministic mode should not auto-populate LLM config")

	assert.ElementsMatch(t, []string{"read_asset", "list_assets"}, dsl.Capabilities.Tools)
	assert.Contains(t, dsl.Boundaries.AllowedActions, "read_asset")
	assert.Empty(t, dsl.Boundaries.DeniedActions)
	assert.ElementsMatch(t, []string{"staging", "dev"}, dsl.Boundaries.EnvironmentScope)

	assert.Equal(t, SandboxStandard, dsl.Safety.SandboxProfile)
	assert.Equal(t, AuditStandard, dsl.Safety.AuditLevel)
}

func TestLoadAgentYaml_ValidRiskQuant(t *testing.T) {
	dsl, err := LoadAgentYaml(fixturePath("valid-risk-quant.yaml"))
	require.NoError(t, err, "valid-risk-quant.yaml should parse without error")
	require.NotNil(t, dsl)

	assert.Equal(t, "risk-quant-v1", dsl.Agent.ID)
	assert.Equal(t, DomainRiskQuant, dsl.Agent.Domain)
	assert.Equal(t, PriorityHigh, dsl.Intent.Priority)
	assert.Equal(t, ReasoningLLMReAct, dsl.Reasoning.Mode)
	assert.InDelta(t, 0.8, dsl.Reasoning.ConfidenceThreshold, 0.001)

	// LLM config should be present for llm_react mode
	require.NotNil(t, dsl.Reasoning.LLM)
	assert.Equal(t, "openai", dsl.Reasoning.LLM.Provider)
	assert.Equal(t, "gpt-4o", dsl.Reasoning.LLM.Model)
	assert.InDelta(t, 0.2, dsl.Reasoning.LLM.Temperature, 0.001)
	assert.Equal(t, 10, dsl.Reasoning.LLM.MaxIterations)
	assert.Equal(t, 4096, dsl.Reasoning.LLM.MaxTokens)

	assert.Contains(t, dsl.Capabilities.Tools, "execute_python")
	assert.Equal(t, RiskBudgetMedium, dsl.Boundaries.RiskBudget)
}

func TestLoadAgentYaml_ValidRedTeam(t *testing.T) {
	dsl, err := LoadAgentYaml(fixturePath("valid-red-team.yaml"))
	require.NoError(t, err, "valid-red-team.yaml should parse without error")
	require.NotNil(t, dsl)

	assert.Equal(t, "red-team-scanner-v1", dsl.Agent.ID)
	assert.Equal(t, DomainRedTeam, dsl.Agent.Domain)
	assert.Equal(t, PriorityCritical, dsl.Intent.Priority)

	// Red team must have offensive_isolated + verbose
	assert.Equal(t, SandboxOffensiveIsolated, dsl.Safety.SandboxProfile)
	assert.Equal(t, AuditVerbose, dsl.Safety.AuditLevel)

	assert.Equal(t, RiskBudgetHigh, dsl.Boundaries.RiskBudget)
	assert.Contains(t, dsl.Boundaries.DeniedActions, "modify_production")
	assert.Contains(t, dsl.Boundaries.DeniedActions, "deploy_payload")
	assert.Contains(t, dsl.Boundaries.ApprovalGates, "execute_exploit")

	require.NotNil(t, dsl.Reasoning.LLM)
	assert.InDelta(t, 0.1, dsl.Reasoning.LLM.Temperature, 0.001)
	assert.Equal(t, 15, dsl.Reasoning.LLM.MaxIterations)
	assert.Equal(t, 8192, dsl.Reasoning.LLM.MaxTokens)
}

// ---------------------------------------------------------------------------
// LoadAgentYaml — invalid fixtures
// ---------------------------------------------------------------------------

func TestLoadAgentYaml_InvalidMissingAgent(t *testing.T) {
	_, err := LoadAgentYaml(fixturePath("invalid-missing-agent.yaml"))
	require.Error(t, err, "missing agent section should cause a validation error")

	// Should report missing agent.id and agent.name at minimum
	errStr := err.Error()
	assert.Contains(t, errStr, "agent.id")
	assert.Contains(t, errStr, "agent.name")
}

func TestLoadAgentYaml_InvalidOverlap(t *testing.T) {
	_, err := LoadAgentYaml(fixturePath("invalid-overlap.yaml"))
	require.Error(t, err, "overlapping allowed/denied actions should fail")

	errStr := err.Error()
	assert.Contains(t, errStr, "execute_python")
	assert.Contains(t, errStr, "allowed_actions")
}

func TestLoadAgentYaml_InvalidRedTeam(t *testing.T) {
	_, err := LoadAgentYaml(fixturePath("invalid-red-team.yaml"))
	require.Error(t, err, "red team without offensive_isolated should fail")

	errStr := err.Error()
	assert.Contains(t, errStr, "sandbox_profile")
	assert.Contains(t, errStr, "audit_level")
}

func TestLoadAgentYaml_InvalidAutonomous(t *testing.T) {
	_, err := LoadAgentYaml(fixturePath("invalid-autonomous.yaml"))
	require.Error(t, err, "fully_autonomous with low confidence should fail")

	errStr := err.Error()
	assert.Contains(t, errStr, "confidence_threshold")
	assert.Contains(t, errStr, "0.9")
}

// ---------------------------------------------------------------------------
// LoadAgentYaml — missing file
// ---------------------------------------------------------------------------

func TestLoadAgentYaml_FileNotFound(t *testing.T) {
	_, err := LoadAgentYaml(fixturePath("does-not-exist.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Slug format validation
// ---------------------------------------------------------------------------

func TestValidation_SlugFormat(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid lowercase with hyphens", "risk-quant-v1", false},
		{"valid numeric boundaries", "a1b2c3", false},
		{"invalid starts with hyphen", "-bad-id", true},
		{"invalid ends with hyphen", "bad-id-", true},
		{"invalid uppercase", "Bad-Agent", true},
		{"invalid underscore", "bad_agent", true},
		{"invalid spaces", "bad agent", true},
		{"empty string", "", true},
		{"single char", "a", true}, // pattern requires at least 2 chars
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := minimalValidDSL()
			d.Agent.ID = tc.id
			d.SetDefaults()
			err := d.Validate()

			if tc.wantErr {
				require.Error(t, err, "expected validation error for id=%q", tc.id)
			} else {
				require.NoError(t, err, "expected no error for id=%q", tc.id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Semver validation
// ---------------------------------------------------------------------------

func TestValidation_SemverFormat(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		{"valid semver", "1.0.0", false},
		{"valid semver large", "12.34.56", false},
		{"missing patch", "1.0", true},
		{"extra parts", "1.0.0.0", true},
		{"alpha characters", "v1.0.0", true},
		{"empty string", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := minimalValidDSL()
			d.Agent.Version = tc.version
			d.SetDefaults()
			err := d.Validate()

			if tc.wantErr {
				require.Error(t, err, "expected validation error for version=%q", tc.version)
			} else {
				require.NoError(t, err, "expected no error for version=%q", tc.version)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-field: Red team requires offensive_isolated + verbose audit
// ---------------------------------------------------------------------------

func TestValidation_RedTeamRequiresOffensiveIsolated(t *testing.T) {
	d := minimalValidDSL()
	d.Agent.Domain = DomainRedTeam
	d.Safety.SandboxProfile = SandboxStandard // wrong
	d.Safety.AuditLevel = AuditStandard       // wrong
	d.SetDefaults()

	err := d.Validate()
	require.Error(t, err)
	errStr := err.Error()
	assert.Contains(t, errStr, "offensive_isolated")
	assert.Contains(t, errStr, "verbose")
}

func TestValidation_RedTeamWithCorrectSafety(t *testing.T) {
	d := minimalValidDSL()
	d.Agent.Domain = DomainRedTeam
	d.Safety.SandboxProfile = SandboxOffensiveIsolated
	d.Safety.AuditLevel = AuditVerbose
	d.SetDefaults()

	err := d.Validate()
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Cross-field: fully_autonomous requires confidence >= 0.9
// ---------------------------------------------------------------------------

func TestValidation_FullyAutonomousRequiresHighConfidence(t *testing.T) {
	d := minimalValidDSL()
	d.Reasoning.AutonomyLevel = AutonomyFullyAutonomous
	d.Reasoning.ConfidenceThreshold = 0.5
	d.SetDefaults()

	err := d.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0.9")
}

func TestValidation_FullyAutonomousAt09Passes(t *testing.T) {
	d := minimalValidDSL()
	d.Reasoning.AutonomyLevel = AutonomyFullyAutonomous
	d.Reasoning.ConfidenceThreshold = 0.9
	d.SetDefaults()

	err := d.Validate()
	require.NoError(t, err)
}

func TestValidation_FullyAutonomousAt1Passes(t *testing.T) {
	d := minimalValidDSL()
	d.Reasoning.AutonomyLevel = AutonomyFullyAutonomous
	d.Reasoning.ConfidenceThreshold = 1.0
	d.SetDefaults()

	err := d.Validate()
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// SetDefaults — LLM auto-population for llm_react mode
// ---------------------------------------------------------------------------

func TestSetDefaults_LLMReactAutoPopulatesLLMConfig(t *testing.T) {
	d := minimalValidDSL()
	d.Reasoning.Mode = ReasoningLLMReAct
	d.Reasoning.LLM = nil // no LLM config provided

	d.SetDefaults()

	require.NotNil(t, d.Reasoning.LLM, "llm_react mode should auto-populate LLM config")
	assert.Equal(t, "openai", d.Reasoning.LLM.Provider)
	assert.Equal(t, "gpt-4o", d.Reasoning.LLM.Model)
	assert.InDelta(t, 0.2, d.Reasoning.LLM.Temperature, 0.001)
	assert.Equal(t, 10, d.Reasoning.LLM.MaxIterations)
	assert.Equal(t, 4096, d.Reasoning.LLM.MaxTokens)
}

func TestSetDefaults_DeterministicDoesNotPopulateLLM(t *testing.T) {
	d := minimalValidDSL()
	d.Reasoning.Mode = ReasoningDeterministic
	d.Reasoning.LLM = nil

	d.SetDefaults()

	assert.Nil(t, d.Reasoning.LLM, "deterministic mode should NOT auto-populate LLM config")
}

func TestSetDefaults_PartialLLMConfigFilled(t *testing.T) {
	d := minimalValidDSL()
	d.Reasoning.Mode = ReasoningLLMReAct
	d.Reasoning.LLM = &LLMConfig{
		Provider: "anthropic", // user-specified
		// all other fields left at zero value
	}

	d.SetDefaults()

	assert.Equal(t, "anthropic", d.Reasoning.LLM.Provider, "user-specified provider should be preserved")
	assert.Equal(t, "gpt-4o", d.Reasoning.LLM.Model, "zero-value model should be filled")
	assert.InDelta(t, 0.2, d.Reasoning.LLM.Temperature, 0.001)
	assert.Equal(t, 10, d.Reasoning.LLM.MaxIterations)
	assert.Equal(t, 4096, d.Reasoning.LLM.MaxTokens)
}

// ---------------------------------------------------------------------------
// SetDefaults — zero-value fields
// ---------------------------------------------------------------------------

func TestSetDefaults_FillsZeroValueFields(t *testing.T) {
	d := &AgentDSL{
		Agent: AgentIdentity{
			ID:      "defaults-test-v1",
			Name:    "Defaults Test",
			Domain:  DomainAppSec,
			Version: "1.0.0",
		},
		Intent: AgentIntent{
			Goal: "Test defaults",
		},
		Reasoning: ReasoningConfig{
			Mode: ReasoningDeterministic,
		},
	}

	d.SetDefaults()

	// Intent
	assert.Equal(t, PriorityMedium, d.Intent.Priority)
	assert.NotNil(t, d.Intent.SuccessCriteria)
	assert.Empty(t, d.Intent.SuccessCriteria)

	// Reasoning
	assert.Equal(t, AutonomyBounded, d.Reasoning.AutonomyLevel)
	assert.InDelta(t, 0.75, d.Reasoning.ConfidenceThreshold, 0.001)

	// Capabilities
	assert.NotNil(t, d.Capabilities.Tools)
	assert.NotNil(t, d.Capabilities.DataAccess)
	assert.NotNil(t, d.Capabilities.GraphAccess)

	// Boundaries
	assert.Equal(t, RiskBudgetMedium, d.Boundaries.RiskBudget)
	assert.NotNil(t, d.Boundaries.AllowedActions)
	assert.NotNil(t, d.Boundaries.DeniedActions)
	assert.NotNil(t, d.Boundaries.EnvironmentScope)
	assert.NotNil(t, d.Boundaries.ApprovalGates)

	// Safety
	assert.Equal(t, SandboxStandard, d.Safety.SandboxProfile)
	assert.Equal(t, AuditStandard, d.Safety.AuditLevel)
	assert.NotNil(t, d.Safety.Guardrails)
}

// ---------------------------------------------------------------------------
// Allowed/Denied overlap rejected
// ---------------------------------------------------------------------------

func TestValidation_AllowedDeniedOverlapRejected(t *testing.T) {
	d := minimalValidDSL()
	d.Boundaries.AllowedActions = []string{"read_asset", "execute_python"}
	d.Boundaries.DeniedActions = []string{"execute_python"}
	d.SetDefaults()

	err := d.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "execute_python")
}

func TestValidation_NoOverlapPasses(t *testing.T) {
	d := minimalValidDSL()
	d.Boundaries.AllowedActions = []string{"read_asset"}
	d.Boundaries.DeniedActions = []string{"execute_python"}
	d.SetDefaults()

	err := d.Validate()
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// ValidateAgentFile — structured ValidationResult
// ---------------------------------------------------------------------------

func TestValidateAgentFile_ValidReturnsValidResult(t *testing.T) {
	result := ValidateAgentFile(fixturePath("valid-generic.yaml"))
	require.NotNil(t, result)

	assert.True(t, result.Valid)
	assert.Equal(t, "test-generic-v1", result.AgentID)
	assert.Empty(t, result.Errors)
}

func TestValidateAgentFile_InvalidReturnsErrors(t *testing.T) {
	result := ValidateAgentFile(fixturePath("invalid-missing-agent.yaml"))
	require.NotNil(t, result)

	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.Errors, "should contain validation errors")
}

func TestValidateAgentFile_MissingFileReturnsError(t *testing.T) {
	result := ValidateAgentFile(fixturePath("nonexistent.yaml"))
	require.NotNil(t, result)

	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "not found")
}

func TestValidateAgentFile_OverlapReturnsAgentID(t *testing.T) {
	result := ValidateAgentFile(fixturePath("invalid-overlap.yaml"))
	require.NotNil(t, result)

	assert.False(t, result.Valid)
	assert.Equal(t, "overlap-test-v1", result.AgentID)
	assert.NotEmpty(t, result.Errors)
}

// ---------------------------------------------------------------------------
// ValidateAgentString — string input
// ---------------------------------------------------------------------------

func TestValidateAgentString_ValidInput(t *testing.T) {
	yaml := `
agent:
  id: inline-test-v1
  name: Inline Test
  domain: appsec
  version: "1.0.0"
intent:
  goal: Test inline parsing
reasoning:
  mode: deterministic
`
	result := ValidateAgentString(yaml)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
	assert.Equal(t, "inline-test-v1", result.AgentID)
}

func TestValidateAgentString_InvalidInput(t *testing.T) {
	yaml := `
agent:
  id: INVALID_ID
  domain: fake_domain
`
	result := ValidateAgentString(yaml)
	require.NotNil(t, result)
	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.Errors)
}

// ---------------------------------------------------------------------------
// LoadAgentYamlString — string convenience wrapper
// ---------------------------------------------------------------------------

func TestLoadAgentYamlString_ValidInput(t *testing.T) {
	yaml := `
agent:
  id: string-test-v1
  name: String Test
  domain: compliance
  version: "2.0.0"
intent:
  goal: Test string loading
reasoning:
  mode: rule_based
`
	dsl, err := LoadAgentYamlString(yaml)
	require.NoError(t, err)
	require.NotNil(t, dsl)
	assert.Equal(t, "string-test-v1", dsl.Agent.ID)
	assert.Equal(t, DomainCompliance, dsl.Agent.Domain)
}

func TestLoadAgentYamlString_InvalidYaml(t *testing.T) {
	_, err := LoadAgentYamlString("{{invalid yaml content")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "YAML")
}

// ---------------------------------------------------------------------------
// ValidationResult String() output
// ---------------------------------------------------------------------------

func TestValidationResult_StringValid(t *testing.T) {
	r := &ValidationResult{Valid: true, AgentID: "test-v1"}
	s := r.String()
	assert.Contains(t, s, "test-v1")
}

func TestValidationResult_StringInvalid(t *testing.T) {
	r := &ValidationResult{
		Valid:   false,
		AgentID: "bad-v1",
		Errors:  []string{"error one", "error two"},
	}
	s := r.String()
	assert.Contains(t, s, "2 error(s)")
	assert.Contains(t, s, "error one")
	assert.Contains(t, s, "error two")
}

// ---------------------------------------------------------------------------
// ValidationError type
// ---------------------------------------------------------------------------

func TestValidationError_ErrorString(t *testing.T) {
	ve := &ValidationError{}
	ve.add("first error")
	ve.addAt("agent.id", "invalid id")

	assert.True(t, ve.hasErrors())
	assert.Len(t, ve.Errors, 2)
	assert.Contains(t, ve.Error(), "2 error(s)")
	assert.Contains(t, ve.Error(), "first error")
	assert.Contains(t, ve.Error(), "[agent.id]")
}

// ---------------------------------------------------------------------------
// Enum validation helpers
// ---------------------------------------------------------------------------

func TestDomainValid(t *testing.T) {
	assert.True(t, DomainRedTeam.Valid())
	assert.True(t, DomainAppSec.Valid())
	assert.True(t, DomainRiskQuant.Valid())
	assert.False(t, Domain("invalid_domain").Valid())
	assert.False(t, Domain("").Valid())
}

func TestReasoningModeValid(t *testing.T) {
	assert.True(t, ReasoningDeterministic.Valid())
	assert.True(t, ReasoningLLMReAct.Valid())
	assert.False(t, ReasoningMode("quantum").Valid())
}

func TestAutonomyLevelValid(t *testing.T) {
	assert.True(t, AutonomyObserve.Valid())
	assert.True(t, AutonomyFullyAutonomous.Valid())
	assert.False(t, AutonomyLevel("chaotic").Valid())
}

func TestPriorityValid(t *testing.T) {
	assert.True(t, PriorityLow.Valid())
	assert.True(t, PriorityCritical.Valid())
	assert.False(t, Priority("urgent").Valid())
}

func TestRiskBudgetValid(t *testing.T) {
	assert.True(t, RiskBudgetLow.Valid())
	assert.True(t, RiskBudgetHigh.Valid())
	assert.False(t, RiskBudget("unlimited").Valid())
}

func TestSandboxProfileValid(t *testing.T) {
	assert.True(t, SandboxMinimal.Valid())
	assert.True(t, SandboxOffensiveIsolated.Valid())
	assert.False(t, SandboxProfile("none").Valid())
}

func TestAuditLevelValid(t *testing.T) {
	assert.True(t, AuditMinimal.Valid())
	assert.True(t, AuditVerbose.Valid())
	assert.False(t, AuditLevel("debug").Valid())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// minimalValidDSL returns a minimal AgentDSL that passes validation.
// Callers can modify fields before calling SetDefaults() + Validate().
func minimalValidDSL() *AgentDSL {
	return &AgentDSL{
		Agent: AgentIdentity{
			ID:      "test-agent-v1",
			Name:    "Test Agent",
			Domain:  DomainAppSec,
			Version: "1.0.0",
		},
		Intent: AgentIntent{
			Goal:     "Test goal",
			Priority: PriorityMedium,
		},
		Reasoning: ReasoningConfig{
			Mode:                ReasoningDeterministic,
			AutonomyLevel:       AutonomyBounded,
			ConfidenceThreshold: 0.75,
		},
		Boundaries: BoundariesConfig{
			RiskBudget: RiskBudgetMedium,
		},
		Safety: SafetyConfig{
			SandboxProfile: SandboxStandard,
			AuditLevel:     AuditStandard,
		},
	}
}
