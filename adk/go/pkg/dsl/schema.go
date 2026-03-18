package dsl

import "regexp"

// AgentIdentity identifies the agent uniquely within the platform.
type AgentIdentity struct {
	ID      string `yaml:"id" json:"id"`
	Name    string `yaml:"name" json:"name"`
	Domain  Domain `yaml:"domain" json:"domain"`
	Version string `yaml:"version" json:"version"`
}

// AgentIntent describes what the agent is trying to achieve.
type AgentIntent struct {
	Goal            string   `yaml:"goal" json:"goal"`
	SuccessCriteria []string `yaml:"success_criteria" json:"success_criteria"`
	Priority        Priority `yaml:"priority" json:"priority"`
}

// LLMConfig holds LLM provider configuration.
type LLMConfig struct {
	Provider      string  `yaml:"provider" json:"provider"`
	Model         string  `yaml:"model" json:"model"`
	Temperature   float64 `yaml:"temperature" json:"temperature"`
	MaxIterations int     `yaml:"max_iterations" json:"max_iterations"`
	MaxTokens     int     `yaml:"max_tokens" json:"max_tokens"`
}

// DefaultLLMConfig returns an LLMConfig with default values.
func DefaultLLMConfig() *LLMConfig {
	return &LLMConfig{
		Provider:      "openai",
		Model:         "gpt-4o",
		Temperature:   0.2,
		MaxIterations: 10,
		MaxTokens:     4096,
	}
}

// ReasoningConfig controls how the agent thinks and decides.
type ReasoningConfig struct {
	Mode                ReasoningMode `yaml:"mode" json:"mode"`
	AutonomyLevel       AutonomyLevel `yaml:"autonomy_level" json:"autonomy_level"`
	ConfidenceThreshold float64       `yaml:"confidence_threshold" json:"confidence_threshold"`
	LLM                 *LLMConfig    `yaml:"llm,omitempty" json:"llm,omitempty"`
}

// CapabilitiesConfig describes what the agent is allowed to use/access.
type CapabilitiesConfig struct {
	Tools       []string `yaml:"tools" json:"tools"`
	DataAccess  []string `yaml:"data_access" json:"data_access"`
	GraphAccess []string `yaml:"graph_access" json:"graph_access"`
}

// BoundariesConfig holds hard constraints on agent behaviour.
type BoundariesConfig struct {
	RiskBudget       RiskBudget `yaml:"risk_budget" json:"risk_budget"`
	AllowedActions   []string   `yaml:"allowed_actions" json:"allowed_actions"`
	DeniedActions    []string   `yaml:"denied_actions" json:"denied_actions"`
	EnvironmentScope []string   `yaml:"environment_scope" json:"environment_scope"`
	ApprovalGates    []string   `yaml:"approval_gates" json:"approval_gates"`
}

// SafetyConfig defines safety guardrails applied to every execution.
type SafetyConfig struct {
	Guardrails     []string       `yaml:"guardrails" json:"guardrails"`
	SandboxProfile SandboxProfile `yaml:"sandbox_profile" json:"sandbox_profile"`
	AuditLevel     AuditLevel     `yaml:"audit_level" json:"audit_level"`
}

// AgentDSL is the complete validated representation of a US-ADSL agent definition.
type AgentDSL struct {
	Agent        AgentIdentity      `yaml:"agent" json:"agent"`
	Intent       AgentIntent        `yaml:"intent" json:"intent"`
	Reasoning    ReasoningConfig    `yaml:"reasoning" json:"reasoning"`
	Capabilities CapabilitiesConfig `yaml:"capabilities" json:"capabilities"`
	Boundaries   BoundariesConfig   `yaml:"boundaries" json:"boundaries"`
	Safety       SafetyConfig       `yaml:"safety" json:"safety"`
}

var (
	slugPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]*[a-z0-9]$`)
	semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// SetDefaults fills in zero-value fields with their canonical defaults.
// Call this after YAML unmarshalling and before Validate().
func (d *AgentDSL) SetDefaults() {
	// Intent defaults
	if d.Intent.Priority == "" {
		d.Intent.Priority = PriorityMedium
	}
	if d.Intent.SuccessCriteria == nil {
		d.Intent.SuccessCriteria = []string{}
	}

	// Reasoning defaults
	if d.Reasoning.AutonomyLevel == "" {
		d.Reasoning.AutonomyLevel = AutonomyBounded
	}
	if d.Reasoning.ConfidenceThreshold == 0 {
		d.Reasoning.ConfidenceThreshold = 0.75
	}

	// Capabilities defaults
	if d.Capabilities.Tools == nil {
		d.Capabilities.Tools = []string{}
	}
	if d.Capabilities.DataAccess == nil {
		d.Capabilities.DataAccess = []string{}
	}
	if d.Capabilities.GraphAccess == nil {
		d.Capabilities.GraphAccess = []string{}
	}

	// Boundaries defaults
	if d.Boundaries.RiskBudget == "" {
		d.Boundaries.RiskBudget = RiskBudgetMedium
	}
	if d.Boundaries.AllowedActions == nil {
		d.Boundaries.AllowedActions = []string{}
	}
	if d.Boundaries.DeniedActions == nil {
		d.Boundaries.DeniedActions = []string{}
	}
	if d.Boundaries.EnvironmentScope == nil {
		d.Boundaries.EnvironmentScope = []string{}
	}
	if d.Boundaries.ApprovalGates == nil {
		d.Boundaries.ApprovalGates = []string{}
	}

	// Safety defaults
	if d.Safety.SandboxProfile == "" {
		d.Safety.SandboxProfile = SandboxStandard
	}
	if d.Safety.AuditLevel == "" {
		d.Safety.AuditLevel = AuditStandard
	}
	if d.Safety.Guardrails == nil {
		d.Safety.Guardrails = []string{}
	}

	// Auto-populate LLM config for llm_react mode
	if d.Reasoning.Mode == ReasoningLLMReAct && d.Reasoning.LLM == nil {
		d.Reasoning.LLM = DefaultLLMConfig()
	}

	// Set LLM defaults if partial config provided
	if d.Reasoning.LLM != nil {
		if d.Reasoning.LLM.Provider == "" {
			d.Reasoning.LLM.Provider = "openai"
		}
		if d.Reasoning.LLM.Model == "" {
			d.Reasoning.LLM.Model = "gpt-4o"
		}
		if d.Reasoning.LLM.Temperature == 0 {
			d.Reasoning.LLM.Temperature = 0.2
		}
		if d.Reasoning.LLM.MaxIterations == 0 {
			d.Reasoning.LLM.MaxIterations = 10
		}
		if d.Reasoning.LLM.MaxTokens == 0 {
			d.Reasoning.LLM.MaxTokens = 4096
		}
	}
}
