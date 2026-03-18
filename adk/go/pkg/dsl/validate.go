package dsl

import (
	"fmt"
	"strings"
)

// ValidationError collects multiple validation issues.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed with %d error(s):\n  %s",
		len(e.Errors), strings.Join(e.Errors, "\n  "))
}

func (e *ValidationError) add(msg string) {
	e.Errors = append(e.Errors, msg)
}

func (e *ValidationError) addAt(path, msg string) {
	e.Errors = append(e.Errors, fmt.Sprintf("[%s] %s", path, msg))
}

func (e *ValidationError) hasErrors() bool {
	return len(e.Errors) > 0
}

// Validate checks the entire AgentDSL for correctness.
// Call SetDefaults() before Validate() to fill in zero-value fields.
func (d *AgentDSL) Validate() error {
	errs := &ValidationError{}

	d.validateAgent(errs)
	d.validateIntent(errs)
	d.validateReasoning(errs)
	d.validateBoundaries(errs)
	d.validateSafety(errs)
	d.validateCrossField(errs)

	if errs.hasErrors() {
		return errs
	}
	return nil
}

func (d *AgentDSL) validateAgent(errs *ValidationError) {
	a := d.Agent

	if a.ID == "" {
		errs.addAt("agent.id", "agent id is required")
	} else if !slugPattern.MatchString(a.ID) {
		errs.addAt("agent.id",
			fmt.Sprintf("agent id '%s' must be lowercase alphanumeric with hyphens only (e.g. 'risk-quant-v1')", a.ID))
	}

	if a.Name == "" {
		errs.addAt("agent.name", "agent name is required")
	}

	if !a.Domain.Valid() {
		errs.addAt("agent.domain", fmt.Sprintf("invalid domain: '%s'", a.Domain))
	}

	if a.Version == "" {
		errs.addAt("agent.version", "version is required")
	} else if !semverPattern.MatchString(a.Version) {
		errs.addAt("agent.version",
			fmt.Sprintf("version '%s' must be semver format (e.g. '1.0.0')", a.Version))
	}
}

func (d *AgentDSL) validateIntent(errs *ValidationError) {
	if d.Intent.Goal == "" {
		errs.addAt("intent.goal", "goal is required")
	}

	if !d.Intent.Priority.Valid() {
		errs.addAt("intent.priority",
			fmt.Sprintf("invalid priority: '%s'", d.Intent.Priority))
	}
}

func (d *AgentDSL) validateReasoning(errs *ValidationError) {
	r := d.Reasoning

	if !r.Mode.Valid() {
		errs.addAt("reasoning.mode",
			fmt.Sprintf("invalid reasoning mode: '%s'", r.Mode))
	}

	if !r.AutonomyLevel.Valid() {
		errs.addAt("reasoning.autonomy_level",
			fmt.Sprintf("invalid autonomy level: '%s'", r.AutonomyLevel))
	}

	if r.ConfidenceThreshold < 0.0 || r.ConfidenceThreshold > 1.0 {
		errs.addAt("reasoning.confidence_threshold",
			"confidence_threshold must be between 0.0 and 1.0")
	}

	if r.LLM != nil {
		llm := r.LLM
		if llm.Temperature < 0.0 || llm.Temperature > 2.0 {
			errs.addAt("reasoning.llm.temperature",
				"temperature must be between 0.0 and 2.0")
		}
		if llm.MaxIterations < 1 || llm.MaxIterations > 50 {
			errs.addAt("reasoning.llm.max_iterations",
				"max_iterations must be between 1 and 50")
		}
		if llm.MaxTokens < 256 || llm.MaxTokens > 32768 {
			errs.addAt("reasoning.llm.max_tokens",
				"max_tokens must be between 256 and 32768")
		}
	}
}

func (d *AgentDSL) validateBoundaries(errs *ValidationError) {
	b := d.Boundaries

	if !b.RiskBudget.Valid() {
		errs.addAt("boundaries.risk_budget",
			fmt.Sprintf("invalid risk_budget: '%s'", b.RiskBudget))
	}

	// Check overlap between allowed and denied
	allowedSet := make(map[string]bool, len(b.AllowedActions))
	for _, a := range b.AllowedActions {
		allowedSet[a] = true
	}

	var overlap []string
	for _, a := range b.DeniedActions {
		if allowedSet[a] {
			overlap = append(overlap, a)
		}
	}

	if len(overlap) > 0 {
		errs.addAt("boundaries.allowed_actions",
			fmt.Sprintf("Actions [%s] appear in both allowed_actions and denied_actions. "+
				"Denied actions always take precedence — remove them from allowed_actions.",
				strings.Join(overlap, ", ")))
	}
}

func (d *AgentDSL) validateSafety(errs *ValidationError) {
	if !d.Safety.SandboxProfile.Valid() {
		errs.addAt("safety.sandbox_profile",
			fmt.Sprintf("invalid sandbox_profile: '%s'", d.Safety.SandboxProfile))
	}

	if !d.Safety.AuditLevel.Valid() {
		errs.addAt("safety.audit_level",
			fmt.Sprintf("invalid audit_level: '%s'", d.Safety.AuditLevel))
	}
}

func (d *AgentDSL) validateCrossField(errs *ValidationError) {
	// Rule 1: Red team agents MUST use offensive_isolated + verbose
	if d.Agent.Domain == DomainRedTeam {
		if d.Safety.SandboxProfile != SandboxOffensiveIsolated {
			errs.addAt("safety.sandbox_profile",
				"Red team agents MUST use sandbox_profile: offensive_isolated. "+
					"Safety requirement cannot be overridden.")
		}
		if d.Safety.AuditLevel != AuditVerbose {
			errs.addAt("safety.audit_level",
				"Red team agents MUST use audit_level: verbose. "+
					"Safety requirement cannot be overridden.")
		}
	}

	// Rule 3: fully_autonomous requires confidence >= 0.9
	if d.Reasoning.AutonomyLevel == AutonomyFullyAutonomous {
		if d.Reasoning.ConfidenceThreshold < 0.9 {
			errs.addAt("reasoning.confidence_threshold",
				"fully_autonomous autonomy level requires confidence_threshold >= 0.9")
		}
	}
}
