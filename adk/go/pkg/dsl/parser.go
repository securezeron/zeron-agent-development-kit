package dsl

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ValidationResult is a structured result from validating an agent YAML definition.
type ValidationResult struct {
	Valid   bool     `json:"valid"`
	AgentID string   `json:"agent_id,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}

// String returns a human-readable representation.
func (r *ValidationResult) String() string {
	if r.Valid {
		return fmt.Sprintf("\u2705 Valid agent definition: %s", r.AgentID)
	}
	lines := []string{fmt.Sprintf("\u274C Invalid agent definition \u2014 %d error(s):", len(r.Errors))}
	for i, err := range r.Errors {
		lines = append(lines, fmt.Sprintf("  %d. %s", i+1, err))
	}
	return strings.Join(lines, "\n")
}

// LoadAgentYaml loads and validates a US-ADSL agent YAML file.
// Returns an error if the file is not found, not valid YAML, or fails validation.
func LoadAgentYaml(path string) (*AgentDSL, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("agent definition not found: %s", path)
		}
		return nil, fmt.Errorf("reading file: %w", err)
	}

	return LoadAgentYamlBytes(data)
}

// LoadAgentYamlBytes parses and validates a US-ADSL YAML byte slice.
func LoadAgentYamlBytes(data []byte) (*AgentDSL, error) {
	var dsl AgentDSL
	if err := yaml.Unmarshal(data, &dsl); err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}

	dsl.SetDefaults()

	if err := dsl.Validate(); err != nil {
		return nil, err
	}

	return &dsl, nil
}

// LoadAgentYamlString parses and validates a US-ADSL YAML string.
func LoadAgentYamlString(content string) (*AgentDSL, error) {
	return LoadAgentYamlBytes([]byte(content))
}

// ValidateAgentFile validates an agent YAML file and returns a structured result.
// Unlike LoadAgentYaml(), this never returns an error — issues are captured in ValidationResult.
func ValidateAgentFile(path string) *ValidationResult {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("File not found: %s", path)}}
		}
		return &ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("Error reading file: %s", err)}}
	}

	return ValidateAgentBytes(data)
}

// ValidateAgentBytes validates a YAML byte slice and returns a structured result.
func ValidateAgentBytes(data []byte) *ValidationResult {
	var dsl AgentDSL
	if err := yaml.Unmarshal(data, &dsl); err != nil {
		return &ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("YAML syntax error: %s", err)}}
	}

	dsl.SetDefaults()

	if err := dsl.Validate(); err != nil {
		if ve, ok := err.(*ValidationError); ok {
			agentID := dsl.Agent.ID
			return &ValidationResult{Valid: false, AgentID: agentID, Errors: ve.Errors}
		}
		return &ValidationResult{Valid: false, AgentID: dsl.Agent.ID, Errors: []string{err.Error()}}
	}

	return &ValidationResult{Valid: true, AgentID: dsl.Agent.ID}
}

// ValidateAgentString validates a YAML string and returns a structured result.
func ValidateAgentString(content string) *ValidationResult {
	return ValidateAgentBytes([]byte(content))
}
