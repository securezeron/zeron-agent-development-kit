// Package dsl provides the Universal Security Agent DSL (US-ADSL) schema,
// parser, and validation for the ZAK Agent Development Kit.
//
// The DSL defines agent behavior declaratively using YAML files. This package
// handles parsing YAML into typed Go structs, applying default values, and
// running cross-field validation rules.
//
// # Schema Types
//
// The core type is [AgentDSL], which contains:
//   - Agent metadata (name, domain, description, version)
//   - Capabilities (allowed/denied actions, autonomy level, confidence threshold)
//   - Policy constraints (max actions per minute, risk budget, environment restrictions)
//   - Reasoning configuration (mode, LLM settings, tool bindings)
//   - Boundaries (sandbox type, network access, output restrictions)
//
// # Parsing
//
// Use [LoadAgentYaml] to parse a YAML file and [ValidateAgentFile] for
// file-level validation:
//
//	result := dsl.LoadAgentYaml("agent.yaml")
//	if result.Valid {
//	    agent := result.Agent
//	    fmt.Println(agent.Agent.Name)
//	}
//
// # Validation Rules
//
// Three cross-field validators are applied automatically:
//   - Red-team agents require offensive_isolated sandbox and verbose audit
//   - LLM ReAct agents auto-populate LLM configuration defaults
//   - Fully autonomous agents require confidence threshold >= 0.9
package dsl
