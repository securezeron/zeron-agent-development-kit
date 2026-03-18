// Package zak provides the Go SDK for the Zeron Agentic Kit (ZAK),
// an open-source Agent Development Kit for building autonomous cybersecurity agents.
//
// ZAK enables declarative agent definitions using the Universal Security Agent DSL
// (US-ADSL), runtime policy enforcement, structured audit logging, and LLM-powered
// autonomous reasoning via the ReAct pattern.
//
// # Installation
//
//	go get github.com/securezeron/zeron-agent-development-kit/adk/go@latest
//
// # Quick Start
//
// Parse and validate an agent definition:
//
//	import "github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
//
//	result := dsl.LoadAgentYaml("my-agent.agent.yaml")
//	if !result.Valid {
//	    log.Fatal(result.Errors)
//	}
//	agent := result.Agent
//
// Evaluate policy at runtime:
//
//	import "github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/policy"
//
//	engine := policy.NewEngine()
//	decision := engine.Evaluate(agent, "scan_code", "production", nil)
//	if decision.Allowed {
//	    // proceed
//	}
//
// Register a tool with automatic policy + audit integration:
//
//	import "github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/tools"
//
//	scanTool := tools.NewZakTool(tools.ZakToolConfig{
//	    Name:        "scan_code",
//	    Description: "Scan source code for vulnerabilities",
//	    Execute: func(ctx context.Context, params map[string]any) (any, error) {
//	        return map[string]any{"vulnerabilities": []any{}}, nil
//	    },
//	})
//
// # Packages
//
// The SDK is organized into the following packages:
//
//   - pkg/dsl — US-ADSL schema, parser, and validation
//   - pkg/policy — Policy engine with 6-rule evaluation chain
//   - pkg/audit — Structured audit event logging (zerolog)
//   - pkg/edition — Edition detection (open-source vs enterprise)
//   - pkg/runtime — BaseAgent, AgentRegistry, AgentExecutor, LLMAgent
//   - pkg/tools — Tool substrate, built-in tools, orchestration
//   - pkg/llm — LLM client interface and provider registry
//   - pkg/sif/schema — Security Intelligence Fabric node and edge types
//   - pkg/sif/risk — Risk propagation engine
//   - pkg/tenants — Multi-tenant context and namespace isolation
//
// # CLI
//
// Install the CLI:
//
//	go install github.com/securezeron/zeron-agent-development-kit/adk/go/cmd/zak@latest
//
// Available commands:
//
//	zak init --domain appsec --name my-agent   # Scaffold agent YAML
//	zak validate my-agent.agent.yaml           # Validate agent definition
//	zak run my-agent.agent.yaml                # Execute agent
//	zak agents                                 # List registered agents
//	zak info                                   # Platform information
//
// # Links
//
//   - Homepage: https://zeron.one
//   - Repository: https://github.com/securezeron/zeron-agent-development-kit
//   - Python SDK: https://pypi.org/project/zin-adk/
//   - Node.js SDK: https://www.npmjs.com/package/zin-adk
package zak
