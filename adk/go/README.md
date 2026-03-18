# zin-adk (Go)

[![Go Reference](https://pkg.go.dev/badge/github.com/securezeron/zeron-agent-development-kit/adk/go.svg)](https://pkg.go.dev/github.com/securezeron/zeron-agent-development-kit/adk/go)
[![Go Report Card](https://goreportcard.com/badge/github.com/securezeron/zeron-agent-development-kit/adk/go)](https://goreportcard.com/report/github.com/securezeron/zeron-agent-development-kit/adk/go)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)

**ZAK (Zeron Agentic Kit)** — Go SDK for building autonomous cybersecurity agents.

Define security agents declaratively with YAML, enforce policy guardrails at runtime, and connect to LLM providers for autonomous reasoning.

## Install

```bash
go get github.com/securezeron/zeron-agent-development-kit/adk/go@latest
```

CLI only:

```bash
go install github.com/securezeron/zeron-agent-development-kit/adk/go/cmd/zak@latest
```

## Quick Start

### 1. Create an Agent Definition

```bash
zak init --domain appsec --name my-scanner
```

### 2. Validate

```bash
zak validate my-scanner.agent.yaml
```

### 3. Use in Code

```go
package main

import (
    "fmt"
    "log"

    "github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
    "github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/policy"
)

func main() {
    // Parse and validate an agent definition
    result := dsl.LoadAgentYaml("my-scanner.agent.yaml")
    if !result.Valid {
        log.Fatalf("Validation errors: %v", result.Errors)
    }

    // Policy engine enforces guardrails at runtime
    engine := policy.NewEngine()
    decision := engine.Evaluate(result.Agent, "scan_code", "production", nil)

    if decision.Allowed {
        fmt.Println("Action allowed — executing scan")
    } else {
        fmt.Printf("Action denied: %s\n", decision.Reason)
    }
}
```

## Packages

| Package | Description |
|---------|-------------|
| `pkg/dsl` | US-ADSL schema, parser, and validation (Zod-equivalent struct validation) |
| `pkg/policy` | Policy engine — 6-rule evaluation chain |
| `pkg/audit` | Structured audit event logging via zerolog |
| `pkg/edition` | Edition detection (open-source vs enterprise) |
| `pkg/runtime` | BaseAgent, AgentRegistry, AgentExecutor, LLMAgent |
| `pkg/tools` | Tool substrate — `NewZakTool()` with policy + audit integration |
| `pkg/llm` | LLM client interface, provider registry, MockLLMClient |
| `pkg/sif/schema` | Security Intelligence Fabric — 7 node types, 7 edge types |
| `pkg/sif/risk` | Risk propagation engine with quantitative scoring |
| `pkg/tenants` | Multi-tenant context and namespace isolation |

## CLI

```bash
zak init --domain <domain> --name <name>   # Scaffold agent YAML
zak validate <file.yaml>                    # Validate agent definition
zak run <file.yaml>                         # Execute agent
zak agents                                  # List registered agents
zak info                                    # Platform information
```

Available domains: `generic`, `risk_quant`, `vuln_triage`, `appsec`, `compliance`

## Building

```bash
make build          # Build binary to ./bin/zak
make test           # Run all tests with race detection
make test-coverage  # Generate HTML coverage report
make lint           # Run go vet
make check          # Lint + test
make install        # go install to $GOPATH/bin
```

## Requirements

- Go >= 1.22

## Publishing

Go modules are published via git tags. Since this module lives in the `adk/go/` subdirectory of the monorepo, tags use a path prefix:

```bash
# Tag a release
git tag -a adk/go/v0.1.4 -m "Release Go ADK v0.1.4"
git push origin adk/go/v0.1.4

# Request indexing on pkg.go.dev
GOPROXY=proxy.golang.org go list -m github.com/securezeron/zeron-agent-development-kit/adk/go@v0.1.4
```

Or use the Makefile:

```bash
make release                  # Uses VERSION from Makefile
make release VERSION=0.2.0    # Override version
```

## Links

- [pkg.go.dev](https://pkg.go.dev/github.com/securezeron/zeron-agent-development-kit/adk/go)
- [Documentation](https://securezeron.github.io/zeron-agent-development-kit)
- [Python SDK (PyPI)](https://pypi.org/project/zin-adk/)
- [Node.js SDK (npm)](https://www.npmjs.com/package/zin-adk)
- [GitHub](https://github.com/securezeron/zeron-agent-development-kit)
- [Changelog](https://github.com/securezeron/zeron-agent-development-kit/blob/main/CHANGELOG.md)

## License

Apache-2.0 — see [LICENSE](../../LICENSE)
