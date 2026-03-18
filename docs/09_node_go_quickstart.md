# Quickstart — Node.js & Go ADK

ZAK is available as a native ADK for **Node.js/TypeScript** and **Go**, with full feature parity with the Python ADK.

All three ADKs share the same:

- **US-ADSL YAML schema** — identical agent definitions across languages
- **Policy engine** — same 6-rule evaluation chain
- **CLI** — same `zak init`, `validate`, `run`, `agents`, `info` commands
- **SIF graph** — same 7 node types and 7 edge types
- **Audit logging** — structured JSON output

---

## Node.js / TypeScript

### Install

```bash
npm install zin-adk
```

With optional LLM providers:

```bash
npm install zin-adk openai              # OpenAI / Azure OpenAI
npm install zin-adk @anthropic-ai/sdk   # Anthropic Claude
```

### Use in code

```typescript
import {
  loadAgentYaml,
  PolicyEngine,
  AuditLogger,
  zakTool,
  AgentExecutor,
} from "zin-adk";

// Parse and validate an agent definition
const agent = await loadAgentYaml("my-scanner.agent.yaml");

// Policy engine enforces guardrails at runtime
const policy = new PolicyEngine();
const decision = policy.evaluate(agent, "scan_code", "staging");

if (decision.allowed) {
  console.log("Action allowed");
}
```

### Create a custom tool

```typescript
import { zakTool } from "zin-adk";

const lookupThreatIntel = zakTool({
  name: "lookup_threat_intel",
  description: "Fetch threat intelligence for a domain or IP",
  parameters: { target: { type: "string" } },
  execute: async (params, context) => {
    const response = await yourIntelProvider.query(params.target);
    return { threatScore: response.score, incidents: response.incidents };
  },
});
```

### CLI

```bash
npx zak init --domain appsec --name my-scanner
npx zak validate my-scanner.agent.yaml
npx zak run my-scanner.agent.yaml --tenant acme
npx zak agents
npx zak info
```

### Requirements

- Node.js >= 20.0.0
- TypeScript >= 5.5 (for development)

### Links

- [npm package](https://www.npmjs.com/package/zin-adk)
- [Node.js ADK README](https://github.com/securezeron/zeron-agent-development-kit/tree/main/adk/node)

---

## Go

### Install

```bash
go get github.com/securezeron/zeron-agent-development-kit/adk/go@latest
```

CLI only:

```bash
go install github.com/securezeron/zeron-agent-development-kit/adk/go/cmd/zak@latest
```

### Use in code

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
    decision := engine.Evaluate(result.Agent, "scan_code", "staging", nil)

    if decision.Allowed {
        fmt.Println("Action allowed")
    }
}
```

### Create a custom tool

```go
import "github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/tools"

scanTool := tools.NewZakTool(tools.ZakToolConfig{
    Name:        "lookup_threat_intel",
    Description: "Fetch threat intelligence for a domain or IP",
    Execute: func(ctx context.Context, params map[string]any) (any, error) {
        target := params["target"].(string)
        resp, err := yourIntelProvider.Query(target)
        if err != nil {
            return nil, err
        }
        return map[string]any{
            "threat_score": resp.Score,
            "incidents":    resp.Incidents,
        }, nil
    },
})
```

### Go packages

| Package | Description |
|---------|-------------|
| `pkg/dsl` | US-ADSL schema, parser, and validation |
| `pkg/policy` | Policy engine — 6-rule evaluation chain |
| `pkg/audit` | Structured audit event logging (zerolog) |
| `pkg/edition` | Edition detection (open-source vs enterprise) |
| `pkg/runtime` | BaseAgent, AgentRegistry, AgentExecutor, LLMAgent |
| `pkg/tools` | Tool substrate — `NewZakTool()` with policy + audit |
| `pkg/llm` | LLM client interface, provider registry, MockLLMClient |
| `pkg/sif/schema` | SIF node types (7) and edge types (7) |
| `pkg/sif/risk` | Risk propagation engine |
| `pkg/tenants` | Multi-tenant context and namespace isolation |

### CLI

```bash
zak init --domain appsec --name my-scanner
zak validate my-scanner.agent.yaml
zak run my-scanner.agent.yaml --tenant acme
zak agents
zak info
```

### Requirements

- Go >= 1.22

### Links

- [pkg.go.dev](https://pkg.go.dev/github.com/securezeron/zeron-agent-development-kit/adk/go)
- [Go ADK README](https://github.com/securezeron/zeron-agent-development-kit/tree/main/adk/go)

---

## Feature Parity

All three ADKs implement the same feature set:

| Feature | Python | Node.js | Go |
|---------|--------|---------|-----|
| US-ADSL Schema (Zod / Pydantic / struct) | :material-check: | :material-check: | :material-check: |
| DSL Parser + Validation | :material-check: | :material-check: | :material-check: |
| Policy Engine (6-rule chain) | :material-check: | :material-check: | :material-check: |
| Audit Logger (structured JSON) | :material-check: | :material-check: | :material-check: |
| Tool Substrate | :material-check: | :material-check: | :material-check: |
| Agent Executor (lifecycle) | :material-check: | :material-check: | :material-check: |
| LLM ReAct Loop | :material-check: | :material-check: | :material-check: |
| SIF Graph (7 nodes, 7 edges) | :material-check: | :material-check: | :material-check: |
| Risk Propagation Engine | :material-check: | :material-check: | :material-check: |
| Multi-tenant Isolation | :material-check: | :material-check: | :material-check: |
| CLI (5 commands) | :material-check: | :material-check: | :material-check: |
