# zin-adk

[![npm version](https://img.shields.io/npm/v/zin-adk.svg)](https://www.npmjs.com/package/zin-adk)
[![License](https://img.shields.io/npm/l/zin-adk.svg)](https://github.com/securezeron/zeron-agent-development-kit/blob/main/LICENSE)
[![Node.js](https://img.shields.io/node/v/zin-adk.svg)](https://nodejs.org/)

**ZAK (Zeron Agentic Kit)** — Node.js/TypeScript SDK for building autonomous cybersecurity agents.

Define security agents declaratively with YAML, enforce policy guardrails at runtime, and connect to LLM providers for autonomous reasoning.

## Install

```bash
npm install zin-adk
```

With LLM provider support:

```bash
npm install zin-adk openai          # OpenAI / Azure OpenAI
npm install zin-adk @anthropic-ai/sdk  # Anthropic Claude
```

With SIF graph backend:

```bash
npm install zin-adk neo4j-driver
```

## Quick Start

### 1. Create an Agent Definition

```bash
npx zak init --domain appsec --name my-scanner
```

This generates `my-scanner.agent.yaml`:

```yaml
version: "1.0"
agent:
  name: my-scanner
  domain: appsec
  description: Application security scanning agent

capabilities:
  allowed_actions: [scan_code, read_file, write_report]

policy:
  max_actions_per_minute: 30
  require_approval_above: high

reasoning:
  mode: rule_based
```

### 2. Validate

```bash
npx zak validate my-scanner.agent.yaml
```

### 3. Use in Code

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
const result = policy.evaluate(agent, "scan_code", { target: "repo" });
// result.allowed === true

// Register tools with automatic policy + audit integration
const scanCode = zakTool({
  name: "scan_code",
  description: "Scan source code for vulnerabilities",
  parameters: { target: { type: "string" } },
  execute: async (params) => {
    // your scanning logic
    return { vulnerabilities: [] };
  },
});
```

## Features

| Feature | Description |
|---------|-------------|
| **US-ADSL Schema** | Declarative YAML agent definitions with Zod validation |
| **Policy Engine** | 6-rule chain: deny-list, allow-list, autonomy, risk budget, environment, red-team |
| **Audit Logger** | Structured JSON audit trail via pino |
| **Tool Substrate** | `zakTool()` higher-order function with policy + audit integration |
| **Agent Executor** | Full lifecycle management with pre/post hooks |
| **LLM ReAct Loop** | Reason + Act pattern with streaming support |
| **SIF Graph** | Security Intelligence Fabric with 7 node types, 7 edge types |
| **Risk Engine** | Quantitative risk propagation with configurable formula |
| **Multi-tenant** | Namespace isolation per tenant |
| **CLI** | `zak init`, `validate`, `run`, `agents`, `info` |

## CLI

```bash
npx zak init --domain <domain> --name <name>   # Scaffold agent YAML
npx zak validate <file.yaml>                    # Validate agent definition
npx zak run <file.yaml>                         # Execute agent
npx zak agents                                  # List registered agents
npx zak info                                    # Platform information
```

Available domains: `generic`, `risk_quant`, `vuln_triage`, `appsec`, `compliance`

## Requirements

- Node.js >= 20.0.0
- TypeScript >= 5.5 (for development)

## Links

- [Documentation](https://securezeron.github.io/zeron-agent-development-kit)
- [Python SDK (PyPI)](https://pypi.org/project/zin-adk/)
- [Go SDK](https://github.com/securezeron/zeron-agent-development-kit/tree/main/adk/go)
- [GitHub](https://github.com/securezeron/zeron-agent-development-kit)
- [Changelog](https://github.com/securezeron/zeron-agent-development-kit/blob/main/CHANGELOG.md)

## License

Apache-2.0 — see [LICENSE](https://github.com/securezeron/zeron-agent-development-kit/blob/main/LICENSE)
