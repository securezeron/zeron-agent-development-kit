<p align="center">
  <img src="docs/assets/images/zak-adk-primary.png" alt="ZAK — Zeron Agent Development Kit" height="60" />
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License" /></a>
  <a href="https://pypi.org/project/zin-adk/"><img src="https://img.shields.io/pypi/v/zin-adk.svg" alt="PyPI" /></a>
  <a href="https://www.npmjs.com/package/zin-adk"><img src="https://img.shields.io/npm/v/zin-adk.svg" alt="npm" /></a>
  <a href="https://pkg.go.dev/github.com/securezeron/zeron-agent-development-kit/adk/go"><img src="https://pkg.go.dev/badge/github.com/securezeron/zeron-agent-development-kit/adk/go.svg" alt="Go Reference" /></a>
  <a href="https://pypi.org/project/zin-adk/"><img src="https://img.shields.io/pypi/pyversions/zin-adk.svg" alt="Python" /></a>
</p>

**ZAK** is an open-source **Agent Development Kit** for building, deploying, and governing autonomous cybersecurity agents.

---

## Quick Start

<table>
<tr><th>Python</th><th>Node.js</th><th>Go</th></tr>
<tr>
<td>

```bash
pip install zin-adk
```

</td>
<td>

```bash
npm install zin-adk
```

</td>
<td>

```bash
go get github.com/securezeron/zeron-agent-development-kit/adk/go@latest
```

</td>
</tr>
</table>

```bash
# Scaffold a new agent
zak init --name "My Risk Agent" --domain risk_quant --out ./agents

# Validate
zak validate agents/my-risk-agent.yaml

# Run
zak run agents/my-risk-agent.yaml --tenant acme
```

---

## Built-in Agents

| Domain | Description |
|--------|-------------|
| `risk_quant` | FAIR-inspired risk scoring for all assets |
| `vuln_triage` | Prioritize CVEs by severity, criticality, and exploitability |
| `appsec` | SAST, SCA, secrets detection, and dependency scanning |
| `generic` | DSL-only custom agent executor |

---

## Key Features

- **US-ADSL** — Declarative YAML schema for agent definitions
- **Policy Engine** — 6 runtime guardrails enforced on every tool call
- **Tool Substrate** — `@zak_tool` decorator for safe, audited tool execution
- **SIF Graph** — Security Intelligence Fabric for shared knowledge persistence
- **Multi-tenant** — Namespace isolation per tenant
- **LLM Modes** — ReAct reasoning with OpenAI, Anthropic, Google, or local Ollama

---

## Installation

### Python (PyPI)

```bash
pip install zin-adk                  # Core + CLI
pip install "zin-adk[llm]"           # + LLM providers (OpenAI, Anthropic, Google)
pip install "zin-adk[graph]"         # + Memgraph/Neo4j graph backend
pip install "zin-adk[dev]"           # + Dev tools (pytest, ruff, mypy)
```

### Node.js (npm)

```bash
npm install zin-adk                  # Core + CLI
npm install zin-adk openai           # + OpenAI / Azure OpenAI
npm install zin-adk neo4j-driver     # + Graph backend
```

### Go

```bash
go get github.com/securezeron/zeron-agent-development-kit/adk/go@latest
go install github.com/securezeron/zeron-agent-development-kit/adk/go/cmd/zak@latest  # CLI only
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `zak init` | Scaffold a new agent (YAML + Python) |
| `zak validate` | Validate a YAML agent definition |
| `zak run` | Execute an agent in a tenant context |
| `zak agents` | List registered agents |
| `zak info` | Show platform info |

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Your Agent (BaseAgent)              │
│          define: execute() + @zak_tool           │
└─────────────────────┬───────────────────────────┘
                      │ calls ToolExecutor.call()
┌─────────────────────▼───────────────────────────┐
│               ZAK Core Layer                    │
│  PolicyEngine  │  AuditLogger  │  AgentExecutor │
└─────────────────────┬───────────────────────────┘
                      │ reads/writes
┌─────────────────────▼───────────────────────────┐
│      Security Intelligence Fabric (SIF)         │
│   Asset  │  Vulnerability  │  Risk  │  Vendor   │
└─────────────────────────────────────────────────┘
```

---

## Multi-Language ADKs

ZAK is available in three languages with full feature parity:

| ADK | Package | Install |
|-----|---------|---------|
| **Python** | [`zin-adk`](https://pypi.org/project/zin-adk/) | `pip install zin-adk` |
| **Node.js** | [`zin-adk`](https://www.npmjs.com/package/zin-adk) | `npm install zin-adk` |
| **Go** | [`adk/go`](adk/go/) | `go get github.com/.../adk/go@latest` |

Each ADK includes: US-ADSL parser, policy engine, tool substrate, agent executor, LLM ReAct loop, SIF graph, audit logger, multi-tenant support, and the `zak` CLI.

---

## Enterprise Edition

Need more? The **ZAK Enterprise Edition** adds 19 additional agents:

AI Security, API Security, Attack Surface, Cloud Posture, Compliance,
Container Security, Cyber Insurance, Data Privacy, IaC Security, IAM Drift,
Identity Risk, Incident Response, Malware Analysis, Network Security,
Pentest Automation, Red Team, Supply Chain, Threat Detection, Threat Intel

Plus: REST API server, platform dashboard, user management, and integrations.

**Learn more at [zeron.one](https://zeron.one)**

---

## Documentation

Full docs: [securezeron.github.io/zeron-agent-development-kit](https://securezeron.github.io/zeron-agent-development-kit)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
