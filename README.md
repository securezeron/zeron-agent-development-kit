# ZAK — Zeron Agentic Kit

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/zin-adk.svg)](https://pypi.org/project/zin-adk/)
[![Python](https://img.shields.io/pypi/pyversions/zin-adk.svg)](https://pypi.org/project/zin-adk/)

**ZAK** is an open-source **Agent Development Kit** for building, deploying, and governing autonomous cybersecurity agents.

---

## Quick Start

```bash
pip install zin-adk

# Scaffold a new agent
zak init --name "My Risk Agent" --domain risk_quant --out ./agents

# Implement agents/my_risk_agent.py → execute()

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

## Installation Options

```bash
pip install zin-adk                  # Core + CLI
pip install "zin-adk[llm]"           # + LLM providers (OpenAI, Anthropic, Google)
pip install "zin-adk[graph]"         # + Memgraph/Neo4j graph backend
pip install "zin-adk[dev]"           # + Dev tools (pytest, ruff, mypy)
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

Full docs: [securezeron.github.io/zak](https://securezeron.github.io/zak)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
