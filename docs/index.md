# ZAK Documentation

**ZAK** is the **Zeron Agentic Kit — Cyber Risk Management ADK** — a Python SDK for building, deploying, and governing autonomous cybersecurity agents.

---

## Documentation

| Guide | Description |
|---|---|
| [Quickstart](01_quickstart.md) | Build and run your first agent in 5 minutes |
| [Core Concepts](02_concepts.md) | Understanding the ZAK mental model |
| [Building Agents](03_building_agents.md) | Step-by-step agent development guide |
| [DSL Reference](04_dsl_reference.md) | Complete YAML schema field reference |
| [Tool Substrate](05_tools.md) | Using and creating ZAK tools |
| [Security Intelligence Fabric](06_sif.md) | The shared graph — nodes, edges, and telemetry |
| [CLI Reference](07_cli.md) | All CLI commands and options |
| [Multi-tenancy](08_multitenancy.md) | How tenant isolation works |

---

## At a glance

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

## Platform Overview

```
┌─────────────────────────────────────────────────┐
│              Your Agent (BaseAgent)              │
│          define: execute() + @zak_tool           │
└─────────────────────┬───────────────────────────┘
                      │ calls ToolExecutor.call()
┌─────────────────────▼───────────────────────────┐
│             ZAK Platform Layer                   │
│  PolicyEngine  │  AuditLogger  │  AgentExecutor  │
└─────────────────────┬───────────────────────────┘
                      │ reads/writes
┌─────────────────────▼───────────────────────────┐
│      Security Intelligence Fabric (SIF)          │
│   Asset  │  Vulnerability  │  Risk  │  Vendor    │
│        (Memgraph, tenant-namespaced)              │
└─────────────────────────────────────────────────┘
```

The key principle: **you write `execute()`. The platform handles policy, audit, and graph persistence.**
