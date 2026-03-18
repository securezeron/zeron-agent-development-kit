<p align="center">
  <img src="assets/images/zak-adk-primary.png" alt="ZAK — Zeron Agent Development Kit" height="60" />
</p>

# ZAK Documentation

**ZAK** is the **Zeron Agent Development Kit** — an open-source ADK for building, deploying, and governing autonomous cybersecurity agents.

Available for **Python**, **Node.js/TypeScript**, and **Go**.

---

## Install

=== "Python"

    ```bash
    pip install zin-adk
    ```

=== "Node.js"

    ```bash
    npm install zin-adk
    ```

=== "Go"

    ```bash
    go get github.com/securezeron/zeron-agent-development-kit/adk/go@latest
    ```

---

## At a glance

```bash
# Scaffold a new agent
zak init --name "My Risk Agent" --domain risk_quant --out ./agents

# Validate
zak validate agents/my-risk-agent.yaml

# Run
zak run agents/my-risk-agent.yaml --tenant acme
```

---

## Documentation

| Guide | Description |
|---|---|
| [Quickstart (Python)](01_quickstart.md) | Build and run your first agent in 5 minutes |
| [Quickstart (Node.js / Go)](09_node_go_quickstart.md) | Get started with the Node.js or Go ADK |
| [Core Concepts](02_concepts.md) | Understanding the ZAK mental model |
| [Building Agents](03_building_agents.md) | Step-by-step agent development guide |
| [DSL Reference](04_dsl_reference.md) | Complete YAML schema field reference |
| [Tool Substrate](05_tools.md) | Using and creating ZAK tools |
| [Security Intelligence Fabric](06_sif.md) | The shared graph — nodes, edges, and telemetry |
| [CLI Reference](07_cli.md) | All CLI commands and options |
| [Multi-tenancy](08_multitenancy.md) | How tenant isolation works |

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
