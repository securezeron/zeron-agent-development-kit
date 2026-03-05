# Quickstart — Build your first agent in 5 minutes

## Prerequisites

- Python 3.11+
- ZAK installed in a virtual environment

```bash
git clone <your-repo>
cd zak
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Step 1 — Scaffold an agent

Use `zak init` to generate a YAML definition and Python class for your chosen domain:

```bash
zak init --name "Vuln Triage Agent" --domain appsec --out ./my_agents
```

Output:
```
✅ Agent scaffolded!
YAML:   my_agents/vuln-triage-agent.yaml
Class:  my_agents/vuln_triage_agent.py
```

Core domains include: `risk_quant`, `supply_chain`, `red_team`, `appsec`, `ai_security`, `compliance`, `vuln_triage`, `threat_intel`, `identity_risk`, and more (22 total — see [DSL Reference](04_dsl_reference.md)).

---

## Step 2 — Implement execute()

Open `my_agents/vuln_triage_agent.py` and fill in the `execute()` method:

```python
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.registry import register_agent
from zak.core.tools.substrate import ToolExecutor
import zak.core.tools.builtins as tools


@register_agent(domain="appsec", description="Triage open vulnerabilities by severity")
class VulnTriageAgent(BaseAgent):
    def execute(self, context: AgentContext) -> AgentResult:
        # Policy check + audit emit happen automatically inside ToolExecutor.call()
        vulns = ToolExecutor.call(tools.list_vulnerabilities, context=context)

        findings = [
            v for v in vulns
            if v.get("severity") in ("high", "critical")
            and v.get("status") == "open"
        ]

        return AgentResult.ok(context, output={
            "total_scanned": len(vulns),
            "high_critical_open": len(findings),
            "findings": findings,
        })
```

> **That's it.** No policy code, no audit code, no tenant code — the platform handles all of that.

---

## Step 3 — Push data into the graph

Before running the agent, push security data into the SIF graph. ZAK uses **Memgraph** (a graph database accessible via the Bolt protocol) for the Security Intelligence Fabric.

**Option A — Via the Platform UI:**

Navigate to **Agent Studio → Seed Demo Data** to populate the graph with sample assets, vulnerabilities, controls, identities, and vendors.

**Option B — Programmatically via the telemetry ingestor:**

```python
from zak.sif.graph.adapter import KuzuAdapter
from zak.sif.telemetry.ingestor import TelemetryIngestor

adapter = KuzuAdapter()  # connects to Memgraph via Bolt protocol
adapter.initialize_schema("acme")           # create namespace for tenant "acme"

ingestor = TelemetryIngestor(adapter)

ingestor.ingest({
    "event_type": "vulnerability_found",
    "vuln_id": "CVE-2024-1234",
    "vuln_type": "cve",
    "severity": "critical",
    "exploitability": 0.9,
    "cvss_score": 9.8,
    "status": "open",
    "source": "snyk",
}, tenant_id="acme")
```

Supported event types: `vulnerability_found`, `asset_discovered`, `control_updated`, `vendor_assessed`.

> **Memgraph requirement:** Ensure Memgraph is running (`docker compose up -d`) and accessible at `bolt://localhost:7687`. You can browse the graph visually at [Memgraph Lab](http://localhost:3001).

---

## Step 4 — Validate the YAML

```bash
zak validate my_agents/vuln-triage-agent.yaml
# ✅ Valid agent definition: vuln-triage-agent
```

---

## Step 5 — Run it

```bash
zak run my_agents/vuln-triage-agent.yaml --tenant acme --env staging
```

You'll see structured JSON audit logs emitted to stdout and a success/failure summary.

---

## Step 6 (optional) — Run programmatically

```python
from zak.core.dsl.parser import load_agent_yaml
from zak.core.runtime.agent import AgentContext
from zak.core.runtime.executor import AgentExecutor
from zak.core.runtime.registry import AgentRegistry
from ulid import ULID

import my_agents.vuln_triage_agent  # triggers @register_agent

dsl = load_agent_yaml("my_agents/vuln-triage-agent.yaml")
context = AgentContext(tenant_id="acme", trace_id=str(ULID()), dsl=dsl)

agent_cls = AgentRegistry.get().resolve("appsec")
result = AgentExecutor().run(agent_cls(), context)

print(result.success)   # True
print(result.output)    # {"total_scanned": 12, "high_critical_open": 3, ...}
```

---

## What you built

```
vuln-triage-agent.yaml    → defines WHO the agent is (identity, intent, capabilities, safety)
vuln_triage_agent.py      → defines WHAT the agent does (execute logic)
TelemetryIngestor         → feeds data INTO the SIF graph
ToolExecutor.call()       → reads data FROM the SIF graph (with policy + audit)
AgentResult               → structured output envelope
```
