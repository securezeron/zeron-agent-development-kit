# Multi-tenancy

ZAK is multi-tenant from day one. Every piece of data, every agent execution, and every audit event is scoped to a tenant.

---

## How isolation works

ZAK uses **namespace isolation** — graph tables are prefixed with the tenant ID at the database level:

```
t_acme_asset         ← AssetNodes for tenant "acme"
t_acme_vulnerability ← VulnerabilityNodes for tenant "acme"
t_acme_risk          ← RiskNodes for tenant "acme"

t_globex_asset       ← AssetNodes for tenant "globex"
t_globex_risk        ← RiskNodes for tenant "globex"
```

This means:
- There is **no runtime filtering** where you could accidentally leak data by forgetting a `WHERE tenant_id = ?` clause
- Tenants are **structurally isolated** at the Memgraph label/namespace level
- Adding a new tenant creates a new namespace — it is zero-cost to the existing tenants

---

## Tenant registration

```python
from zak.tenants.context import TenantRegistry

registry = TenantRegistry()

# Register a new tenant
registry.register(tenant_id="acme", name="Acme Corp")

# Check if tenant exists
registry.exists("acme")   # True

# Get all registered tenants
registry.all()   # ["acme", "globex", ...]
```

In the CLI, tenants are auto-registered when you run `zak run --tenant <id>` if they don't already exist.

---

## TenantContext

`TenantContext` scopes operations to a specific tenant:

```python
from zak.tenants.context import TenantContext

ctx = TenantContext(tenant_id="acme", name="Acme Corp")

# Get the graph namespace prefix for this tenant
ctx.graph_namespace()   # → "t_acme"

# Use in graph adapter:
table_name = f"{ctx.graph_namespace()}_asset"   # → "t_acme_asset"
```

You rarely need to use `TenantContext` directly — it's consumed internally by `AgentContext` and the graph adapter.

---

## AgentContext carries tenant identity

Every agent execution is tenant-scoped via `AgentContext`:

```python
context = AgentContext(
    tenant_id="acme",       # ← everything in this run is scoped here
    trace_id=str(ULID()),
    dsl=dsl,
    environment="staging",
)
```

All tool calls and graph reads/writes automatically use `context.tenant_id` — you never pass the tenant explicitly inside `execute()`.

---

## Audit logs are always tenant-scoped

Every audit event includes `tenant_id`:

```json
{
  "event": "agent.started",
  "tenant_id": "acme",
  "agent_id": "my-risk-agent",
  "trace_id": "01HX2P...",
  "timestamp": "2026-03-03T12:14:00Z"
}
```

This makes it straightforward to route audit logs to per-tenant SIEM streams.

---

## Initialising the graph for a new tenant

Before a tenant's agents can read or write the SIF graph, their namespace must exist in Memgraph:

```python
from zak.sif.graph.adapter import KuzuAdapter

adapter = KuzuAdapter()  # connects to Memgraph via Bolt protocol
adapter.initialize_schema("acme")   # creates all t_acme_* labels
```

In production, call this during tenant onboarding. It is idempotent — safe to call multiple times.

---

## Current limitations

| Limitation | Status |
|---|---|
| Tenant registry is in-memory (SDK) | Platform API uses PostgreSQL for persistent tenant storage |
| No per-tenant rate limiting | Planned |
| No tenant-level policy overrides | Planned — tenants will be able to tighten global policies |

---

## Running agents for multiple tenants in parallel

```python
import asyncio
from zak.core.dsl.parser import load_agent_yaml
from zak.core.runtime.agent import AgentContext
from zak.core.runtime.executor import AgentExecutor
from zak.core.runtime.registry import AgentRegistry
from ulid import ULID

import my_agents.risk_agent   # trigger @register_agent

dsl = load_agent_yaml("agents/risk-agent.yaml")
agent_cls = AgentRegistry.get().resolve("risk_quant")

tenants = ["acme", "globex", "initech"]

results = {}
for tenant in tenants:
    context = AgentContext(tenant_id=tenant, trace_id=str(ULID()), dsl=dsl)
    results[tenant] = AgentExecutor().run(agent_cls(), context)

for tenant, result in results.items():
    print(f"{tenant}: {'✅' if result.success else '❌'}")
```
