# Core Concepts

Understanding these core concepts unlocks everything in ZAK.

---

## 1. The Agent DSL (US-ADSL)

Every agent in ZAK is **defined by a YAML file** before any code is written. This isn't configuration — it's a **contract** that the platform enforces at runtime.

```yaml
agent:
  id: my-agent         # unique slug
  domain: risk_quant   # which security domain
  version: "1.0.0"

intent:
  goal: "What this agent is trying to achieve"
  priority: high

reasoning:
  mode: deterministic          # how the agent thinks (see Reasoning Modes below)
  autonomy_level: bounded      # how much it can do unsupervised
  confidence_threshold: 0.75

capabilities:
  tools: [read_asset, compute_risk]   # what it can call

boundaries:
  allowed_actions: [read_asset, compute_risk]
  denied_actions: [delete_asset]
  environment_scope: [production, staging]

safety:
  sandbox_profile: standard
  audit_level: standard
```

The YAML is validated against a strict Pydantic schema before any execution starts. **Invalid definitions are rejected at the gate — not at runtime.**

---

## 2. The Five Agent Primitives

Every agent is defined by exactly five things:

| Primitive | What it answers |
|---|---|
| **Identity** | Who is this agent and what domain does it operate in? |
| **Intent** | What is it trying to achieve? What does success look like? |
| **Capabilities** | What tools and data can it access? |
| **Boundaries** | What is it explicitly allowed and denied to do? |
| **Reasoning** | How does it make decisions? How autonomous is it? |

---

## 3. Reasoning Modes

Agents support two primary reasoning modes:

| Mode | How it works |
|---|---|
| `deterministic` | Python code in `execute()` runs tools in a fixed sequence. No LLM involved. Fast, predictable, auditable. |
| `llm_react` | An LLM drives a ReAct loop — it reads tool results, decides what to call next, and iterates until confident. Requires an LLM provider configured in Platform Settings. |

**Deterministic** is the default and recommended starting point. Switch to `llm_react` when the task requires dynamic reasoning (e.g., red teaming, adaptive triage).

```yaml
reasoning:
  mode: llm_react              # switches agent to LLM-powered ReAct loop
  autonomy_level: bounded
  confidence_threshold: 0.85
  llm:
    provider: openai           # optional — overrides platform default
    model: gpt-4o
    temperature: 0.2
    max_iterations: 10         # safety cap on ReAct loop iterations
    max_tokens: 4096
```

> **Safety guarantee:** Even in `llm_react` mode, every tool call still passes through the Policy Engine. The LLM gets intelligence; the framework keeps control.

---

## 4. Bounded Autonomy

Agents are not free-running. Every agent operates within a **risk budget** and **autonomy level**:

| Autonomy Level | What the agent can do |
|---|---|
| `observe` | Read-only. Cannot call any mutating tools. |
| `suggest` | Can compute and return recommendations, no writes. |
| `bounded` | Can act, but within explicit allow/deny lists. |
| `high` | Broad action allowed within the environment scope. |
| `fully_autonomous` | Full autonomy — requires `confidence_threshold ≥ 0.9`. |

> **Red team agents** are forced into `sandbox_profile: offensive_isolated` and `audit_level: verbose` by the schema validator. You cannot bypass this.

---

## 5. The Policy Engine

Before every tool call, ZAK evaluates **6 rules in order** (first deny wins):

```
1. Is the action in the explicit deny-list?         → block
2. Is the action NOT in the allow-list?             → block (if allow-list non-empty)
3. Is the agent observe-only trying to mutate?      → block
4. Is the action high-risk but budget is low?       → block
5. Is the target environment out of scope?          → block
6. Is the agent a red-team targeting production?    → block
                                                    → permit
```

This runs **inside `ToolExecutor.call()`** — you never call the policy engine directly.

---

## 6. Multi-Agent Orchestration

A parent agent can **spawn child agents** to delegate sub-tasks. The built-in `spawn_agent` tool handles this:

```yaml
capabilities:
  tools: [list_assets, compute_risk, spawn_agent]
```

```python
# Inside an LLM-powered agent's ReAct loop, the LLM can call:
spawn_agent(domain="vuln_triage", environment="staging")
```

**Safety rules for spawned agents:**

- Child agents always run in `deterministic` mode — no recursive LLM spawning.
- Child agents inherit the parent's `tenant_id` and `trace_id` for audit continuity.
- The `spawn_agent` tool is policy-checked like any other tool.

---

## 7. Streaming & Approval Gates

When agents run via the REST API, results are **streamed as Server-Sent Events (SSE)**:

```
event: thought     → LLM reasoning text (token-by-token in llm_react mode)
event: tool_call   → tool invocation (name + arguments)
event: tool_result → tool output
event: iteration   → iteration boundary marker
event: gate        → approval gate pause (human-in-the-loop)
event: result      → final agent output
event: error       → error details
```

**Approval gates** pause the ReAct loop when a tool call targets an action listed in `boundaries.approval_gates`. The UI displays the pending action and waits for human approval before the agent continues.

---

## 8. The Security Intelligence Fabric (SIF)

The SIF is the **shared, time-aware security knowledge graph** stored in **Memgraph** that all agents read from and write to.

**Agents are stateless — the SIF holds truth.**

```
 Asset ──────────────► Vulnerability
   │                        │
   │                  ControlNode (mitigates)
   │
 Identity ──────────► Asset (has_access_to)
   │
 Vendor ─────────────► Asset (supplies)
   │
 AIModel ────────────► DataStore (accesses)
   │
 RiskNode ───────────► Asset (impacts)
```

Every node is **time-aware**:
```python
{
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_to": None,          # None = currently active
  "confidence": 0.95,        # data quality score
  "source": "snyk"           # integration that produced it
}
```

This enables: drift detection, attack path replay, forensics, and risk trend analysis.

**Reasoning traces** are also written to Memgraph after each LLM agent run — including which tools were called, how many iterations the ReAct loop took, and the final output. This gives full observability into how the LLM arrived at its conclusions.

---

## How it all fits together

```
                   ┌──────────────────┐
                   │   YAML (DSL)     │  ← defines identity, boundaries, safety
                   └────────┬─────────┘
                            │ load_agent_yaml()
                   ┌────────▼─────────┐
                   │  AgentExecutor   │  ← enforces policy, emits audit
                   └────────┬─────────┘
                            │ calls
               ┌────────────┴────────────┐
               │                         │
  ┌────────────▼───────────┐  ┌──────────▼──────────┐
  │  BaseAgent (determin.) │  │  LLMAgent (ReAct)   │
  │  .execute()            │  │  LLM → tool → loop  │
  └────────────┬───────────┘  └──────────┬──────────┘
               │                         │
               └────────────┬────────────┘
                            │ ToolExecutor.call()
                   ┌────────▼─────────┐
                   │  @zak_tool fns   │  ← reads/writes SIF graph
                   └────────┬─────────┘
                            │
                   ┌────────▼─────────┐
                   │   SIF Graph      │  ← Memgraph, tenant-namespaced
                   │  (per tenant)    │
                   └──────────────────┘
```
