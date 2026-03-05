# Building Agents — Complete Guide

## 1. Anatomy of a ZAK agent

A complete agent consists of:

```
my_agents/
├── vuln-triage-agent.yaml     # contract (DSL definition)
└── vuln_triage_agent.py       # implementation (Python class)
```

The YAML and Python are deliberately separate. The YAML is the **what and the rules**. The Python is the **how**.

---

## 2. The BaseAgent contract

Every agent inherits from `BaseAgent` and must implement `execute()`:

```python
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.registry import register_agent

@register_agent(domain="risk_quant")
class MyAgent(BaseAgent):

    def pre_run(self, context: AgentContext) -> None:
        """Optional: setup, validate preconditions."""
        pass

    def execute(self, context: AgentContext) -> AgentResult:
        """Required: your agent logic."""
        # ... do work ...
        return AgentResult.ok(context, output={"key": "value"})

    def post_run(self, context: AgentContext, result: AgentResult) -> None:
        """Optional: cleanup, post-processing."""
        pass
```

### AgentContext

Everything your agent needs is injected via `AgentContext`:

```python
context.tenant_id      # str — which tenant this run belongs to
context.trace_id       # str — unique trace ID for this execution
context.dsl            # AgentDSL — the validated YAML definition
context.agent_id       # str — shortcut for context.dsl.agent.id
context.environment    # str — "production" | "staging" | "dev"
```

### AgentResult

Always return one of:

```python
# Success
return AgentResult.ok(context, output={"results": [...], "count": 5})

# Failure
return AgentResult.fail(context, errors=["Could not connect to graph", "..."])
```

---

## 3. Using tools inside execute()

**Never call SIF graph functions directly.** Always go through `ToolExecutor.call()` so policy is enforced and audit events are emitted:

```python
from zak.core.tools.substrate import ToolExecutor
import zak.core.tools.builtins as tools

def execute(self, context: AgentContext) -> AgentResult:
    # ✅ Correct — policy checked, audit emitted
    assets = ToolExecutor.call(tools.list_assets, context=context)

    # ❌ Wrong — bypasses policy and audit
    # adapter = KuzuAdapter()
    # assets = adapter.get_nodes(tenant_id=context.tenant_id, node_type="asset")
```

### Passing arguments to tools

```python
risk = ToolExecutor.call(
    tools.compute_risk,
    context=context,
    criticality="high",
    exposure="external",
    exploitability=0.8,
    control_effectiveness=0.3,
    privilege_level="admin",
)
# Returns: {"risk_score": 7.2, "risk_level": "high", "raw_score": 0.72}
```

---

## 4. Creating custom tools

If the built-in tools don't cover your use case, create domain-specific tools with `@zak_tool`:

```python
# my_agents/my_tools.py
from zak.core.runtime.agent import AgentContext
from zak.core.tools.substrate import zak_tool


@zak_tool(
    name="lookup_vendor_intel",
    description="Look up vendor cyber incidents from external threat intel",
    action_id="lookup_vendor_intel",   # must match capabilities.tools in YAML
    tags=["vendor", "threat_intel"],
)
def lookup_vendor_intel(context: AgentContext, vendor_name: str) -> dict:
    """Returns threat intel for a vendor."""
    # call your threat intel API here
    return {"incidents": [], "risk_score": 2.5}
```

Then declare it in your YAML:
```yaml
capabilities:
  tools:
    - lookup_vendor_intel    # ← your custom tool

boundaries:
  allowed_actions:
    - lookup_vendor_intel    # ← must also be in allowed_actions
```

And call it:
```python
intel = ToolExecutor.call(my_tools.lookup_vendor_intel, context=context, vendor_name="Acme Corp")
```

---

## 5. Agent patterns

### Pattern A: Read → Compute → Write

The most common pattern. Read data from the graph, compute something, write the result back.

```python
def execute(self, context: AgentContext) -> AgentResult:
    assets = ToolExecutor.call(tools.list_assets, context=context)
    results = []
    for asset in assets:
        score = ToolExecutor.call(
            tools.compute_risk, context=context,
            criticality=asset.get("criticality", "medium"),
        )
        # write_risk_node persists back to SIF
        ToolExecutor.call(tools.write_risk_node, context=context, risk_node=build_risk_node(score))
        results.append(score)
    return AgentResult.ok(context, output={"results": results})
```

### Pattern B: Filter → Flag

Read data, apply rules, return a list of findings (read-only agent).

```python
reasoning:
  autonomy_level: observe    # read-only, no writes

def execute(self, context: AgentContext) -> AgentResult:
    vulns = ToolExecutor.call(tools.list_vulnerabilities, context=context)
    critical = [v for v in vulns if v.get("severity") == "critical"]
    return AgentResult.ok(context, output={"critical_count": len(critical), "items": critical})
```

### Pattern C: Multi-step with approval gate

For actions that need human approval before proceeding.

```yaml
boundaries:
  approval_gates:
    - flag_critical_vendor
```

```python
from zak.core.runtime.executor import AgentExecutor

def execute(self, context: AgentContext) -> AgentResult:
    executor = AgentExecutor()
    vendors = ToolExecutor.call(tools.list_vendors, context=context)

    for vendor in vendors:
        if float(vendor.get("risk_score", 0)) > 8.0:
            # Check if this action needs human approval
            if executor.check_action(context, "flag_critical_vendor").allowed:
                # Proceed (approval already granted externally)
                pass
            else:
                # Pause and request approval (emit governance event)
                return AgentResult.fail(context, errors=[
                    f"Approval required to flag vendor {vendor['node_id']} as critical"
                ])

    return AgentResult.ok(context, output={"vendors_processed": len(vendors)})
```

---

## 6. Registering agents

The `@register_agent` decorator makes your agent discoverable by the registry and CLI:

```python
@register_agent(
    domain="appsec",
    description="Runs SAST scans and writes findings to SIF",
    version="2.0.0",
    override=False,   # True = this becomes the new primary for the domain
)
class MySastAgent(BaseAgent):
    ...
```

Multiple agents can be registered for the same domain. The first registered is the primary (used by `zak run`). Use `override=True` to replace it.

To register an agent, its module must be imported before `AgentRegistry.get().resolve()` is called. In the CLI, this happens automatically. In your own code, import the module explicitly:

```python
import my_agents.vuln_triage_agent   # triggers @register_agent

agent_cls = AgentRegistry.get().resolve("appsec")
```

---

## 7. Agents with constructor dependencies

If your agent needs dependencies (like a graph adapter), accept them in `__init__`:

```python
from zak.sif.graph.adapter import KuzuAdapter

class MyAgent(BaseAgent):
    def __init__(self, adapter: KuzuAdapter, config: dict) -> None:
        self._adapter = adapter
        self._config = config
```

The CLI's registry-based dispatch auto-injects `adapter` if the constructor accepts it. For programmatic use, construct the agent manually:

```python
from zak.sif.graph.adapter import KuzuAdapter

adapter = KuzuAdapter()  # connects to Memgraph via Bolt protocol
adapter.initialize_schema("acme")
agent = AgentRegistry.get().resolve("risk_quant")(adapter)
result = AgentExecutor().run(agent, context)
```

---

## 8. LLM-Powered Agents (ReAct Mode)

Instead of writing fixed logic in `execute()`, you can let an LLM drive the agent via a ReAct loop. The LLM reads tool results, decides what to call next, and iterates until it has a confident answer.

### Switching an agent to LLM mode

Set `reasoning.mode: llm_react` in the DSL:

```yaml
reasoning:
  mode: llm_react
  autonomy_level: bounded
  confidence_threshold: 0.85
  llm:
    provider: openai         # optional — overrides platform default
    model: gpt-4o
    temperature: 0.2
    max_iterations: 10       # safety cap
    max_tokens: 4096
```

### The LLMAgent base class

LLM agents extend `LLMAgent` instead of `BaseAgent`:

```python
from zak.core.runtime.agent import AgentContext, AgentResult
from zak.core.runtime.llm_agent import LLMAgent

class _LLMRiskQuantAgent(LLMAgent):
    system_prompt = """
    You are a risk quantification analyst. Use the available tools to:
    1. List all assets for the tenant
    2. Compute risk scores for each asset
    3. Return a structured summary
    """

    @property
    def tools(self) -> list:
        from zak.core.tools.builtins import list_assets, compute_risk
        return [list_assets, compute_risk]
```

You don't need to implement `execute()` — the ReAct loop handles it. Just define:
- **`system_prompt`**: Instructions for the LLM on what to accomplish.
- **`tools`**: The list of `@zak_tool` functions the LLM can call.

### How the ReAct loop works

```
1. System prompt + user goal → LLM
2. LLM returns a tool call (or final answer)
3. ToolExecutor.call() runs the tool (policy-checked)
4. Tool result → appended to conversation → back to step 2
5. Repeat until LLM returns a final answer or max_iterations hit
```

Every iteration is streamed as SSE events (`thought`, `tool_call`, `tool_result`, `iteration`).

---

## 9. Multi-Agent Orchestration

Parent agents can delegate sub-tasks to child agents using the built-in `spawn_agent` tool.

### Adding spawn_agent to an agent

```yaml
capabilities:
  tools: [list_assets, compute_risk, spawn_agent]
boundaries:
  allowed_actions: [list_assets, compute_risk, spawn_agent, agent_execute]
```

```python
@property
def tools(self) -> list:
    from zak.core.tools.builtins import list_assets, compute_risk
    from zak.core.tools.orchestration import spawn_agent
    return [list_assets, compute_risk, spawn_agent]
```

In `llm_react` mode, the LLM can decide when to spawn a child:

```
LLM: "I need vulnerability data. Let me delegate to vuln_triage."
→ spawn_agent(domain="vuln_triage", environment="production")
→ Child runs in deterministic mode, returns results
→ LLM incorporates child output into its reasoning
```

### Safety guarantees

- **No recursive LLM spawning**: Child agents always run in `deterministic` mode regardless of their YAML.
- **Audit continuity**: Child agents inherit `tenant_id` and `trace_id` from the parent.
- **Policy enforcement**: `spawn_agent` is policy-checked — it must be in `capabilities.tools` and `allowed_actions`.

---

## 10. Approval Gates (Human-in-the-Loop)

For high-impact actions, you can require human approval before the agent proceeds.

### Configuring approval gates

```yaml
boundaries:
  approval_gates:
    - flag_critical_vendor
    - delete_asset
```

When the LLM (or deterministic agent) tries to call a tool whose `action_id` is in `approval_gates`, the run **pauses** and emits an SSE `gate` event:

```json
{"event": "gate", "data": {"gate_id": "g-abc123", "action": "flag_critical_vendor", "arguments": {...}}}
```

The UI displays the pending action with Approve/Deny buttons. The run resumes only after approval via:

```
POST /runs/{run_id}/gates/{gate_id}/approve
```

This keeps humans in the loop for critical decisions while letting the agent handle routine work autonomously.

---

## 11. AI-Powered Agent Generation

Instead of writing YAML manually, you can describe what an agent should do in plain English and let the LLM generate a complete DSL definition.

### Via the Platform UI

1. Navigate to **Agent Studio → Create Agent**
2. Click the **AI Generate** toggle
3. Describe your agent in the prompt textarea (e.g. *"Scan cloud infrastructure for SOC2 compliance misconfigurations, read all assets and controls, compute risk scores, and produce a prioritized remediation list"*)
4. Click **Generate Agent** — the LLM creates a valid US-ADSL YAML definition
5. Review and edit the generated YAML in the Monaco editor (Step 2)
6. Click **Create Agent** to register it

> **Prerequisite:** Configure your LLM provider (OpenAI, Anthropic, or local) in **Settings** before using AI generation.

### Via the REST API

```bash
curl -X POST http://localhost:8000/agents/generate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Scan cloud infrastructure for SOC2 compliance issues"}'
```

**Response:**
```json
{
  "yaml_config": "agent:\n  id: cloud-soc2-scanner\n  ...",
  "domain": "compliance",
  "name": "Cloud SOC2 Scanner",
  "description": "Scan cloud infrastructure for SOC2 compliance issues",
  "valid": true,
  "validation_errors": []
}
```

The response includes `valid` and `validation_errors` fields — if the generated YAML has schema issues, you can fix them before creating the agent.

### How it works

The generation service (`zak/platform/agent_gen_service.py`):

1. Sends the user's prompt to the configured LLM with a system prompt containing the full DSL schema specification, all valid domains, available tools, and validation rules
2. Strips any markdown code fences from the LLM response
3. Parses the YAML and extracts `domain`, `name`, and `description`
4. Validates against `AgentDSL.model_validate()` (the same Pydantic schema used for all agents)
5. Returns the generated YAML along with validation status
