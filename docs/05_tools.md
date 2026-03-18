# Tool Substrate Reference

Tools are the primary way agents interact with the Security Intelligence Fabric (SIF) and external systems. They are policy-aware by design.

---

## Using tools

Always call tools through `ToolExecutor.call()`:

```python
from zak.core.tools.substrate import ToolExecutor
import zak.core.tools.builtins as tools

result = ToolExecutor.call(tools.list_assets, context=context)
```

`ToolExecutor.call()` enforces three things before executing:
1. **Capability check** — the tool's `action_id` must be in `capabilities.tools`
2. **Policy check** — the `action_id` must pass the PolicyEngine (not in deny-list, in allow-list, etc.)
3. **Audit emission** — a `tool_called` event is emitted before execution and a `tool_result` event after

If the action is denied at step 1 or 2, a `PermissionError` is raised and an audit event is logged.

---

## Built-in platform tools

These tools are available to all agents without any additional setup.

### SIF Read Tools

| Tool function | `action_id` | Arguments | Returns |
|---|---|---|---|
| `tools.read_asset` | `read_asset` | `asset_id: str` | `dict \| None` |
| `tools.list_assets` | `list_assets` | _(none)_ | `list[dict]` |
| `tools.list_vulnerabilities` | `list_vulnerabilities` | _(none)_ | `list[dict]` |
| `tools.list_vendors` | `list_vendors` | _(none)_ | `list[dict]` |
| `tools.list_controls` | `list_controls` | _(none)_ | `list[dict]` |
| `tools.list_identities` | `list_identities` | _(none)_ | `list[dict]` |
| `tools.list_risks` | `list_risks` | _(none)_ | `list[dict]` |
| `tools.list_ai_models` | `list_ai_models` | _(none)_ | `list[dict]` |

All read tools are automatically scoped to the current tenant — you never pass `tenant_id` explicitly.

### Risk Tools

| Tool function | `action_id` | Arguments | Returns |
|---|---|---|---|
| `tools.compute_risk` | `compute_risk` | `criticality, exposure, exploitability, control_effectiveness, privilege_level` | `dict` |

`compute_risk` returns:
```python
{
    "risk_score": 7.2,      # 0.0–10.0 scaled score
    "risk_level": "high",   # "low" | "medium" | "high" | "critical"
    "raw_score": 0.72,      # unscaled input to formula
}
```

Criticality values: `"low"`, `"medium"`, `"high"`, `"critical"`
Exposure values: `"internet_facing"`, `"external"`, `"internal"`, `"air_gapped"`
Privilege level values: `"none"`, `"low"`, `"medium"`, `"admin"`

### SIF Write Tools

| Tool function | `action_id` | Arguments | Returns |
|---|---|---|---|
| `tools.write_risk_node` | `write_risk_node` | `risk_node: RiskNode` | `None` |

### Orchestration Tools

| Tool function | `action_id` | Arguments | Returns |
|---|---|---|---|
| `orchestration.spawn_agent` | `spawn_agent` | `domain: str, environment: str` | `dict` (child agent result) |

The `spawn_agent` tool allows parent agents (especially LLM-powered ones) to delegate sub-tasks to child agents. See [Multi-Agent Orchestration](03_building_agents.md#9-multi-agent-orchestration) for details.

---

## Creating custom tools

=== "Python"

    Use `@zak_tool` to create your own tools:

    ```python
    from zak.core.runtime.agent import AgentContext
    from zak.core.tools.substrate import zak_tool

    @zak_tool(
        name="lookup_threat_intel",
        description="Fetch threat intelligence for a domain or IP",
        action_id="lookup_threat_intel",
        tags=["threat_intel", "read"],
    )
    def lookup_threat_intel(context: AgentContext, target: str) -> dict:
        """Query your threat intel provider."""
        response = your_intel_provider.query(target)
        return {"threat_score": response.score, "incidents": response.incidents}
    ```

=== "Node.js"

    Use `zakTool()` to create your own tools:

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

=== "Go"

    Use `NewZakTool()` to create your own tools:

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

**Rules for custom tools:**
- The function must be importable before `ToolExecutor.call()` is used
- `action_id` must match exactly what's in `capabilities.tools` and `allowed_actions` in the YAML
- If your function accepts a `context` parameter, it is automatically injected by `ToolExecutor`
- Use descriptive `tags` — they appear in `zak tools` listings

---

## Declaring tools in YAML

```yaml
capabilities:
  tools:
    - list_assets           # built-in
    - compute_risk          # built-in
    - lookup_threat_intel   # custom

boundaries:
  allowed_actions:
    - list_assets
    - compute_risk
    - lookup_threat_intel   # must also appear here
```

> **Important:** A tool listed in `capabilities.tools` but not `allowed_actions` will be blocked by the policy engine (not the capability check). Be consistent.

---

## ToolRegistry — discovery

To enumerate all registered tools programmatically:

```python
from zak.core.tools.substrate import ToolRegistry

reg = ToolRegistry.get()
print(reg.summary())

for tool_meta in reg.all_tools():
    print(tool_meta.action_id, tool_meta.description)
```

---

## Error handling

```python
try:
    result = ToolExecutor.call(tools.list_assets, context=context)
except PermissionError as e:
    # Policy denied or not in capabilities.tools
    print(f"Tool blocked: {e}")
except ValueError as e:
    # Function is not a @zak_tool
    print(f"Not a tool: {e}")
```

`AgentExecutor` catches `PermissionError` automatically if the tool is called inside `execute()` and records it as a policy block audit event.
