# DSL Reference — US-ADSL YAML Field Reference

Every ZAK agent is defined by a YAML file conforming to the US-ADSL schema. This page documents every field.

---

## Top-level structure

```yaml
agent:     # required
intent:    # required
reasoning: # required
capabilities:
boundaries:
safety:
```

---

## `agent` block

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string (slug) | ✅ | Unique agent identifier. Must match `[a-z0-9-]+`. |
| `name` | string | ✅ | Human-readable name. |
| `domain` | enum | ✅ | Security domain (see below). |
| `version` | semver string | ✅ | Agent version (e.g. `"1.0.0"`). |

**Valid domains (22 total):**

| Domain | Description |
|---|---|
| `risk_quant` | Risk quantification and scoring |
| `supply_chain` | Third-party vendor risk |
| `red_team` | Offensive security and attack path discovery |
| `appsec` | Application and code security (SAST/DAST) |
| `ai_security` | AI/LLM model risk assessment |
| `compliance` | Control monitoring and evidence collection |
| `api_security` | API security testing and monitoring |
| `attack_surface` | Attack surface management |
| `cloud_posture` | Cloud security posture management (CSPM) |
| `container_security` | Container and Kubernetes security |
| `cyber_insurance` | Cyber insurance readiness and risk assessment |
| `data_privacy` | Data privacy and classification |
| `iac_security` | Infrastructure-as-code security scanning |
| `iam_drift` | IAM configuration drift detection |
| `identity_risk` | Identity and access risk analysis |
| `incident_response` | Automated incident response workflows |
| `malware_analysis` | Malware analysis and classification |
| `network_security` | Network security monitoring |
| `pentest_auto` | Automated penetration testing |
| `threat_detection` | Threat detection and alerting |
| `threat_intel` | Threat intelligence correlation |
| `vuln_triage` | Vulnerability triage and prioritization |

---

## `intent` block

| Field | Type | Required | Description |
|---|---|---|---|
| `goal` | string | ✅ | Plain-language description of what the agent aims to achieve. |
| `success_criteria` | list[string] | — | Measurable conditions that define a successful run. |
| `priority` | enum | — | `low` \| `medium` \| `high` \| `critical`. Default: `medium`. |

---

## `reasoning` block

| Field | Type | Required | Description |
|---|---|---|---|
| `mode` | enum | ✅ | How the agent makes decisions (see below). |
| `autonomy_level` | enum | ✅ | How much the agent can do without human approval (see below). |
| `confidence_threshold` | float (0.0–1.0) | — | Minimum confidence required before acting. Default: `0.75`. |

**Reasoning modes:**
| Mode | Description |
|---|---|
| `deterministic` | Fixed, algorithmic decision-making. |
| `rule_based` | Deterministic, rule-driven logic. |
| `probabilistic` | Bayesian or statistical reasoning. |
| `hybrid` | Combination of rule-based and probabilistic. |
| `llm_assisted` | LLM provides suggestions, human/code decides. |
| `llm_react` | LLM drives a ReAct loop — iterates tool calls until confident. Requires `llm` sub-block. |

### `reasoning.llm` sub-block (required for `llm_react` mode)

| Field | Type | Required | Description |
|---|---|---|---|
| `provider` | string | — | LLM provider (`openai`, `anthropic`, `local`). Overrides platform default. |
| `model` | string | — | Model name (e.g. `gpt-4o`, `claude-sonnet-4-20250514`). |
| `temperature` | float | — | Sampling temperature (0.0–2.0). Default: `0.2`. |
| `max_iterations` | int | — | Safety cap on ReAct loop iterations. Default: `10`. |
| `max_tokens` | int | — | Max tokens per LLM response. Default: `4096`. |

```yaml
reasoning:
  mode: llm_react
  autonomy_level: bounded
  confidence_threshold: 0.85
  llm:
    provider: openai
    model: gpt-4o
    temperature: 0.2
    max_iterations: 10
    max_tokens: 4096
```

**Autonomy levels:**
| Level | What it can do | Constraints |
|---|---|---|
| `observe` | Read-only | Cannot call any mutating tool. |
| `suggest` | Compute and return recommendations | No writes to graph. |
| `bounded` | Act within explicit allow/deny lists | Policy-enforced. |
| `high` | Broad action within environment scope | Environment check enforced. |
| `fully_autonomous` | Full autonomy | Requires `confidence_threshold ≥ 0.9`. |

---

## `capabilities` block

| Field | Type | Required | Description |
|---|---|---|---|
| `tools` | list[string] | — | Tool `action_id`s the agent is allowed to call. |
| `data_access` | list[string] | — | Data source names (used for audit and documentation). |
| `graph_access` | list[string] | — | SIF node types the agent reads/writes. |

> Tools listed here must also be in `boundaries.allowed_actions`. If a tool is not in `capabilities.tools`, `ToolExecutor.call()` will raise `PermissionError`.

---

## `boundaries` block

| Field | Type | Required | Description |
|---|---|---|---|
| `risk_budget` | enum | — | `low` \| `medium` \| `high`. Limits high-risk actions to matching budgets. Default: `medium`. |
| `allowed_actions` | list[string] | — | Explicit allow-list of action IDs. If non-empty, anything not listed is denied. |
| `denied_actions` | list[string] | — | Explicit deny-list. These are always blocked, even if in `allowed_actions`. |
| `environment_scope` | list[string] | — | Environments the agent can target. If set, actions against other environments are blocked. |
| `approval_gates` | list[string] | — | Action IDs that require human approval before execution. |

> **Conflict rule:** `denied_actions` takes priority over `allowed_actions`. An action in both lists is always denied. The schema validator raises an error for overlapping lists.

---

## `safety` block

| Field | Type | Required | Description |
|---|---|---|---|
| `guardrails` | list[string] | — | Named guardrail rules to apply (advisory; logged on violation). |
| `sandbox_profile` | enum | — | Execution sandbox profile (see below). |
| `audit_level` | enum | — | Log verbosity (see below). |

**Sandbox profiles:**
| Profile | Description |
|---|---|
| `strict` | No network, no file writes. Observe-only agents. |
| `standard` | Network allowed; no destructive system actions. |
| `permissive` | Broad access; must justify in `intent`. |
| `offensive_isolated` | Red team mode. **Required for `domain: red_team`.** Fully isolated environment. |

**Audit levels:**
| Level | What is logged |
|---|---|
| `minimal` | Start, complete, policy blocks only. |
| `standard` | + every tool call and result. |
| `verbose` | + full inputs/outputs on every event. **Required for `domain: red_team`.** |

---

## Domain-specific validation rules

These are enforced by the schema validator and cannot be overridden:

| Domain | Rule |
|---|---|
| `red_team` | `safety.sandbox_profile` must be `offensive_isolated` |
| `red_team` | `safety.audit_level` must be `verbose` |
| `red_team` | `boundaries.environment_scope` must not include `production` |
| `fully_autonomous` | `reasoning.confidence_threshold` must be `≥ 0.9` |
| All | `denied_actions` and `allowed_actions` must not overlap |

---

## Validation

```bash
zak validate my-agent.yaml
```

Or programmatically:
```python
from zak.core.dsl.parser import validate_agent, load_agent_yaml

result = validate_agent("my-agent.yaml")
if result.valid:
    dsl = load_agent_yaml("my-agent.yaml")
else:
    print(result.errors)
```
