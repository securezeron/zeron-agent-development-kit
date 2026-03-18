# CLI Reference

ZAK includes a developer-facing CLI for scaffolding, validating, and running agents. The CLI is available in all three ADKs.

=== "Python"

    ```bash
    pip install zin-adk
    zak --help
    ```

=== "Node.js"

    ```bash
    npm install zin-adk
    npx zak --help
    ```

=== "Go"

    ```bash
    go install github.com/securezeron/zeron-agent-development-kit/adk/go/cmd/zak@latest
    zak --help
    ```

---

## `zak init`

Scaffold a new agent — generates a YAML definition and Python class.

```bash
zak init --name <agent-name> --domain <domain> [--out <directory>]
```

| Flag | Short | Required | Description |
|---|---|---|---|
| `--name` | `-n` | ✅ | Human-readable agent name. Spaces OK (e.g. `"My Risk Agent"`). |
| `--domain` | `-d` | ✅ | Security domain. One of: `risk_quant`, `supply_chain`, `red_team`, `appsec`, `ai_security`, `compliance`. |
| `--out` | `-o` | — | Output directory. Default: `.` (current directory). |

**Example:**
```bash
zak init --name "Container Vuln Scanner" --domain appsec --out ./agents
```

**Output:**
```
✅ Agent scaffolded!
YAML:   agents/container-vuln-scanner.yaml
Class:  agents/container_vuln_scanner.py

Next:
  1. Implement ContainerVulnScannerAgent.execute()
  2. zak validate agents/container-vuln-scanner.yaml
  3. zak run agents/container-vuln-scanner.yaml --tenant <id>
```

The generated YAML is **immediately validated** after creation. If there are any issues, they are reported.

---

## `zak validate`

Validate a US-ADSL agent YAML definition.

```bash
zak validate <path>
```

| Argument | Description |
|---|---|
| `path` | Path to the YAML file to validate. |

**Success output:**
```
╭─ ZAK Validation ─────────────────────────────╮
│ ✅ Valid — Agent ID: container-vuln-scanner   │
╰───────────────────────────────────────────────╯
```

**Failure output:**
```
╭─ ❌ Validation Failed (2 error(s)) ──────────╮
│ • agent.id: must match slug pattern [a-z0-9-] │
│ • safety.sandbox_profile: red_team agents ... │
╰───────────────────────────────────────────────╯
```

Exit code `1` on validation failure. Use in CI:
```yaml
# .github/workflows/zak.yml
- run: zak validate agents/my-agent.yaml
```

---

## `zak run`

Run an agent defined by a YAML file under a specific tenant context.

```bash
zak run <path> --tenant <id> [--env <environment>]
```

| Argument/Flag | Short | Required | Description |
|---|---|---|---|
| `path` | — | ✅ | Path to the YAML file to run. |
| `--tenant` | `-t` | ✅ | Tenant ID. Created automatically if it doesn't exist. |
| `--env` | `-e` | — | Target environment. Default: `staging`. |

**Example:**
```bash
zak run agents/my-risk-agent.yaml --tenant acme --env production
```

**Output:**
```
╭─ 🚀 ZAK Agent Run ─────────────────────────────────────╮
│ Agent:       My Risk Agent (my-risk-agent)              │
│ Tenant:      acme                                       │
│ Environment: production                                 │
│ Trace ID:    01HX2P... (ULID)                           │
╰─────────────────────────────────────────────────────────╯

✅ Agent completed successfully in 142.3ms
```

**Agent not registered:**
```
⚠ No agent registered for domain 'appsec'.
  Implement a BaseAgent subclass and decorate it with @register_agent(domain="appsec").

Registered domains: ['risk_quant', 'supply_chain']
```

**Audit logs** (JSON, emitted to stdout during run):
```json
{"event": "agent.started", "agent_id": "my-risk-agent", "tenant_id": "acme", "trace_id": "01HX2P..."}
{"event": "tool.called", "tool": "list_assets", "agent_id": "my-risk-agent", ...}
{"event": "tool.result", "tool": "list_assets", "result_type": "list", ...}
{"event": "agent.completed", "success": true, "duration_ms": 142.3, ...}
```

---

## `zak agents`

List all registered agent classes and their domains.

```bash
zak agents
```

**Output:**
```
             Registered Agents
┌──────────────┬──────────────────┬─────────┬──────────────────────┐
│ Domain       │ Class            │ Version │ Description          │
├──────────────┼──────────────────┼─────────┼──────────────────────┤
│ risk_quant   │ RiskQuantAgent   │ 1.0.0   │ Computes risk scores  │
│ supply_chain │ SupplyChainAgent │ 1.0.0   │ Assesses vendor risk │
└──────────────┴──────────────────┴─────────┴──────────────────────┘
```

---

## `zak info`

Show ZAK platform info and registered domains.

```bash
zak info
```

**Output:**
```
         ZAK Platform Info
┌────────────────────┬──────────────────────────┐
│ Version            │ 0.1.0                    │
│ Registered Domains │ risk_quant, supply_chain  │
│ Graph Backend      │ Kuzu → Memgraph           │
│ Multi-tenant       │ ✅ Namespace isolation    │
│ Audit              │ ✅ Structured JSON        │
└────────────────────┴──────────────────────────┘
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Validation failure or agent execution error |

---

## Using with CI/CD

```yaml
# Example GitHub Actions step
- name: Validate ZAK agent definitions
  run: |
    source .venv/bin/activate
    for f in agents/*.yaml; do zak validate "$f"; done

- name: Run compliance agent (dry-run on staging)
  run: |
    source .venv/bin/activate
    zak run agents/compliance-agent.yaml --tenant ci-tenant --env staging
```
