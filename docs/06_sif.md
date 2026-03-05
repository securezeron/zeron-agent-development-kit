# Security Intelligence Fabric (SIF) Reference

The SIF is the shared, time-aware, tenant-namespaced security knowledge graph that all agents read from and write to.

---

## Node types

All nodes extend the `SIFNode` base which provides:

| Field | Type | Description |
|---|---|---|
| `node_id` | str | Unique identifier for this node |
| `valid_from` | datetime | When this data became valid |
| `valid_to` | datetime \| None | When it expired (`None` = currently active) |
| `confidence` | float (0–1) | Data quality score from the source integration |
| `source` | str | Integration that produced this data (e.g. `"snyk"`, `"crowdstrike"`) |

### AssetNode

Represents a technical asset (server, service, container, database).

```python
AssetNode(
    node_id="asset-srv-001",
    name="Payment Service",
    asset_type="service",           # "host" | "service" | "container" | "database" | "cloud_resource"
    criticality="high",             # "low" | "medium" | "high" | "critical"
    exposure_level="internet_facing", # "internet_facing" | "external" | "internal" | "air_gapped"
    owner="payments-team",
    environment="production",
    tags=["pci", "tier-1"],
    source="cmdb",
)
```

### VulnerabilityNode

Represents a known security vulnerability.

```python
VulnerabilityNode(
    node_id="CVE-2024-1234",
    vuln_type="cve",                # "cve" | "cwe" | "owasp" | "custom"
    severity="critical",            # "informational" | "low" | "medium" | "high" | "critical"
    cvss_score=9.8,
    exploitability=0.9,
    patch_available=True,
    status="open",                  # "open" | "in_remediation" | "resolved" | "accepted"
    source="snyk",
)
```

### IdentityNode

Represents a human or service identity.

```python
IdentityNode(
    node_id="user-sanket",
    identity_type="human",          # "human" | "service_account" | "api_key" | "role"
    privilege_level="admin",        # "none" | "low" | "medium" | "high" | "admin"
    mfa_enabled=True,
    source="okta",
)
```

### ControlNode

Represents a security control.

```python
ControlNode(
    node_id="ctrl-waf-001",
    control_type="preventive",      # "preventive" | "detective" | "corrective" | "compensating"
    effectiveness=0.85,
    framework="SOC2",
    status="active",
    source="manual",
)
```

### RiskNode

Represents a computed risk score for an asset.

```python
RiskNode(
    node_id="risk-srv-001-v1",
    risk_score=7.2,
    risk_level="high",              # "low" | "medium" | "high" | "critical"
    eal=45000.0,                    # Expected Annual Loss (USD)
    contributing_factors=["CVE-2024-1234", "internet_facing", "admin_identity"],
    source="zak-risk-quant-agent",
)
```

### VendorNode

Represents a third-party vendor.

```python
VendorNode(
    node_id="vendor-acme",
    name="Acme Corp",
    tier=1,                         # 1=critical, 2=important, 3=standard
    risk_score=4.5,
    source="vendor_registry",
)
```

### AIModelNode

Represents an AI/ML model in use by the organization.

```python
AIModelNode(
    node_id="model-gpt4-prod",
    model_type="llm",
    exposure="external",
    training_data_classification="confidential",
    prompt_injection_risk=0.6,
    source="ai_registry",
)
```

---

## Edge types

| Edge | From → To | Meaning |
|---|---|---|
| `IdentityHasAccessToAsset` | Identity → Asset | Identity can access the asset |
| `AssetHasVulnerability` | Asset → Vulnerability | Asset is affected by the vulnerability |
| `ControlMitigatesVulnerability` | Control → Vulnerability | Control reduces vulnerability exposure |
| `AssetDependsOnVendor` | Asset → Vendor | Asset depends on a vendor's service/component |
| `RiskImpactsAsset` | Risk → Asset | Computed risk is attributed to this asset |
| `AIModelAccessesDataStore` | AIModel → Asset | AI model processes data from this store |
| `IdentityOwnsAsset` | Identity → Asset | Identity owns/is responsible for the asset |

---

## Graph backend — Memgraph

ZAK uses **Memgraph** as the graph database for the SIF. Memgraph is accessed via the **Bolt protocol** (compatible with Neo4j drivers), runs as a Docker container, and provides:

- **Memgraph Lab** at `http://localhost:3001` for visual graph exploration
- **Bolt endpoint** at `bolt://localhost:7687` for programmatic access

```bash
# Start Memgraph (from the project root)
docker compose up -d
```

## Graph adapter (direct use)

For cases where you need to write to the graph directly (e.g. from ingestion pipelines), use the graph adapter:

```python
from zak.sif.graph.adapter import KuzuAdapter

adapter = KuzuAdapter()  # connects to Memgraph via Bolt protocol
adapter.initialize_schema("acme")  # create tenant namespace

# Upsert a node
from zak.sif.schema.nodes import AssetNode
from datetime import datetime, timezone

asset = AssetNode(
    node_id="asset-db-001",
    name="Payments DB",
    asset_type="database",
    criticality="critical",
    exposure_level="internal",
    source="cmdb",
    valid_from=datetime.now(timezone.utc),
    confidence=0.99,
)
adapter.upsert_node(tenant_id="acme", node=asset)

# Read a node
node = adapter.get_node(tenant_id="acme", node_type="asset", node_id="asset-db-001")

# Read all nodes of a type
assets = adapter.get_nodes(tenant_id="acme", node_type="asset")

# Check connectivity
adapter.ping()  # returns True if Memgraph is reachable
```

> **Inside agents:** use `ToolExecutor.call()` instead of the adapter directly. The adapter is for ingestion pipelines and integration code outside agents.

---

## Telemetry ingestion

The `TelemetryIngestor` maps raw events from integrations to SIF nodes/edges:

```python
from zak.sif.telemetry.ingestor import TelemetryIngestor

ingestor = TelemetryIngestor(adapter)

# Supported event types
ingestor.ingest({"event_type": "vulnerability_found", ...}, tenant_id="acme")
ingestor.ingest({"event_type": "asset_discovered", ...}, tenant_id="acme")
ingestor.ingest({"event_type": "control_updated", ...}, tenant_id="acme")
ingestor.ingest({"event_type": "vendor_assessed", ...}, tenant_id="acme")
```

**`vulnerability_found` payload:**
```json
{
  "event_type": "vulnerability_found",
  "vuln_id": "CVE-2024-1234",
  "vuln_type": "cve",
  "severity": "critical",
  "exploitability": 0.9,
  "cvss_score": 9.8,
  "status": "open",
  "patch_available": true,
  "source": "snyk"
}
```

**`asset_discovered` payload:**
```json
{
  "event_type": "asset_discovered",
  "asset_id": "asset-srv-001",
  "name": "API Gateway",
  "asset_type": "service",
  "criticality": "high",
  "exposure_level": "internet_facing",
  "environment": "production",
  "source": "aws_config"
}
```

---

## Risk propagation formula

```
risk_raw = base_risk × exposure_factor × exploitability × (1 - control_effectiveness) × privilege_amplifier
risk_score = min(risk_raw × 10, 10.0)
```

Input mappings:

| Input | Values |
|---|---|
| `criticality` → `base_risk` | `critical=1.0`, `high=0.7`, `medium=0.4`, `low=0.2` |
| `exposure` → `exposure_factor` | `internet_facing=1.0`, `external=0.6`, `internal=0.2`, `air_gapped=0.05` |
| `privilege_level` → `privilege_amplifier` | `admin=1.5`, `high=1.3`, `medium=1.0`, `low=0.5`, `none=0.1` |

Risk level bands:
- `critical` — score ≥ 7.5
- `high` — score ≥ 5.0
- `medium` — score ≥ 2.5
- `low` — score < 2.5
