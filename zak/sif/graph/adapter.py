"""
ZAK Memgraph Graph Adapter — tenant-namespaced graph operations via Bolt protocol.

Replaces the embedded KuzuDB backend with Memgraph, a server-mode graph DB
that speaks Bolt (same protocol as Neo4j). The public interface is identical
so all existing agents and services need zero changes.

Key design decisions:
- Tenant isolation via a `tenant_id` property on every node (no table prefixing needed)
- Labels: :Asset  :Vulnerability  :Identity  :Control  :Risk  :Vendor  :AIModel
- MERGE on (node_id, tenant_id) gives true upsert semantics
- Indexes on node_id and tenant_id per label for fast scoped queries
- All domain data (type-specific fields) stored in a JSON `data` blob

Run Memgraph locally:
    docker run -it -p 7687:7687 memgraph/memgraph

Configure via env vars (all optional, defaults shown):
    MEMGRAPH_HOST=localhost
    MEMGRAPH_PORT=7687
    MEMGRAPH_USER=        (empty = no auth)
    MEMGRAPH_PASSWORD=    (empty = no auth)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

try:
    from neo4j import GraphDatabase as _Neo4jGD  # type: ignore[import-untyped]
except ImportError:
    _Neo4jGD = None  # type: ignore[assignment]

from zak.sif.schema.nodes import (
    AIModelNode,
    AssetNode,
    ControlNode,
    IdentityNode,
    RiskNode,
    SIFNode,
    VendorNode,
    VulnerabilityNode,
)

logger = logging.getLogger(__name__)

# ── Mapping tables ─────────────────────────────────────────────────────────────

# node_type string  →  Memgraph label (CamelCase, Cypher convention)
NODE_LABEL_MAP: dict[str, str] = {
    "asset":           "Asset",
    "identity":        "Identity",
    "vulnerability":   "Vulnerability",
    "control":         "Control",
    "risk":            "Risk",
    "vendor":          "Vendor",
    "ai_model":        "AIModel",
}

# node_type string  →  Pydantic class
NODE_TYPE_MAP: dict[str, type[SIFNode]] = {
    "asset":           AssetNode,
    "identity":        IdentityNode,
    "vulnerability":   VulnerabilityNode,
    "control":         ControlNode,
    "risk":            RiskNode,
    "vendor":          VendorNode,
    "ai_model":        AIModelNode,
}


# ── Adapter ────────────────────────────────────────────────────────────────────

class KuzuAdapter:
    """
    Tenant-namespaced graph adapter backed by Memgraph (Bolt protocol).

    Class name kept as ``KuzuAdapter`` for backward compatibility — all existing
    agent code, tests and service layers import this name and need no changes.

    Usage::

        adapter = KuzuAdapter()                          # reads env vars
        adapter.initialize_schema(tenant_id="acme")
        adapter.upsert_node(tenant_id="acme", node=AssetNode(...))
        nodes = adapter.get_nodes(tenant_id="acme", node_type="asset")
        adapter.close()
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        user: str | None = None,
        password: str | None = None,
        # Legacy KuzuDB param — accepted but ignored (Memgraph is server-based)
        db_path: Any = None,
    ) -> None:
        if _Neo4jGD is None:
            raise ImportError(
                "neo4j package is required for the Memgraph graph adapter. "
                "Install with:  pip install neo4j  or  pip install 'zin-adk[graph]'"
            )

        _host     = host     or os.getenv("MEMGRAPH_HOST",     "localhost")
        _port     = port     or int(os.getenv("MEMGRAPH_PORT", "7687"))
        _user     = (user     if user     is not None else os.getenv("MEMGRAPH_USER",     ""))
        _password = (password if password is not None else os.getenv("MEMGRAPH_PASSWORD", ""))

        uri = f"bolt://{_host}:{_port}"
        self._driver = _Neo4jGD.driver(uri, auth=(_user, _password))
        logger.info("KuzuAdapter (Memgraph backend) connected to %s", uri)

    # ── Schema / indexes ───────────────────────────────────────────────────────

    def initialize_schema(self, tenant_id: str) -> None:
        """
        Create per-label indexes for fast tenant-scoped queries.

        Safe to call multiple times and safe when Memgraph is unreachable
        (logs a warning and continues — agents degrade gracefully to no-graph mode).
        """
        try:
            with self._driver.session() as session:
                for label in NODE_LABEL_MAP.values():
                    for prop in ("node_id", "tenant_id"):
                        try:
                            session.run(f"CREATE INDEX ON :{label}({prop});")
                        except Exception:
                            pass  # index already exists — that's fine
            logger.debug("Schema/indexes initialised for tenant %s", tenant_id)
        except Exception as exc:
            logger.warning(
                "Memgraph unreachable during schema init — running without graph storage. "
                "Start Memgraph with: docker compose up -d  Error: %s", exc,
            )

    # ── Write ──────────────────────────────────────────────────────────────────

    def upsert_node(self, tenant_id: str, node: SIFNode) -> None:
        """
        Insert or update a node in the graph.

        Uses MERGE on (node_id, tenant_id) — idempotent and efficient.
        Silently skips write and logs a warning if Memgraph is unreachable.
        """
        node_type = _get_node_type_key(node)
        label = NODE_LABEL_MAP[node_type]
        p = _node_to_props(tenant_id, node)

        try:
            with self._driver.session() as session:
                session.run(
                    f"""
                    MERGE (n:{label} {{node_id: $node_id, tenant_id: $tenant_id}})
                    SET
                        n.valid_from  = $valid_from,
                        n.valid_to    = $valid_to,
                        n.confidence  = $confidence,
                        n.source      = $source,
                        n.data        = $data
                    """,
                    node_id=p["node_id"],
                    tenant_id=p["tenant_id"],
                    valid_from=p["valid_from"],
                    valid_to=p["valid_to"],
                    confidence=p["confidence"],
                    source=p["source"],
                    data=p["data"],
                )
        except Exception as exc:
            logger.warning(
                "upsert_node failed (Memgraph unreachable?) — skipping write for %s: %s",
                node.node_id, exc,
            )

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_node(
        self, tenant_id: str, node_type: str, node_id: str
    ) -> Optional[dict[str, Any]]:
        """Retrieve a single node by type and ID. Returns None if not found or unreachable."""
        label = NODE_LABEL_MAP.get(node_type)
        if not label:
            return None

        try:
            with self._driver.session() as session:
                result = session.run(
                    f"MATCH (n:{label} {{node_id: $node_id, tenant_id: $tenant_id}}) RETURN n",
                    node_id=node_id,
                    tenant_id=tenant_id,
                )
                record = result.single()
                if record is None:
                    return None
                return _deserialise_node(record["n"])
        except Exception as exc:
            logger.warning("get_node failed (Memgraph unreachable?): %s", exc)
            return None

    def get_nodes(
        self,
        tenant_id: str,
        node_type: str,
        filters: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve all nodes of a given type for a tenant.

        Returns an empty list if Memgraph is unreachable (agents degrade gracefully).
        """
        label = NODE_LABEL_MAP.get(node_type)
        if not label:
            return []

        try:
            with self._driver.session() as session:
                result = session.run(
                    f"MATCH (n:{label} {{tenant_id: $tenant_id}}) RETURN n",
                    tenant_id=tenant_id,
                )
                nodes: list[dict[str, Any]] = [_deserialise_node(r["n"]) for r in result]
        except Exception as exc:
            logger.warning(
                "get_nodes(%s) failed (Memgraph unreachable?) — returning []: %s",
                node_type, exc,
            )
            return []

        if filters:
            nodes = [
                n for n in nodes
                if all(n.get(k) == v for k, v in filters.items())
            ]
        return nodes

    # ── Reasoning traces ───────────────────────────────────────────────────────

    def write_reasoning_trace(self, tenant_id: str, trace: dict[str, Any]) -> None:
        """
        Persist a reasoning trace as a :ReasoningTrace node in the graph.

        The trace dict must contain:
            trace_id        — unique run/trace identifier
            domain          — agent domain slug
            environment     — execution environment
            status          — "completed" | "failed"
            iteration_count — number of ReAct iterations
            tool_calls      — list of {tool, arguments} dicts
            output          — final agent output dict

        Silently skips write and logs a warning if Memgraph is unreachable.
        """
        import datetime

        trace_id = trace.get("trace_id", "")
        try:
            with self._driver.session() as session:
                session.run(
                    """
                    MERGE (t:ReasoningTrace {trace_id: $trace_id, tenant_id: $tenant_id})
                    SET
                        t.domain          = $domain,
                        t.environment     = $environment,
                        t.status          = $status,
                        t.iteration_count = $iteration_count,
                        t.tool_calls      = $tool_calls,
                        t.output          = $output,
                        t.timestamp       = $timestamp
                    """,
                    trace_id=trace_id,
                    tenant_id=tenant_id,
                    domain=trace.get("domain", ""),
                    environment=trace.get("environment", ""),
                    status=trace.get("status", "unknown"),
                    iteration_count=int(trace.get("iteration_count", 0)),
                    tool_calls=json.dumps(trace.get("tool_calls", []), default=str),
                    output=json.dumps(trace.get("output", {}), default=str),
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                )
            logger.debug("Reasoning trace %s persisted for tenant %s", trace_id, tenant_id)
        except Exception as exc:
            logger.warning(
                "write_reasoning_trace failed (Memgraph unreachable?) — "
                "skipping trace %s: %s", trace_id, exc,
            )

    def get_reasoning_traces(
        self, tenant_id: str, domain: str | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        """
        Retrieve recent reasoning traces for a tenant, optionally filtered by domain.

        Returns an empty list if Memgraph is unreachable.
        """
        try:
            with self._driver.session() as session:
                if domain:
                    result = session.run(
                        """
                        MATCH (t:ReasoningTrace {tenant_id: $tenant_id, domain: $domain})
                        RETURN t ORDER BY t.timestamp DESC LIMIT $limit
                        """,
                        tenant_id=tenant_id,
                        domain=domain,
                        limit=limit,
                    )
                else:
                    result = session.run(
                        """
                        MATCH (t:ReasoningTrace {tenant_id: $tenant_id})
                        RETURN t ORDER BY t.timestamp DESC LIMIT $limit
                        """,
                        tenant_id=tenant_id,
                        limit=limit,
                    )
                traces = []
                for record in result:
                    node = dict(record["t"])
                    # Deserialise JSON blobs back to Python objects
                    for key in ("tool_calls", "output"):
                        if isinstance(node.get(key), str):
                            try:
                                node[key] = json.loads(node[key])
                            except Exception:
                                pass
                    traces.append(node)
                return traces
        except Exception as exc:
            logger.warning(
                "get_reasoning_traces failed (Memgraph unreachable?): %s", exc
            )
            return []

    def upsert_edge(
        self,
        tenant_id: str,
        from_node_id: str,
        from_label: str,
        to_node_id: str,
        to_label: str,
        rel_type: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """
        Create or update a directed relationship between two nodes.

        Uses MERGE so it is safe to call multiple times (idempotent).
        Silently skips and logs a warning if Memgraph is unreachable.

        ``rel_type`` must be a valid Cypher relationship type (UPPER_SNAKE_CASE).
        Example: upsert_edge(..., rel_type="AssetHasVulnerability")
        """
        props = properties or {}

        # Validate labels against known node types to prevent Cypher injection
        valid_labels = set(NODE_LABEL_MAP.values()) | {"ReasoningTrace"}
        if from_label not in valid_labels:
            raise ValueError(
                f"Invalid from_label '{from_label}'. Must be one of: {sorted(valid_labels)}"
            )
        if to_label not in valid_labels:
            raise ValueError(
                f"Invalid to_label '{to_label}'. Must be one of: {sorted(valid_labels)}"
            )
        # rel_type must be alphanumeric/underscores only (valid Cypher relationship type)
        import re
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", rel_type):
            raise ValueError(
                f"Invalid rel_type '{rel_type}'. Must match [A-Za-z_][A-Za-z0-9_]*."
            )

        query = f"""
        MATCH (a:{from_label} {{node_id: $from_id, tenant_id: $tenant_id}})
        MATCH (b:{to_label}   {{node_id: $to_id,   tenant_id: $tenant_id}})
        MERGE (a)-[r:{rel_type}]->(b)
        SET r += $props
        """
        try:
            with self._driver.session() as session:
                session.run(
                    query,
                    from_id=from_node_id,
                    to_id=to_node_id,
                    tenant_id=tenant_id,
                    props=props,
                )
        except Exception as exc:
            logger.warning(
                "upsert_edge(%s -[%s]-> %s) failed (Memgraph unreachable?): %s",
                from_node_id, rel_type, to_node_id, exc,
            )

    def get_edges(self, tenant_id: str) -> list[dict[str, Any]]:
        """
        Retrieve all relationships between nodes for a tenant.

        Returns a list of dicts with keys: rel_type, source, target,
        source_label, target_label.

        Returns an empty list if Memgraph is unreachable (graceful degradation).
        """
        # Build the set of valid labels for SIF node types
        valid_labels = set(NODE_LABEL_MAP.values())
        query = """
        MATCH (a)-[r]->(b)
        WHERE a.tenant_id = $tenant_id AND b.tenant_id = $tenant_id
        RETURN type(r) AS rel_type,
               a.node_id AS source,
               b.node_id AS target,
               labels(a) AS source_labels,
               labels(b) AS target_labels
        """
        try:
            with self._driver.session() as session:
                result = session.run(query, tenant_id=tenant_id)
                edges: list[dict[str, Any]] = []
                for record in result:
                    # Pick the first label that matches a known SIF node type
                    src_labels = list(record["source_labels"] or [])
                    tgt_labels = list(record["target_labels"] or [])
                    source_label = next(
                        (label for label in src_labels if label in valid_labels), src_labels[0] if src_labels else ""
                    )
                    target_label = next(
                        (label for label in tgt_labels if label in valid_labels), tgt_labels[0] if tgt_labels else ""
                    )
                    edges.append({
                        "rel_type":     record["rel_type"],
                        "source":       record["source"],
                        "target":       record["target"],
                        "source_label": source_label,
                        "target_label": target_label,
                    })
                return edges
        except Exception as exc:
            logger.warning(
                "get_edges failed (Memgraph unreachable?) — returning []: %s", exc
            )
            return []

    def ping(self) -> bool:
        """Return True if Memgraph is reachable, False otherwise."""
        try:
            with self._driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception:
            return False

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the Bolt driver connection pool."""
        self._driver.close()

    def __enter__(self) -> KuzuAdapter:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


# ── Internal helpers ───────────────────────────────────────────────────────────

def _get_node_type_key(node: SIFNode) -> str:
    """Return the string type key for a SIFNode instance."""
    reverse = {v: k for k, v in NODE_TYPE_MAP.items()}
    key = reverse.get(type(node))
    if key is None:
        raise ValueError(
            f"Unknown node type: {type(node).__name__}. "
            "Register it in NODE_TYPE_MAP and NODE_LABEL_MAP."
        )
    return key


def _node_to_props(tenant_id: str, node: SIFNode) -> dict[str, Any]:
    """Flatten a SIFNode into a flat Memgraph-compatible property dict."""
    data = node.model_dump(mode="json")
    node_id    = data.pop("node_id")
    valid_from = str(data.pop("valid_from", "") or "")
    valid_to   = str(data.pop("valid_to",   "") or "")
    confidence = float(data.pop("confidence", 1.0))
    source     = str(data.pop("source", "") or "")
    # All remaining type-specific fields go into a JSON blob
    extra_json = json.dumps(data, default=str)

    return {
        "node_id":    node_id,
        "tenant_id":  tenant_id,
        "valid_from": valid_from,
        "valid_to":   valid_to,
        "confidence": confidence,
        "source":     source,
        "data":       extra_json,
    }


def _deserialise_node(node: Any) -> dict[str, Any]:
    """
    Convert a Memgraph node record into a plain dict.

    Merges the ``data`` JSON blob back into the top-level dict so callers
    see a flat view identical to what the Kuzu adapter returned.
    """
    props = dict(node)
    extra = props.pop("data", "{}")
    try:
        props.update(json.loads(extra))
    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to deserialise 'data' blob for node %s", props.get("node_id"))
    return props
