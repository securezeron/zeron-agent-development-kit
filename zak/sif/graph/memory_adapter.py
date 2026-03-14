"""
ZAK In-Memory Graph Adapter — zero-dependency graph backend for development and testing.

Drop-in replacement for KuzuAdapter that stores all nodes and edges in Python dicts.
No external database required — agents work out of the box.

Select via env var:
    ZAK_GRAPH_BACKEND=memory   (default)
    ZAK_GRAPH_BACKEND=memgraph

Or use directly:
    from zak.sif.graph.memory_adapter import InMemoryGraphAdapter
    adapter = InMemoryGraphAdapter()
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from zak.sif.graph.adapter import NODE_LABEL_MAP, NODE_TYPE_MAP, _node_to_props
from zak.sif.schema.nodes import SIFNode

logger = logging.getLogger(__name__)


class InMemoryGraphAdapter:
    """
    In-memory graph adapter with the same interface as KuzuAdapter.

    Nodes are stored as ``{(tenant_id, label, node_id): props_dict}``.
    Edges are stored as ``[(tenant_id, from_id, from_label, to_id, to_label, rel_type, props)]``.
    """

    def __init__(self, **_kwargs: Any) -> None:
        # Nodes: keyed by (tenant_id, label, node_id)
        self._nodes: dict[tuple[str, str, str], dict[str, Any]] = {}
        # Edges: list of edge records
        self._edges: list[dict[str, Any]] = []
        # Reasoning traces: keyed by (tenant_id, trace_id)
        self._traces: dict[tuple[str, str], dict[str, Any]] = {}
        logger.info("InMemoryGraphAdapter initialised (no external DB required)")

    # ── Schema / indexes ───────────────────────────────────────────────────────

    def initialize_schema(self, tenant_id: str) -> None:
        """No-op for in-memory backend — no indexes needed."""
        logger.debug("Schema init (no-op) for tenant %s", tenant_id)

    # ── Write ──────────────────────────────────────────────────────────────────

    def upsert_node(self, tenant_id: str, node: SIFNode) -> None:
        """Insert or update a node in the in-memory store."""
        node_type = self._get_node_type_key(node)
        label = NODE_LABEL_MAP[node_type]
        props = _node_to_props(tenant_id, node)
        key = (tenant_id, label, props["node_id"])
        self._nodes[key] = props

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_node(
        self, tenant_id: str, node_type: str, node_id: str
    ) -> Optional[dict[str, Any]]:
        """Retrieve a single node by type and ID."""
        label = NODE_LABEL_MAP.get(node_type)
        if not label:
            return None
        props = self._nodes.get((tenant_id, label, node_id))
        if props is None:
            return None
        return self._deserialise(props)

    def get_nodes(
        self,
        tenant_id: str,
        node_type: str,
        filters: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        """Retrieve all nodes of a given type for a tenant."""
        label = NODE_LABEL_MAP.get(node_type)
        if not label:
            return []
        nodes = [
            self._deserialise(props)
            for (tid, lbl, _), props in self._nodes.items()
            if tid == tenant_id and lbl == label
        ]
        if filters:
            nodes = [
                n for n in nodes
                if all(n.get(k) == v for k, v in filters.items())
            ]
        return nodes

    # ── Reasoning traces ───────────────────────────────────────────────────────

    def write_reasoning_trace(self, tenant_id: str, trace: dict[str, Any]) -> None:
        """Persist a reasoning trace in memory."""
        trace_id = trace.get("trace_id", "")
        record = {
            "trace_id": trace_id,
            "tenant_id": tenant_id,
            "domain": trace.get("domain", ""),
            "environment": trace.get("environment", ""),
            "status": trace.get("status", "unknown"),
            "iteration_count": int(trace.get("iteration_count", 0)),
            "tool_calls": trace.get("tool_calls", []),
            "output": trace.get("output", {}),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._traces[(tenant_id, trace_id)] = record

    def get_reasoning_traces(
        self, tenant_id: str, domain: str | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Retrieve recent reasoning traces."""
        traces = [
            t for (tid, _), t in self._traces.items()
            if tid == tenant_id and (domain is None or t.get("domain") == domain)
        ]
        traces.sort(key=lambda t: t.get("timestamp", ""), reverse=True)
        return traces[:limit]

    # ── Edges ──────────────────────────────────────────────────────────────────

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
        """Create or update a directed relationship between two nodes."""
        valid_labels = set(NODE_LABEL_MAP.values()) | {"ReasoningTrace"}
        if from_label not in valid_labels:
            raise ValueError(
                f"Invalid from_label '{from_label}'. Must be one of: {sorted(valid_labels)}"
            )
        if to_label not in valid_labels:
            raise ValueError(
                f"Invalid to_label '{to_label}'. Must be one of: {sorted(valid_labels)}"
            )
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", rel_type):
            raise ValueError(
                f"Invalid rel_type '{rel_type}'. Must match [A-Za-z_][A-Za-z0-9_]*."
            )

        # Check if edge already exists — update props if so
        for edge in self._edges:
            if (
                edge["tenant_id"] == tenant_id
                and edge["source"] == from_node_id
                and edge["target"] == to_node_id
                and edge["rel_type"] == rel_type
            ):
                edge["properties"] = properties or {}
                return

        self._edges.append({
            "tenant_id": tenant_id,
            "source": from_node_id,
            "source_label": from_label,
            "target": to_node_id,
            "target_label": to_label,
            "rel_type": rel_type,
            "properties": properties or {},
        })

    def get_edges(self, tenant_id: str) -> list[dict[str, Any]]:
        """Retrieve all relationships for a tenant."""
        return [
            {
                "rel_type": e["rel_type"],
                "source": e["source"],
                "target": e["target"],
                "source_label": e["source_label"],
                "target_label": e["target_label"],
            }
            for e in self._edges
            if e["tenant_id"] == tenant_id
        ]

    # ── Utility ────────────────────────────────────────────────────────────────

    def ping(self) -> bool:
        """Always reachable."""
        return True

    def close(self) -> None:
        """No-op — nothing to close."""
        pass

    def __enter__(self) -> InMemoryGraphAdapter:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _get_node_type_key(node: SIFNode) -> str:
        reverse = {v: k for k, v in NODE_TYPE_MAP.items()}
        key = reverse.get(type(node))
        if key is None:
            raise ValueError(f"Unknown node type: {type(node).__name__}")
        return key

    @staticmethod
    def _deserialise(props: dict[str, Any]) -> dict[str, Any]:
        """Merge the JSON data blob back into a flat dict."""
        result = dict(props)
        extra = result.pop("data", "{}")
        try:
            result.update(json.loads(extra))
        except (json.JSONDecodeError, TypeError):
            pass
        return result
