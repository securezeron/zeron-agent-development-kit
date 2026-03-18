"""Tests for InMemoryGraphAdapter — verifies same interface as KuzuAdapter."""

from __future__ import annotations

import pytest

from zak.sif.graph.memory_adapter import InMemoryGraphAdapter
from zak.sif.schema.nodes import (
    AssetNode,
    ControlNode,
    IdentityNode,
    RiskNode,
    VendorNode,
    VulnerabilityNode,
)


@pytest.fixture
def adapter() -> InMemoryGraphAdapter:
    return InMemoryGraphAdapter()


TENANT = "test-tenant"


class TestInMemoryGraphAdapter:
    def test_ping(self, adapter: InMemoryGraphAdapter) -> None:
        assert adapter.ping() is True

    def test_initialize_schema_noop(self, adapter: InMemoryGraphAdapter) -> None:
        adapter.initialize_schema(TENANT)  # should not raise

    def test_upsert_and_get_node(self, adapter: InMemoryGraphAdapter) -> None:
        node = AssetNode(
            node_id="srv-001",
            asset_type="server",
            criticality="high",
            source="test",
        )
        adapter.upsert_node(TENANT, node)

        result = adapter.get_node(TENANT, "asset", "srv-001")
        assert result is not None
        assert result["node_id"] == "srv-001"
        assert result["asset_type"] == "server"

    def test_get_node_not_found(self, adapter: InMemoryGraphAdapter) -> None:
        assert adapter.get_node(TENANT, "asset", "nonexistent") is None

    def test_get_node_invalid_type(self, adapter: InMemoryGraphAdapter) -> None:
        assert adapter.get_node(TENANT, "invalid_type", "x") is None

    def test_get_nodes(self, adapter: InMemoryGraphAdapter) -> None:
        for i in range(3):
            adapter.upsert_node(
                TENANT,
                AssetNode(node_id=f"srv-{i}", asset_type="server", source="test"),
            )
        nodes = adapter.get_nodes(TENANT, "asset")
        assert len(nodes) == 3

    def test_get_nodes_with_filters(self, adapter: InMemoryGraphAdapter) -> None:
        adapter.upsert_node(
            TENANT,
            AssetNode(node_id="srv-1", asset_type="server", source="test"),
        )
        adapter.upsert_node(
            TENANT,
            AssetNode(node_id="db-1", asset_type="database", source="test"),
        )
        servers = adapter.get_nodes(TENANT, "asset", filters={"asset_type": "server"})
        assert len(servers) == 1
        assert servers[0]["asset_type"] == "server"

    def test_tenant_isolation(self, adapter: InMemoryGraphAdapter) -> None:
        adapter.upsert_node(
            "tenant-a",
            AssetNode(node_id="srv-1", asset_type="server", source="test"),
        )
        adapter.upsert_node(
            "tenant-b",
            AssetNode(node_id="srv-1", asset_type="server", source="test"),
        )
        assert len(adapter.get_nodes("tenant-a", "asset")) == 1
        assert len(adapter.get_nodes("tenant-b", "asset")) == 1
        assert adapter.get_node("tenant-a", "asset", "srv-1") is not None
        assert adapter.get_node("tenant-b", "asset", "srv-1") is not None

    def test_upsert_updates_existing(self, adapter: InMemoryGraphAdapter) -> None:
        adapter.upsert_node(
            TENANT,
            AssetNode(node_id="srv-1", asset_type="server", source="v1"),
        )
        adapter.upsert_node(
            TENANT,
            AssetNode(node_id="srv-1", asset_type="database", source="v2"),
        )
        result = adapter.get_node(TENANT, "asset", "srv-1")
        assert result is not None
        assert result["asset_type"] == "database"
        assert result["source"] == "v2"

    def test_all_node_types(self, adapter: InMemoryGraphAdapter) -> None:
        nodes = [
            ("asset", AssetNode(node_id="a1", asset_type="server", source="t")),
            ("identity", IdentityNode(node_id="i1", identity_type="human", source="t")),
            ("vulnerability", VulnerabilityNode(node_id="v1", vuln_type="cve", source="t")),
            ("control", ControlNode(node_id="c1", control_type="firewall", source="t")),
            ("risk", RiskNode(node_id="r1", risk_type="cyber", source="t")),
            ("vendor", VendorNode(node_id="vn1", vendor_type="saas", tier=1, source="t")),
        ]
        for node_type, node in nodes:
            adapter.upsert_node(TENANT, node)
            result = adapter.get_node(TENANT, node_type, node.node_id)
            assert result is not None, f"Failed for {node_type}"

    def test_upsert_and_get_edge(self, adapter: InMemoryGraphAdapter) -> None:
        adapter.upsert_node(TENANT, AssetNode(node_id="a1", asset_type="server", source="t"))
        adapter.upsert_node(
            TENANT, VulnerabilityNode(node_id="v1", vuln_type="cve", source="t")
        )
        adapter.upsert_edge(
            tenant_id=TENANT,
            from_node_id="a1",
            from_label="Asset",
            to_node_id="v1",
            to_label="Vulnerability",
            rel_type="AssetHasVulnerability",
        )
        edges = adapter.get_edges(TENANT)
        assert len(edges) == 1
        assert edges[0]["rel_type"] == "AssetHasVulnerability"
        assert edges[0]["source"] == "a1"
        assert edges[0]["target"] == "v1"

    def test_edge_upsert_updates_props(self, adapter: InMemoryGraphAdapter) -> None:
        adapter.upsert_edge(
            TENANT, "a1", "Asset", "v1", "Vulnerability", "HAS", {"score": 1},
        )
        adapter.upsert_edge(
            TENANT, "a1", "Asset", "v1", "Vulnerability", "HAS", {"score": 2},
        )
        edges = adapter.get_edges(TENANT)
        assert len(edges) == 1

    def test_edge_invalid_label_raises(self, adapter: InMemoryGraphAdapter) -> None:
        with pytest.raises(ValueError, match="Invalid from_label"):
            adapter.upsert_edge(TENANT, "a", "BadLabel", "b", "Asset", "REL")

    def test_edge_invalid_rel_type_raises(self, adapter: InMemoryGraphAdapter) -> None:
        with pytest.raises(ValueError, match="Invalid rel_type"):
            adapter.upsert_edge(TENANT, "a", "Asset", "b", "Asset", "bad rel!")

    def test_edge_tenant_isolation(self, adapter: InMemoryGraphAdapter) -> None:
        adapter.upsert_edge("t1", "a", "Asset", "b", "Asset", "DEPENDS_ON")
        adapter.upsert_edge("t2", "a", "Asset", "b", "Asset", "DEPENDS_ON")
        assert len(adapter.get_edges("t1")) == 1
        assert len(adapter.get_edges("t2")) == 1

    def test_reasoning_trace(self, adapter: InMemoryGraphAdapter) -> None:
        adapter.write_reasoning_trace(TENANT, {
            "trace_id": "tr-1",
            "domain": "risk_quant",
            "status": "completed",
            "iteration_count": 3,
            "tool_calls": [{"tool": "compute_risk"}],
            "output": {"risk_score": 7.5},
        })
        traces = adapter.get_reasoning_traces(TENANT)
        assert len(traces) == 1
        assert traces[0]["trace_id"] == "tr-1"

    def test_reasoning_trace_domain_filter(self, adapter: InMemoryGraphAdapter) -> None:
        adapter.write_reasoning_trace(TENANT, {"trace_id": "t1", "domain": "risk_quant"})
        adapter.write_reasoning_trace(TENANT, {"trace_id": "t2", "domain": "vuln_triage"})
        assert len(adapter.get_reasoning_traces(TENANT, domain="risk_quant")) == 1

    def test_context_manager(self) -> None:
        with InMemoryGraphAdapter() as adapter:
            assert adapter.ping() is True

    def test_get_nodes_empty(self, adapter: InMemoryGraphAdapter) -> None:
        assert adapter.get_nodes(TENANT, "asset") == []
        assert adapter.get_nodes(TENANT, "invalid_type") == []
