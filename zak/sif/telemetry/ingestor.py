"""
ZAK Telemetry Ingestor — parses incoming security events and upserts them into the SIF graph.

Supported event shapes (Phase 1):
- vulnerability_found  → creates/updates VulnerabilityNode + AssetHasVulnerability edge
- asset_discovered     → creates/updates AssetNode
- control_updated      → creates/updates ControlNode
- vendor_assessed      → creates/updates VendorNode
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from zak.sif.graph.adapter import KuzuAdapter
from zak.sif.schema.nodes import AssetNode, ControlNode, VendorNode, VulnerabilityNode


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


class TelemetryIngestor:
    """
    Consumes raw telemetry events (dicts) and writes structured nodes/edges into the SIF.

    All ingest operations are tenant-scoped. Events that don't match a known
    schema are logged and skipped (no-op).
    """

    SUPPORTED_EVENTS = {
        "vulnerability_found",
        "asset_discovered",
        "control_updated",
        "vendor_assessed",
    }

    def __init__(self, adapter: KuzuAdapter) -> None:
        self._adapter = adapter

    def ingest(self, event: dict[str, Any], tenant_id: str) -> None:
        """
        Process a single telemetry event and persist to the SIF graph.

        Args:
            event:     Raw event dict. Must contain 'event_type' key.
            tenant_id: Tenant to scope the write to.
        """
        event_type = event.get("event_type")
        if event_type not in self.SUPPORTED_EVENTS:
            return  # Unsupported events are silently dropped in Phase 1

        handler = getattr(self, f"_handle_{event_type}", None)
        if handler:
            handler(event, tenant_id)

    def _handle_asset_discovered(
        self, event: dict[str, Any], tenant_id: str
    ) -> None:
        node = AssetNode(
            node_id=event.get("asset_id", str(uuid4())),
            asset_type=event.get("asset_type", "unknown"),
            criticality=event.get("criticality", "medium"),
            environment=event.get("environment", "production"),
            owner=event.get("owner"),
            exposure_level=event.get("exposure_level", "internal"),
            source=event.get("source", "telemetry"),
        )
        self._adapter.upsert_node(tenant_id, node)

    def _handle_vulnerability_found(
        self, event: dict[str, Any], tenant_id: str
    ) -> None:
        vuln = VulnerabilityNode(
            node_id=event.get("vuln_id", str(uuid4())),
            vuln_type=event.get("vuln_type", "cve"),
            cve_id=event.get("cve_id"),
            severity=event.get("severity", "medium"),
            exploitability=_safe_float(event.get("exploitability", 0.5), 0.5),
            cvss_score=event.get("cvss_score"),
            source=event.get("source", "telemetry"),
        )
        self._adapter.upsert_node(tenant_id, vuln)

        # Create AssetHasVulnerability edge if asset_id is provided
        asset_id = event.get("asset_id")
        if asset_id:
            self._adapter.upsert_edge(
                tenant_id=tenant_id,
                from_node_id=asset_id,
                from_label="Asset",
                to_node_id=vuln.node_id,
                to_label="Vulnerability",
                rel_type="AssetHasVulnerability",
            )

    def _handle_control_updated(
        self, event: dict[str, Any], tenant_id: str
    ) -> None:
        node = ControlNode(
            node_id=event.get("control_id", str(uuid4())),
            control_type=event.get("control_type", "unknown"),
            effectiveness=_safe_float(event.get("effectiveness", 0.5), 0.5),
            automated=event.get("automated", True),
            source=event.get("source", "telemetry"),
        )
        self._adapter.upsert_node(tenant_id, node)

    def _handle_vendor_assessed(
        self, event: dict[str, Any], tenant_id: str
    ) -> None:
        node = VendorNode(
            node_id=event.get("vendor_id", str(uuid4())),
            vendor_type=event.get("vendor_type", "saas"),
            tier=_safe_int(event.get("tier", 1), 1),
            risk_score=_safe_float(event.get("risk_score", 0.0), 0.0),
            last_assessed=datetime.now(timezone.utc),
            source=event.get("source", "telemetry"),
        )
        self._adapter.upsert_node(tenant_id, node)
