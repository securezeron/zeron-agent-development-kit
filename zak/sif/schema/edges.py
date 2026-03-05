"""
ZAK SIF Edge Schemas — typed relationship definitions for the Security Intelligence Fabric.

Edges represent relationships between nodes. Each edge type encodes the semantics
of the relationship (e.g. IDENTITY_HAS_ACCESS_TO means read/write access, not ownership).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SIFEdge(BaseModel):
    """Base class for all SIF edges. Time-aware and confidence-scored."""
    from_id: str = Field(..., description="Source node ID")
    to_id: str = Field(..., description="Target node ID")
    valid_from: datetime = Field(default_factory=_now)
    valid_to: Optional[datetime] = None
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    source: str = Field(..., description="Integration or system that produced this edge")


class IdentityHasAccessToAsset(SIFEdge):
    """IDENTITY → ASSET: an identity has access to an asset."""
    access_type: str = "read"  # read | write | admin
    granted_by: Optional[str] = None


class AssetHasVulnerability(SIFEdge):
    """ASSET → VULNERABILITY: a vulnerability was found on an asset."""
    scanner: Optional[str] = None
    first_seen: datetime = Field(default_factory=_now)


class ControlMitigatesVulnerability(SIFEdge):
    """CONTROL → VULNERABILITY: a control reduces the risk of a vulnerability."""
    mitigation_type: str = "partial"  # full | partial | compensating


class VendorSuppliesAsset(SIFEdge):
    """VENDOR → ASSET: a vendor provides or manages an asset."""
    contract_ref: Optional[str] = None


class AIModelAccessesDataStore(SIFEdge):
    """AI_MODEL → ASSET (data_store): an AI model reads from a data store."""
    access_purpose: str = "training"  # training | inference | evaluation


class RiskImpactsAsset(SIFEdge):
    """RISK → ASSET: a risk scenario could impact an asset if realized."""
    blast_radius: str = "local"  # local | department | org_wide


class AssetCommunicatesWith(SIFEdge):
    """ASSET → ASSET: network communication relationship."""
    protocol: Optional[str] = None
    port: Optional[int] = None
    encrypted: bool = True
