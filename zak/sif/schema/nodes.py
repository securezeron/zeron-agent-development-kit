"""
ZAK SIF Node Schemas — canonical Pydantic models for all Security Intelligence Fabric node types.

Every node is:
- Time-aware: valid_from, valid_to, confidence, source
- Tenant-scoped: tenant_id injected at graph adapter level
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Shared time-aware base
# ---------------------------------------------------------------------------


class SIFNode(BaseModel):
    """Base class for all SIF nodes. Provides time-aware metadata."""
    node_id: str = Field(..., description="Unique identifier for this node")
    valid_from: datetime = Field(default_factory=_now)
    valid_to: Optional[datetime] = Field(None, description="None means currently active")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Data confidence score")
    source: str = Field(..., description="System or integration that produced this node")

    @property
    def is_active(self) -> bool:
        """Returns True if the node is currently valid (not expired)."""
        if self.valid_to is None:
            return True
        return datetime.now(timezone.utc) < self.valid_to


# ---------------------------------------------------------------------------
# Enums shared across node types
# ---------------------------------------------------------------------------


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExposureLevel(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    INTERNET_FACING = "internet_facing"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEV = "dev"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnStatus(str, Enum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class PrivilegeLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ADMIN = "admin"


class DataSensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    RESTRICTED = "restricted"


# ---------------------------------------------------------------------------
# Canonical Node Types
# ---------------------------------------------------------------------------


class AssetNode(SIFNode):
    """Represents a technology asset (server, service, application, database, etc.)."""
    asset_type: str = Field(..., description="e.g. server, application, database, cloud_service")
    criticality: Criticality = Criticality.MEDIUM
    environment: Environment = Environment.PRODUCTION
    owner: Optional[str] = None
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    tags: list[str] = Field(default_factory=list)


class IdentityNode(SIFNode):
    """Represents a human or machine identity (user, service account, API key, etc.)."""
    identity_type: str = Field(..., description="e.g. human, service_account, api_key, role")
    privilege_level: PrivilegeLevel = PrivilegeLevel.LOW
    mfa_enabled: bool = False
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    department: Optional[str] = None


class VulnerabilityNode(SIFNode):
    """Represents a security vulnerability (CVE, misconfiguration, finding, etc.)."""
    vuln_type: str = Field(..., description="e.g. cve, misconfiguration, secret_exposure, injection")
    cve_id: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    exploitability: float = Field(0.5, ge=0.0, le=1.0, description="CVSS exploitability score (0-1)")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    status: VulnStatus = VulnStatus.OPEN


class ControlNode(SIFNode):
    """Represents a security control (firewall rule, policy, monitoring, etc.)."""
    control_type: str = Field(..., description="e.g. firewall, waf, iam_policy, mfa, dlp")
    effectiveness: float = Field(0.5, ge=0.0, le=1.0, description="Control effectiveness (0-1)")
    automated: bool = True
    framework_refs: list[str] = Field(
        default_factory=list,
        description="Framework control IDs this maps to (e.g. ISO27001:A.12.6.1)",
    )


class RiskNode(SIFNode):
    """Represents a computed risk scenario."""
    risk_type: str = Field(..., description="e.g. cyber, ai, third_party, operational")
    likelihood: float = Field(0.0, ge=0.0, le=1.0)
    impact: float = Field(0.0, ge=0.0, le=10.0)
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    eal: Optional[float] = Field(None, description="Expected Annual Loss in USD")
    var_95: Optional[float] = Field(None, description="Value at Risk (95th percentile) in USD")


class VendorNode(SIFNode):
    """Represents a third-party vendor or supplier."""
    vendor_type: str = Field(..., description="e.g. saas, infrastructure, professional_services")
    tier: int = Field(..., ge=1, le=3, description="Supply chain tier (1=direct, 3=nth party)")
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    last_assessed: Optional[datetime] = None
    country: Optional[str] = None


class AIModelNode(SIFNode):
    """Represents an AI/ML model in use within the organization."""
    model_type: str = Field(..., description="e.g. llm, classifier, embedding, generative")
    provider: str = Field(..., description="e.g. openai, anthropic, google, internal")
    data_sensitivity: DataSensitivity = DataSensitivity.MEDIUM
    guardrails_enabled: bool = False
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    exposed_via_api: bool = False
