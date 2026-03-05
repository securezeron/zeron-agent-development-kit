"""
ZAK Tenant Layer — TenantRegistry, TenantContext, and isolation utilities.

Multi-tenancy is enforced as a namespace layer at the graph adapter level.
Every operation carries a tenant_id — no raw graph access is possible without it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Tenant:
    """A registered tenant in the ZAK platform."""
    tenant_id: str
    name: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)
    active: bool = True


class TenantRegistry:
    """
    In-memory tenant registry (Phase 1).
    Singleton — all callers share the same tenant store.

    In production this would be backed by a persistent store (Postgres etc.).
    The interface is the same regardless of backing store.
    """

    _instance: TenantRegistry | None = None

    def __init__(self) -> None:
        # Only initialise _tenants on first construction
        if not hasattr(self, "_tenants"):
            self._tenants: dict[str, Tenant] = {}

    @classmethod
    def get(cls) -> TenantRegistry:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __new__(cls) -> TenantRegistry:
        # Always return the same instance so TenantRegistry() == TenantRegistry.get()
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def register(self, tenant_id: str, name: str, **metadata: Any) -> Tenant:
        """Register a new tenant. Raises ValueError if tenant_id already exists."""
        if tenant_id in self._tenants:
            raise ValueError(f"Tenant '{tenant_id}' is already registered.")
        tenant = Tenant(tenant_id=tenant_id, name=name, metadata=dict(metadata))
        self._tenants[tenant_id] = tenant
        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant:
        """Retrieve a tenant by ID. Raises KeyError if not found."""
        if tenant_id not in self._tenants:
            raise KeyError(f"Tenant '{tenant_id}' not found.")
        return self._tenants[tenant_id]

    def exists(self, tenant_id: str) -> bool:
        return tenant_id in self._tenants

    def deactivate(self, tenant_id: str) -> None:
        self.get_tenant(tenant_id).active = False

    def all(self) -> list[Tenant]:
        return list(self._tenants.values())

    def list_active(self) -> list[Tenant]:
        return [t for t in self._tenants.values() if t.active]

    def clear(self) -> None:
        """For tests only."""
        self._tenants.clear()



@dataclass
class TenantContext:
    """
    Scopes all runtime and graph operations to a single tenant.

    Created per-request/per-run. Never shared across tenants.
    """
    tenant_id: str
    trace_id: str
    environment: str = "staging"

    def graph_namespace(self, node_type: str) -> str:
        """
        Returns the namespaced node type label for Kuzu queries.

        Example: graph_namespace("asset") → "tenant__acme__asset"
        This prevents cross-tenant graph data from ever mixing.
        """
        safe_id = self.tenant_id.replace("-", "_").lower()
        return f"tenant__{safe_id}__{node_type}"

    def assert_active(self, registry: TenantRegistry) -> None:
        """Raises PermissionError if the tenant is not active."""
        tenant = registry.get(self.tenant_id)
        if not tenant.active:
            raise PermissionError(
                f"Tenant '{self.tenant_id}' is deactivated. Access denied."
            )
