/**
 * ZAK Tenant Layer — TenantRegistry, TenantContext, and isolation utilities.
 *
 * Multi-tenancy is enforced as a namespace layer at the graph adapter level.
 * Every operation carries a tenantId — no raw graph access is possible without it.
 *
 * TypeScript equivalent of zak/tenants/context.py.
 */

// ---------------------------------------------------------------------------
// Tenant
// ---------------------------------------------------------------------------

export interface Tenant {
  tenantId: string;
  name: string;
  createdAt: Date;
  metadata: Record<string, unknown>;
  active: boolean;
}

// ---------------------------------------------------------------------------
// TenantRegistry
// ---------------------------------------------------------------------------

let _tenantRegistryInstance: TenantRegistryImpl | null = null;

class TenantRegistryImpl {
  private _tenants = new Map<string, Tenant>();

  register(
    tenantId: string,
    name: string,
    metadata: Record<string, unknown> = {}
  ): Tenant {
    if (this._tenants.has(tenantId)) {
      throw new Error(`Tenant '${tenantId}' is already registered.`);
    }
    const tenant: Tenant = {
      tenantId,
      name,
      createdAt: new Date(),
      metadata,
      active: true,
    };
    this._tenants.set(tenantId, tenant);
    return tenant;
  }

  getTenant(tenantId: string): Tenant {
    const t = this._tenants.get(tenantId);
    if (!t) {
      throw new Error(`Tenant '${tenantId}' not found.`);
    }
    return t;
  }

  exists(tenantId: string): boolean {
    return this._tenants.has(tenantId);
  }

  deactivate(tenantId: string): void {
    this.getTenant(tenantId).active = false;
  }

  all(): Tenant[] {
    return [...this._tenants.values()];
  }

  listActive(): Tenant[] {
    return [...this._tenants.values()].filter((t) => t.active);
  }

  clear(): void {
    this._tenants.clear();
  }
}

/**
 * Public access point for the global tenant registry.
 */
export class TenantRegistry {
  static get(): TenantRegistryImpl {
    if (_tenantRegistryInstance === null) {
      _tenantRegistryInstance = new TenantRegistryImpl();
    }
    return _tenantRegistryInstance;
  }
}

// ---------------------------------------------------------------------------
// TenantContext
// ---------------------------------------------------------------------------

/**
 * Scopes all runtime and graph operations to a single tenant.
 * Created per-request/per-run. Never shared across tenants.
 */
export class TenantContext {
  readonly tenantId: string;
  readonly traceId: string;
  readonly environment: string;

  constructor(tenantId: string, traceId: string, environment = "staging") {
    this.tenantId = tenantId;
    this.traceId = traceId;
    this.environment = environment;
  }

  /**
   * Returns the namespaced node type label for graph queries.
   * Prevents cross-tenant graph data from ever mixing.
   *
   * @example graphNamespace("asset") → "tenant__acme__asset"
   */
  graphNamespace(nodeType: string): string {
    const safeId = this.tenantId.replace(/-/g, "_").toLowerCase();
    return `tenant__${safeId}__${nodeType}`;
  }

  /**
   * Raises if the tenant is not active.
   */
  assertActive(registry: TenantRegistryImpl): void {
    const tenant = registry.getTenant(this.tenantId);
    if (!tenant.active) {
      throw new Error(
        `Tenant '${this.tenantId}' is deactivated. Access denied.`
      );
    }
  }
}
