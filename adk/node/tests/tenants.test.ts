/**
 * ZAK Tenant Context Tests (Phase 2)
 *
 * Covers:
 * - TenantRegistry register/getTenant/exists
 * - Duplicate registration throws
 * - deactivate/listActive
 * - TenantContext.graphNamespace() produces correct namespace
 * - TenantContext.assertActive() throws for inactive tenants
 * - TenantRegistry.all() returns all tenants
 * - TenantRegistry.clear() empties registry
 * - TenantContext constructor defaults
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  TenantRegistry,
  TenantContext,
  type Tenant,
} from "../src/tenants/context.js";

// ---------------------------------------------------------------------------
// Clear tenant registry before each test
// ---------------------------------------------------------------------------

beforeEach(() => {
  TenantRegistry.get().clear();
});

// ---------------------------------------------------------------------------
// TenantRegistry register/getTenant/exists
// ---------------------------------------------------------------------------
describe("TenantRegistry register/getTenant/exists", () => {
  it("register() creates a new tenant and returns it", () => {
    const tenant = TenantRegistry.get().register("acme", "Acme Corp");
    expect(tenant.tenantId).toBe("acme");
    expect(tenant.name).toBe("Acme Corp");
    expect(tenant.active).toBe(true);
  });

  it("register() sets createdAt to a Date", () => {
    const before = new Date();
    const tenant = TenantRegistry.get().register("acme", "Acme Corp");
    const after = new Date();
    expect(tenant.createdAt).toBeInstanceOf(Date);
    expect(tenant.createdAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
    expect(tenant.createdAt.getTime()).toBeLessThanOrEqual(after.getTime());
  });

  it("register() sets default empty metadata", () => {
    const tenant = TenantRegistry.get().register("acme", "Acme Corp");
    expect(tenant.metadata).toEqual({});
  });

  it("register() accepts custom metadata", () => {
    const tenant = TenantRegistry.get().register("acme", "Acme Corp", {
      plan: "enterprise",
      region: "us-east-1",
    });
    expect(tenant.metadata).toEqual({
      plan: "enterprise",
      region: "us-east-1",
    });
  });

  it("getTenant() returns the registered tenant", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    const tenant = TenantRegistry.get().getTenant("acme");
    expect(tenant.tenantId).toBe("acme");
    expect(tenant.name).toBe("Acme Corp");
  });

  it("getTenant() throws for unknown tenant", () => {
    expect(() => TenantRegistry.get().getTenant("nonexistent")).toThrow(
      "Tenant 'nonexistent' not found"
    );
  });

  it("exists() returns true for registered tenant", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    expect(TenantRegistry.get().exists("acme")).toBe(true);
  });

  it("exists() returns false for unregistered tenant", () => {
    expect(TenantRegistry.get().exists("unknown")).toBe(false);
  });

  it("exists() returns false after clear()", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    TenantRegistry.get().clear();
    expect(TenantRegistry.get().exists("acme")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Duplicate registration throws
// ---------------------------------------------------------------------------
describe("Duplicate registration throws", () => {
  it("throws when registering a tenant with the same ID", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    expect(() =>
      TenantRegistry.get().register("acme", "Acme Corp Again")
    ).toThrow("Tenant 'acme' is already registered");
  });

  it("error message includes the tenant ID", () => {
    TenantRegistry.get().register("globex", "Globex Corp");
    expect(() =>
      TenantRegistry.get().register("globex", "Globex Again")
    ).toThrow("globex");
  });

  it("allows registering different tenant IDs", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    expect(() =>
      TenantRegistry.get().register("globex", "Globex Corp")
    ).not.toThrow();
  });

  it("allows re-registering after clear()", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    TenantRegistry.get().clear();
    expect(() =>
      TenantRegistry.get().register("acme", "Acme Corp Re-registered")
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// deactivate/listActive
// ---------------------------------------------------------------------------
describe("deactivate/listActive", () => {
  it("deactivate() sets tenant.active to false", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    TenantRegistry.get().deactivate("acme");
    const tenant = TenantRegistry.get().getTenant("acme");
    expect(tenant.active).toBe(false);
  });

  it("deactivate() throws for unknown tenant", () => {
    expect(() => TenantRegistry.get().deactivate("nonexistent")).toThrow(
      "Tenant 'nonexistent' not found"
    );
  });

  it("listActive() returns only active tenants", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    TenantRegistry.get().register("globex", "Globex Corp");
    TenantRegistry.get().register("initech", "Initech");

    TenantRegistry.get().deactivate("globex");

    const active = TenantRegistry.get().listActive();
    expect(active).toHaveLength(2);
    const ids = active.map((t) => t.tenantId);
    expect(ids).toContain("acme");
    expect(ids).toContain("initech");
    expect(ids).not.toContain("globex");
  });

  it("listActive() returns empty array when all are deactivated", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    TenantRegistry.get().deactivate("acme");
    expect(TenantRegistry.get().listActive()).toEqual([]);
  });

  it("listActive() returns all tenants when none are deactivated", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    TenantRegistry.get().register("globex", "Globex Corp");
    expect(TenantRegistry.get().listActive()).toHaveLength(2);
  });

  it("listActive() returns empty array when registry is empty", () => {
    expect(TenantRegistry.get().listActive()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// TenantRegistry.all()
// ---------------------------------------------------------------------------
describe("TenantRegistry.all()", () => {
  it("returns all tenants including inactive ones", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    TenantRegistry.get().register("globex", "Globex Corp");
    TenantRegistry.get().deactivate("globex");

    const all = TenantRegistry.get().all();
    expect(all).toHaveLength(2);
    const ids = all.map((t) => t.tenantId);
    expect(ids).toContain("acme");
    expect(ids).toContain("globex");
  });

  it("returns empty array when no tenants registered", () => {
    expect(TenantRegistry.get().all()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// TenantRegistry.clear()
// ---------------------------------------------------------------------------
describe("TenantRegistry.clear()", () => {
  it("removes all tenants", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    TenantRegistry.get().register("globex", "Globex Corp");
    TenantRegistry.get().clear();
    expect(TenantRegistry.get().all()).toEqual([]);
  });

  it("exists returns false after clear", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    TenantRegistry.get().clear();
    expect(TenantRegistry.get().exists("acme")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// TenantContext.graphNamespace() produces correct namespace
// ---------------------------------------------------------------------------
describe("TenantContext.graphNamespace()", () => {
  it("produces tenant__<id>__<nodeType> format", () => {
    const ctx = new TenantContext("acme", "trace-001");
    expect(ctx.graphNamespace("asset")).toBe("tenant__acme__asset");
  });

  it("replaces hyphens with underscores in tenant ID", () => {
    const ctx = new TenantContext("acme-corp", "trace-001");
    expect(ctx.graphNamespace("vulnerability")).toBe(
      "tenant__acme_corp__vulnerability"
    );
  });

  it("lowercases the tenant ID", () => {
    const ctx = new TenantContext("AcmeCorp", "trace-001");
    expect(ctx.graphNamespace("asset")).toBe("tenant__acmecorp__asset");
  });

  it("handles multiple hyphens in tenant ID", () => {
    const ctx = new TenantContext("us-east-1-acme", "trace-001");
    expect(ctx.graphNamespace("node")).toBe("tenant__us_east_1_acme__node");
  });

  it("handles various node types", () => {
    const ctx = new TenantContext("acme", "trace-001");
    expect(ctx.graphNamespace("vulnerability")).toBe(
      "tenant__acme__vulnerability"
    );
    expect(ctx.graphNamespace("finding")).toBe("tenant__acme__finding");
    expect(ctx.graphNamespace("identity")).toBe("tenant__acme__identity");
  });

  it("handles UUID-style tenant IDs", () => {
    const ctx = new TenantContext(
      "550e8400-e29b-41d4-a716-446655440000",
      "trace-001"
    );
    const ns = ctx.graphNamespace("asset");
    expect(ns).toBe(
      "tenant__550e8400_e29b_41d4_a716_446655440000__asset"
    );
    expect(ns).not.toContain("-");
  });
});

// ---------------------------------------------------------------------------
// TenantContext.assertActive() throws for inactive tenants
// ---------------------------------------------------------------------------
describe("TenantContext.assertActive()", () => {
  it("does not throw for active tenants", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    const ctx = new TenantContext("acme", "trace-001");
    expect(() => ctx.assertActive(TenantRegistry.get())).not.toThrow();
  });

  it("throws for deactivated tenants", () => {
    TenantRegistry.get().register("acme", "Acme Corp");
    TenantRegistry.get().deactivate("acme");
    const ctx = new TenantContext("acme", "trace-001");
    expect(() => ctx.assertActive(TenantRegistry.get())).toThrow(
      "Tenant 'acme' is deactivated. Access denied."
    );
  });

  it("throws for unregistered tenants (getTenant fails)", () => {
    const ctx = new TenantContext("unknown", "trace-001");
    expect(() => ctx.assertActive(TenantRegistry.get())).toThrow(
      "Tenant 'unknown' not found"
    );
  });

  it("error message includes the tenant ID", () => {
    TenantRegistry.get().register("globex", "Globex Corp");
    TenantRegistry.get().deactivate("globex");
    const ctx = new TenantContext("globex", "trace-001");
    expect(() => ctx.assertActive(TenantRegistry.get())).toThrow("globex");
  });
});

// ---------------------------------------------------------------------------
// TenantContext constructor
// ---------------------------------------------------------------------------
describe("TenantContext constructor", () => {
  it("sets tenantId correctly", () => {
    const ctx = new TenantContext("acme", "trace-001");
    expect(ctx.tenantId).toBe("acme");
  });

  it("sets traceId correctly", () => {
    const ctx = new TenantContext("acme", "trace-001");
    expect(ctx.traceId).toBe("trace-001");
  });

  it("defaults environment to 'staging'", () => {
    const ctx = new TenantContext("acme", "trace-001");
    expect(ctx.environment).toBe("staging");
  });

  it("accepts custom environment", () => {
    const ctx = new TenantContext("acme", "trace-001", "production");
    expect(ctx.environment).toBe("production");
  });

  it("properties are readonly", () => {
    const ctx = new TenantContext("acme", "trace-001", "staging");
    // TypeScript enforces this at compile time. At runtime, we verify the values
    // are set and accessible.
    expect(ctx.tenantId).toBe("acme");
    expect(ctx.traceId).toBe("trace-001");
    expect(ctx.environment).toBe("staging");
  });
});

// ---------------------------------------------------------------------------
// TenantRegistry singleton
// ---------------------------------------------------------------------------
describe("TenantRegistry.get() singleton", () => {
  it("returns the same instance across calls", () => {
    const r1 = TenantRegistry.get();
    const r2 = TenantRegistry.get();
    expect(r1).toBe(r2);
  });
});

// ---------------------------------------------------------------------------
// Integration: register, deactivate, assertActive
// ---------------------------------------------------------------------------
describe("Integration: register -> deactivate -> assertActive", () => {
  it("full lifecycle works correctly", () => {
    // Register
    const tenant = TenantRegistry.get().register("lifecycle-test", "Lifecycle");
    expect(tenant.active).toBe(true);

    // Assert active (should succeed)
    const ctx = new TenantContext("lifecycle-test", "trace-lc");
    expect(() => ctx.assertActive(TenantRegistry.get())).not.toThrow();

    // Verify namespace
    expect(ctx.graphNamespace("asset")).toBe(
      "tenant__lifecycle_test__asset"
    );

    // Deactivate
    TenantRegistry.get().deactivate("lifecycle-test");

    // Assert active (should fail)
    expect(() => ctx.assertActive(TenantRegistry.get())).toThrow(
      "deactivated"
    );

    // Tenant still exists
    expect(TenantRegistry.get().exists("lifecycle-test")).toBe(true);

    // But not in active list
    const active = TenantRegistry.get().listActive();
    expect(active.map((t) => t.tenantId)).not.toContain("lifecycle-test");
  });
});
