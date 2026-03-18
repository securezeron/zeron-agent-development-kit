package tenants

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func registryCleanup(t *testing.T) {
	t.Cleanup(func() {
		RegistryGet().Clear()
	})
}

// ===========================================================================
// Registry tests
// ===========================================================================

func TestRegistry_Register_CreatesTenant(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	tenant, err := reg.Register("acme", "Acme Corp", map[string]interface{}{"tier": "gold"})

	require.NoError(t, err)
	require.NotNil(t, tenant)

	assert.Equal(t, "acme", tenant.TenantID)
	assert.Equal(t, "Acme Corp", tenant.Name)
	assert.True(t, tenant.Active, "new tenants should be active by default")
	assert.False(t, tenant.CreatedAt.IsZero(), "CreatedAt should be set")
	assert.Equal(t, "gold", tenant.Metadata["tier"])
}

func TestRegistry_Register_NilMetadata(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	tenant, err := reg.Register("tenant-nil-meta", "Nil Meta Corp", nil)

	require.NoError(t, err)
	require.NotNil(t, tenant)
	assert.NotNil(t, tenant.Metadata, "nil metadata should be initialized to empty map")
	assert.Empty(t, tenant.Metadata)
}

func TestRegistry_GetTenant_ReturnsTenant(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, err := reg.Register("acme", "Acme Corp", nil)
	require.NoError(t, err)

	tenant, err := reg.GetTenant("acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", tenant.TenantID)
	assert.Equal(t, "Acme Corp", tenant.Name)
}

func TestRegistry_GetTenant_NotFound(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, err := reg.GetTenant("nonexistent")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
	assert.Contains(t, err.Error(), "not found")
}

func TestRegistry_Exists(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	assert.False(t, reg.Exists("acme"))

	_, err := reg.Register("acme", "Acme Corp", nil)
	require.NoError(t, err)

	assert.True(t, reg.Exists("acme"))
	assert.False(t, reg.Exists("other"))
}

func TestRegistry_DuplicateRegistration_ReturnsError(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, err := reg.Register("acme", "Acme Corp", nil)
	require.NoError(t, err)

	_, err = reg.Register("acme", "Acme Corp Duplicate", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acme")
	assert.Contains(t, err.Error(), "already registered")
}

func TestRegistry_Deactivate(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, err := reg.Register("acme", "Acme Corp", nil)
	require.NoError(t, err)

	err = reg.Deactivate("acme")
	require.NoError(t, err)

	tenant, err := reg.GetTenant("acme")
	require.NoError(t, err)
	assert.False(t, tenant.Active, "deactivated tenant should have Active=false")
}

func TestRegistry_Deactivate_NotFound(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	err := reg.Deactivate("nonexistent")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
	assert.Contains(t, err.Error(), "not found")
}

func TestRegistry_ListActive(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, err := reg.Register("active-1", "Active One", nil)
	require.NoError(t, err)
	_, err = reg.Register("active-2", "Active Two", nil)
	require.NoError(t, err)
	_, err = reg.Register("inactive-1", "Inactive One", nil)
	require.NoError(t, err)

	err = reg.Deactivate("inactive-1")
	require.NoError(t, err)

	active := reg.ListActive()
	assert.Len(t, active, 2)

	activeIDs := make([]string, len(active))
	for i, t := range active {
		activeIDs[i] = t.TenantID
	}
	assert.Contains(t, activeIDs, "active-1")
	assert.Contains(t, activeIDs, "active-2")
	assert.NotContains(t, activeIDs, "inactive-1")
}

func TestRegistry_All(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, _ = reg.Register("t1", "Tenant 1", nil)
	_, _ = reg.Register("t2", "Tenant 2", nil)
	_, _ = reg.Register("t3", "Tenant 3", nil)

	_ = reg.Deactivate("t2")

	all := reg.All()
	assert.Len(t, all, 3, "All() should return all tenants regardless of active status")
}

func TestRegistry_Clear(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, _ = reg.Register("t1", "Tenant 1", nil)
	_, _ = reg.Register("t2", "Tenant 2", nil)
	require.True(t, reg.Exists("t1"))
	require.True(t, reg.Exists("t2"))

	reg.Clear()
	assert.False(t, reg.Exists("t1"))
	assert.False(t, reg.Exists("t2"))
	assert.Empty(t, reg.All())
}

// ===========================================================================
// Context tests
// ===========================================================================

func TestNewContext_Defaults(t *testing.T) {
	ctx := NewContext("acme", "trace-123")

	assert.Equal(t, "acme", ctx.TenantID)
	assert.Equal(t, "trace-123", ctx.TraceID)
	assert.Equal(t, "staging", ctx.Environment, "default environment should be 'staging'")
}

func TestNewContext_WithEnvironment(t *testing.T) {
	ctx := NewContext("acme", "trace-456", "production")

	assert.Equal(t, "production", ctx.Environment)
}

func TestNewContext_EmptyEnvironmentFallsBackToDefault(t *testing.T) {
	ctx := NewContext("acme", "trace-789", "")

	assert.Equal(t, "staging", ctx.Environment, "empty string should fall back to staging")
}

func TestContext_GraphNamespace(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		nodeType string
		expected string
	}{
		{
			name:     "simple tenant ID",
			tenantID: "acme",
			nodeType: "asset",
			expected: "tenant__acme__asset",
		},
		{
			name:     "tenant ID with hyphens",
			tenantID: "acme-corp",
			nodeType: "vulnerability",
			expected: "tenant__acme_corp__vulnerability",
		},
		{
			name:     "tenant ID with multiple hyphens",
			tenantID: "my-big-tenant",
			nodeType: "host",
			expected: "tenant__my_big_tenant__host",
		},
		{
			name:     "uppercase tenant ID is lowercased",
			tenantID: "AcMe",
			nodeType: "service",
			expected: "tenant__acme__service",
		},
		{
			name:     "mixed case with hyphens",
			tenantID: "Acme-Corp-Labs",
			nodeType: "finding",
			expected: "tenant__acme_corp_labs__finding",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := NewContext(tc.tenantID, "trace-1")
			result := ctx.GraphNamespace(tc.nodeType)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestContext_AssertActive_ActiveTenant(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, err := reg.Register("acme", "Acme Corp", nil)
	require.NoError(t, err)

	ctx := NewContext("acme", "trace-1")
	err = ctx.AssertActive(reg)
	assert.NoError(t, err, "active tenant should pass AssertActive")
}

func TestContext_AssertActive_InactiveTenant(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, err := reg.Register("acme", "Acme Corp", nil)
	require.NoError(t, err)

	err = reg.Deactivate("acme")
	require.NoError(t, err)

	ctx := NewContext("acme", "trace-2")
	err = ctx.AssertActive(reg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "acme")
	assert.Contains(t, err.Error(), "deactivated")
}

func TestContext_AssertActive_NonexistentTenant(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	ctx := NewContext("nonexistent", "trace-3")
	err := ctx.AssertActive(reg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
	assert.Contains(t, err.Error(), "not found")
}

// ===========================================================================
// Edge cases
// ===========================================================================

func TestRegistry_MultipleTenants_Independent(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, err := reg.Register("t1", "Tenant 1", map[string]interface{}{"level": 1})
	require.NoError(t, err)
	_, err = reg.Register("t2", "Tenant 2", map[string]interface{}{"level": 2})
	require.NoError(t, err)

	t1, err := reg.GetTenant("t1")
	require.NoError(t, err)
	t2, err := reg.GetTenant("t2")
	require.NoError(t, err)

	assert.Equal(t, 1, t1.Metadata["level"])
	assert.Equal(t, 2, t2.Metadata["level"])
}

func TestRegistry_Deactivate_DoesNotAffectOtherTenants(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, _ = reg.Register("t1", "Tenant 1", nil)
	_, _ = reg.Register("t2", "Tenant 2", nil)

	err := reg.Deactivate("t1")
	require.NoError(t, err)

	t1, _ := reg.GetTenant("t1")
	t2, _ := reg.GetTenant("t2")

	assert.False(t, t1.Active)
	assert.True(t, t2.Active, "deactivating t1 should not affect t2")
}

func TestRegistry_ListActive_EmptyRegistry(t *testing.T) {
	registryCleanup(t)

	active := RegistryGet().ListActive()
	assert.Empty(t, active)
}

func TestRegistry_ListActive_AllDeactivated(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, _ = reg.Register("t1", "Tenant 1", nil)
	_, _ = reg.Register("t2", "Tenant 2", nil)

	_ = reg.Deactivate("t1")
	_ = reg.Deactivate("t2")

	active := reg.ListActive()
	assert.Empty(t, active)
}

func TestContext_GraphNamespace_EmptyNodeType(t *testing.T) {
	ctx := NewContext("acme", "trace-1")
	result := ctx.GraphNamespace("")
	assert.Equal(t, "tenant__acme__", result)
}

func TestNewContext_MultipleEnvironmentArgs(t *testing.T) {
	// Only the first environment argument is used.
	ctx := NewContext("acme", "trace-1", "production", "dev")
	assert.Equal(t, "production", ctx.Environment)
}

func TestRegistry_RegisterAfterClear(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	_, _ = reg.Register("old-tenant", "Old", nil)
	reg.Clear()

	_, err := reg.Register("new-tenant", "New", nil)
	require.NoError(t, err)
	assert.True(t, reg.Exists("new-tenant"))
	assert.False(t, reg.Exists("old-tenant"))
}

func TestRegistry_MetadataIsPreserved(t *testing.T) {
	registryCleanup(t)

	reg := RegistryGet()
	meta := map[string]interface{}{
		"plan":    "enterprise",
		"seats":   100,
		"enabled": true,
	}
	_, err := reg.Register("meta-tenant", "Meta Corp", meta)
	require.NoError(t, err)

	tenant, err := reg.GetTenant("meta-tenant")
	require.NoError(t, err)
	assert.Equal(t, "enterprise", tenant.Metadata["plan"])
	assert.Equal(t, 100, tenant.Metadata["seats"])
	assert.Equal(t, true, tenant.Metadata["enabled"])
}
