// Package tenants provides multi-tenancy support: TenantRegistry,
// TenantContext, and isolation utilities.
package tenants

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Tenant represents a registered tenant in the ZAK platform.
type Tenant struct {
	TenantID  string                 `json:"tenant_id"`
	Name      string                 `json:"name"`
	CreatedAt time.Time              `json:"created_at"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Active    bool                   `json:"active"`
}

// Registry is the in-memory tenant registry.
type Registry struct {
	mu      sync.RWMutex
	tenants map[string]*Tenant
}

var (
	globalTenantRegistry     *Registry
	globalTenantRegistryOnce sync.Once
)

// RegistryGet returns the global tenant registry singleton.
func RegistryGet() *Registry {
	globalTenantRegistryOnce.Do(func() {
		globalTenantRegistry = &Registry{
			tenants: make(map[string]*Tenant),
		}
	})
	return globalTenantRegistry
}

// Register adds a new tenant. Returns an error if tenant_id already exists.
func (r *Registry) Register(tenantID, name string, metadata map[string]interface{}) (*Tenant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tenants[tenantID]; exists {
		return nil, fmt.Errorf("tenant '%s' is already registered", tenantID)
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	t := &Tenant{
		TenantID:  tenantID,
		Name:      name,
		CreatedAt: time.Now().UTC(),
		Metadata:  metadata,
		Active:    true,
	}
	r.tenants[tenantID] = t
	return t, nil
}

// GetTenant retrieves a tenant by ID. Returns an error if not found.
func (r *Registry) GetTenant(tenantID string) (*Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tenants[tenantID]
	if !ok {
		return nil, fmt.Errorf("tenant '%s' not found", tenantID)
	}
	return t, nil
}

// Exists returns true if a tenant is registered.
func (r *Registry) Exists(tenantID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.tenants[tenantID]
	return ok
}

// Deactivate marks a tenant as inactive.
func (r *Registry) Deactivate(tenantID string) error {
	t, err := r.GetTenant(tenantID)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t.Active = false
	return nil
}

// All returns all registered tenants.
func (r *Registry) All() []*Tenant {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*Tenant, 0, len(r.tenants))
	for _, t := range r.tenants {
		result = append(result, t)
	}
	return result
}

// ListActive returns only active tenants.
func (r *Registry) ListActive() []*Tenant {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*Tenant
	for _, t := range r.tenants {
		if t.Active {
			result = append(result, t)
		}
	}
	return result
}

// Clear removes all tenants (for tests).
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenants = make(map[string]*Tenant)
}

// Context scopes all runtime and graph operations to a single tenant.
type Context struct {
	TenantID    string
	TraceID     string
	Environment string
}

// NewContext creates a new TenantContext.
func NewContext(tenantID, traceID string, environment ...string) *Context {
	env := "staging"
	if len(environment) > 0 && environment[0] != "" {
		env = environment[0]
	}
	return &Context{
		TenantID:    tenantID,
		TraceID:     traceID,
		Environment: env,
	}
}

// GraphNamespace returns the namespaced node type label for graph queries.
// Prevents cross-tenant graph data from ever mixing.
//
// Example: GraphNamespace("asset") → "tenant__acme__asset"
func (c *Context) GraphNamespace(nodeType string) string {
	safeID := strings.ToLower(strings.ReplaceAll(c.TenantID, "-", "_"))
	return fmt.Sprintf("tenant__%s__%s", safeID, nodeType)
}

// AssertActive raises an error if the tenant is not active.
func (c *Context) AssertActive(registry *Registry) error {
	t, err := registry.GetTenant(c.TenantID)
	if err != nil {
		return err
	}
	if !t.Active {
		return fmt.Errorf("tenant '%s' is deactivated. Access denied", c.TenantID)
	}
	return nil
}
