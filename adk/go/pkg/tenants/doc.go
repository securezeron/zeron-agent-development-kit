// Package tenants provides multi-tenant context and namespace isolation for
// the ZAK Agent Development Kit.
//
// Each tenant gets an isolated namespace for graph data, audit logs, and agent
// execution. The [Registry] manages tenant contexts globally, and the [Context]
// type provides tenant-scoped configuration.
//
// # Usage
//
//	ctx := tenants.NewContext("acme-corp")
//	ns := ctx.GraphNamespace() // "tenant_acme_corp"
//
//	reg := tenants.NewRegistry()
//	reg.Register(ctx)
//	t, ok := reg.Resolve("acme-corp")
package tenants
