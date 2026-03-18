package runtime

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/edition"
)

// AgentRegistration holds metadata for a single registered agent.
type AgentRegistration struct {
	Domain      string
	Factory     AgentFactory
	Description string
	Version     string
	Edition     string
	ClassName   string
}

// AgentFactory is a function that creates a new BaseAgent instance.
type AgentFactory func() BaseAgent

// agentRegistry is the internal singleton registry.
type agentRegistry struct {
	mu       sync.RWMutex
	registry map[string][]*AgentRegistration
}

var (
	globalRegistry     *agentRegistry
	globalRegistryOnce sync.Once
)

func getGlobalRegistry() *agentRegistry {
	globalRegistryOnce.Do(func() {
		globalRegistry = &agentRegistry{
			registry: make(map[string][]*AgentRegistration),
		}
	})
	return globalRegistry
}

// RegisterAgent registers an agent factory under a domain.
func RegisterAgent(domain string, factory AgentFactory, opts ...RegisterOption) *AgentRegistration {
	return AgentRegistryGet().Register(domain, factory, opts...)
}

// RegisterOption configures agent registration.
type RegisterOption func(*registerConfig)

type registerConfig struct {
	description string
	version     string
	edition     string
	override    bool
	className   string
}

// WithDescription sets the agent description.
func WithDescription(desc string) RegisterOption {
	return func(c *registerConfig) { c.description = desc }
}

// WithVersion sets the agent version.
func WithVersion(v string) RegisterOption {
	return func(c *registerConfig) { c.version = v }
}

// WithEdition sets the agent edition ("open-source" or "enterprise").
func WithEdition(e string) RegisterOption {
	return func(c *registerConfig) { c.edition = e }
}

// WithOverride makes this the primary agent for the domain.
func WithOverride() RegisterOption {
	return func(c *registerConfig) { c.override = true }
}

// WithClassName sets the display class name.
func WithClassName(name string) RegisterOption {
	return func(c *registerConfig) { c.className = name }
}

// AgentRegistryGet returns the global agent registry singleton.
func AgentRegistryGet() *agentRegistry {
	return getGlobalRegistry()
}

// Register adds an agent factory under a domain.
func (r *agentRegistry) Register(domain string, factory AgentFactory, opts ...RegisterOption) *AgentRegistration {
	cfg := &registerConfig{
		version:   "1.0.0",
		edition:   "enterprise",
		className: "Agent",
	}
	for _, o := range opts {
		o(cfg)
	}

	reg := &AgentRegistration{
		Domain:      domain,
		Factory:     factory,
		Description: cfg.description,
		Version:     cfg.version,
		Edition:     cfg.edition,
		ClassName:   cfg.className,
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if cfg.override {
		r.registry[domain] = append([]*AgentRegistration{reg}, r.registry[domain]...)
	} else {
		r.registry[domain] = append(r.registry[domain], reg)
	}

	return reg
}

// Resolve returns the primary agent factory for a domain.
func (r *agentRegistry) Resolve(domain string) (AgentFactory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries := r.registry[domain]
	if len(entries) == 0 {
		domains := make([]string, 0, len(r.registry))
		for d := range r.registry {
			domains = append(domains, d)
		}
		return nil, fmt.Errorf("no agent registered for domain '%s'. Available domains: [%s]",
			domain, strings.Join(domains, ", "))
	}

	reg := entries[0]
	if reg.Edition == "enterprise" && !edition.IsEnterprise() {
		return nil, edition.NewError(
			fmt.Sprintf("Agent '%s' is available in the enterprise edition only", domain))
	}

	return reg.Factory, nil
}

// ResolveAll returns all registrations for a domain.
func (r *agentRegistry) ResolveAll(domain string) []*AgentRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries := r.registry[domain]
	result := make([]*AgentRegistration, len(entries))
	copy(result, entries)
	return result
}

// AllDomains returns sorted domains accessible in the current edition.
func (r *agentRegistry) AllDomains() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	current := edition.GetEdition()
	var domains []string
	for domain, regs := range r.registry {
		if len(regs) > 0 && (current == edition.Enterprise || regs[0].Edition == "open-source") {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	return domains
}

// AllRegistrations returns registrations accessible in the current edition.
func (r *agentRegistry) AllRegistrations() []*AgentRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	current := edition.GetEdition()
	var result []*AgentRegistration
	for _, regs := range r.registry {
		for _, reg := range regs {
			if current == edition.Enterprise || reg.Edition == "open-source" {
				result = append(result, reg)
			}
		}
	}
	return result
}

// AllRegistrationsUnfiltered returns all registrations regardless of edition.
func (r *agentRegistry) AllRegistrationsUnfiltered() []*AgentRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*AgentRegistration
	for _, regs := range r.registry {
		result = append(result, regs...)
	}
	return result
}

// IsRegistered returns true if a domain has at least one registration.
func (r *agentRegistry) IsRegistered(domain string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.registry[domain]) > 0
}

// Unregister removes registrations for a domain.
// If factory is nil, removes all registrations for the domain.
func (r *agentRegistry) Unregister(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.registry, domain)
}

// Clear removes all registrations (for tests).
func (r *agentRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registry = make(map[string][]*AgentRegistration)
}

// Summary returns a human-readable summary of all registrations.
func (r *agentRegistry) Summary() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.registry) == 0 {
		return "No agents registered."
	}

	lines := []string{"Registered agents:"}
	for _, domain := range r.AllDomains() {
		regs := r.registry[domain]
		primary := regs[0]
		extras := ""
		if len(regs) > 1 {
			extras = fmt.Sprintf(" (+%d alternatives)", len(regs)-1)
		}
		lines = append(lines, fmt.Sprintf("  %-20s → %s%s", domain, primary.ClassName, extras))
	}
	return strings.Join(lines, "\n")
}
