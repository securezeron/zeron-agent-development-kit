// Package policy provides in-process policy enforcement for ZAK agents.
//
// Evaluates agent actions against rules derived from the AgentDSL
// boundaries and safety config.
package policy

import (
	"fmt"
	"strings"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
)

// Decision represents the outcome of a policy evaluation.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// Permit creates a positive policy decision.
func Permit(reason ...string) Decision {
	r := "Action permitted by policy"
	if len(reason) > 0 {
		r = reason[0]
	}
	return Decision{Allowed: true, Reason: r}
}

// Deny creates a negative policy decision.
func Deny(reason string) Decision {
	return Decision{Allowed: false, Reason: reason}
}

// mutatingVerbs are action prefixes that indicate a write/mutate operation.
var mutatingVerbs = []string{
	"write", "delete", "update", "create", "modify", "execute",
}

// highRiskActions require at least medium risk budget.
var highRiskActions = map[string]bool{
	"execute_exploit":   true,
	"deploy_payload":    true,
	"modify_production": true,
}

// Engine evaluates whether an action is permitted for a given agent.
//
// Rules applied in order (first deny wins):
//  1. Explicit deny-list check
//  2. Explicit allow-list check (if allow-list is non-empty)
//  3. Autonomy level constraints
//  4. Risk budget constraints
//  5. Environment scope constraints
//  6. Offensive agent safety constraints
type Engine struct{}

// NewEngine creates a new PolicyEngine.
func NewEngine() *Engine {
	return &Engine{}
}

// Evaluate checks whether action is permitted under dsl constraints.
func (e *Engine) Evaluate(
	agentDSL *dsl.AgentDSL,
	action string,
	environment string,
	metadata map[string]interface{},
) Decision {
	boundaries := agentDSL.Boundaries

	// Rule 1 — Explicit deny-list (always wins)
	for _, denied := range boundaries.DeniedActions {
		if denied == action {
			return Deny(fmt.Sprintf(
				"Action '%s' is explicitly denied by agent boundaries.", action))
		}
	}

	// Rule 2 — Explicit allow-list (if defined, action must be in it)
	if len(boundaries.AllowedActions) > 0 {
		found := false
		for _, allowed := range boundaries.AllowedActions {
			if allowed == action {
				found = true
				break
			}
		}
		if !found {
			return Deny(fmt.Sprintf(
				"Action '%s' is not in the agent's allow-list. Allowed: %v",
				action, boundaries.AllowedActions))
		}
	}

	// Rule 3 — Observe-only agents cannot write/mutate anything
	if agentDSL.Reasoning.AutonomyLevel == dsl.AutonomyObserve {
		lowerAction := strings.ToLower(action)
		for _, verb := range mutatingVerbs {
			if strings.HasPrefix(lowerAction, verb) {
				return Deny(fmt.Sprintf(
					"Action '%s' is a mutating operation. "+
						"Agents with autonomy_level 'observe' are read-only.", action))
			}
		}
	}

	// Rule 4 — Risk budget: high-risk actions require sufficient budget
	if highRiskActions[action] && boundaries.RiskBudget == dsl.RiskBudgetLow {
		return Deny(fmt.Sprintf(
			"Action '%s' requires at least risk_budget: medium. "+
				"Current budget: %s", action, boundaries.RiskBudget))
	}

	// Rule 5 — Environment scope
	if environment != "" && len(boundaries.EnvironmentScope) > 0 {
		found := false
		for _, env := range boundaries.EnvironmentScope {
			if env == environment {
				found = true
				break
			}
		}
		if !found {
			return Deny(fmt.Sprintf(
				"Environment '%s' is not in scope for this agent. "+
					"Allowed environments: %v", environment, boundaries.EnvironmentScope))
		}
	}

	// Rule 6 — Offensive agents: production access denied unless explicitly scoped
	if agentDSL.Agent.Domain == dsl.DomainRedTeam {
		if environment == "production" {
			found := false
			for _, env := range boundaries.EnvironmentScope {
				if env == "production" {
					found = true
					break
				}
			}
			if !found {
				return Deny(
					"Red team agents are not permitted to target production " +
						"unless 'production' is explicitly in environment_scope.")
			}
		}
	}

	return Permit()
}

// CheckApprovalGate returns true if action requires human approval.
func (e *Engine) CheckApprovalGate(agentDSL *dsl.AgentDSL, action string) bool {
	for _, gate := range agentDSL.Boundaries.ApprovalGates {
		if gate == action {
			return true
		}
	}
	return false
}
