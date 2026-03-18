// Package policy provides the runtime policy engine for the ZAK Agent
// Development Kit.
//
// The engine evaluates whether an agent is allowed to perform a specific action
// in a given environment by applying a 6-rule evaluation chain:
//
//  1. Deny-list — explicitly denied actions are always blocked
//  2. Allow-list — if defined, only listed actions are permitted
//  3. Autonomy — fully autonomous agents bypass approval requirements
//  4. Risk budget — actions consuming risk budget are checked against limits
//  5. Environment — production restrictions are enforced
//  6. Red-team — offensive agents are restricted to isolated sandboxes
//
// # Usage
//
//	engine := policy.NewEngine()
//	decision := engine.Evaluate(agentDSL, "scan_code", "production", nil)
//	if !decision.Allowed {
//	    log.Printf("Policy denied: %s", decision.Reason)
//	}
package policy
