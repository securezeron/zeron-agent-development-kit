// Package audit provides structured audit event logging for the ZAK Agent
// Development Kit.
//
// All security-relevant actions — agent starts, tool executions, policy
// decisions, and errors — are emitted as typed audit events with structured
// JSON output via zerolog.
//
// # Event Types
//
// 13 event types are defined covering the full agent lifecycle:
//   - agent_started, agent_completed, agent_failed
//   - tool_invoked, tool_completed, tool_failed
//   - policy_evaluated, policy_denied
//   - llm_request, llm_response
//   - escalation_triggered, context_switched, custom
//
// # Usage
//
//	logger := audit.NewLogger(nil)
//	evt := audit.NewToolInvokedEvent("scan_code", "agent-1", map[string]any{"target": "repo"})
//	logger.Log(evt)
package audit
