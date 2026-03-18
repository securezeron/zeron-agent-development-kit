// Package audit provides typed event definitions and structured logging
// for the ZAK agent audit trail.
//
// All events carry: EventType, AgentID, TenantID, TraceID, Timestamp.
package audit

import "time"

// EventType identifies the category of audit event (13 types).
type EventType string

const (
	AgentStarted           EventType = "agent.started"
	AgentCompleted         EventType = "agent.completed"
	AgentFailed            EventType = "agent.failed"
	ToolCalled             EventType = "agent.tool_called"
	ToolResult             EventType = "agent.tool_result"
	DecisionMade           EventType = "agent.decision"
	PolicyAllowed          EventType = "policy.allowed"
	PolicyBlocked          EventType = "policy.blocked"
	GraphRead              EventType = "sif.graph_read"
	GraphWrite             EventType = "sif.graph_write"
	HumanApprovalRequested EventType = "governance.approval_requested"
	HumanApprovalGranted   EventType = "governance.approval_granted"
	HumanApprovalDenied    EventType = "governance.approval_denied"
)

// Event is the base immutable structured audit log entry.
type Event struct {
	EventType EventType              `json:"event_type"`
	AgentID   string                 `json:"agent_id"`
	TenantID  string                 `json:"tenant_id"`
	TraceID   string                 `json:"trace_id"`
	Timestamp time.Time              `json:"timestamp"`
	Payload   map[string]interface{} `json:"payload,omitempty"`
}

// NewEvent creates a new audit event with the current timestamp.
func NewEvent(eventType EventType, agentID, tenantID, traceID string) *Event {
	return &Event{
		EventType: eventType,
		AgentID:   agentID,
		TenantID:  tenantID,
		TraceID:   traceID,
		Timestamp: time.Now().UTC(),
		Payload:   make(map[string]interface{}),
	}
}

// WithPayload adds key-value pairs to the event payload.
func (e *Event) WithPayload(key string, value interface{}) *Event {
	e.Payload[key] = value
	return e
}

// AgentStartedEvent creates an agent.started event.
func AgentStartedEvent(agentID, tenantID, traceID string) *Event {
	return NewEvent(AgentStarted, agentID, tenantID, traceID)
}

// AgentCompletedEvent creates an agent.completed event with success and duration.
func AgentCompletedEvent(agentID, tenantID, traceID string, success bool, durationMs float64) *Event {
	e := NewEvent(AgentCompleted, agentID, tenantID, traceID)
	e.Payload["success"] = success
	e.Payload["duration_ms"] = durationMs
	return e
}

// AgentFailedEvent creates an agent.failed event with error message.
func AgentFailedEvent(agentID, tenantID, traceID, errMsg string) *Event {
	e := NewEvent(AgentFailed, agentID, tenantID, traceID)
	e.Payload["error"] = errMsg
	return e
}

// PolicyBlockedEvent creates a policy.blocked event.
func PolicyBlockedEvent(agentID, tenantID, traceID, action, reason string) *Event {
	e := NewEvent(PolicyBlocked, agentID, tenantID, traceID)
	e.Payload["action"] = action
	e.Payload["reason"] = reason
	return e
}

// ToolCalledEvent creates an agent.tool_called event.
func ToolCalledEvent(agentID, tenantID, traceID, toolName, inputSummary string) *Event {
	e := NewEvent(ToolCalled, agentID, tenantID, traceID)
	e.Payload["tool_name"] = toolName
	e.Payload["input_summary"] = inputSummary
	return e
}

// GraphWriteEvent creates a sif.graph_write event.
func GraphWriteEvent(agentID, tenantID, traceID, nodeType, nodeID, operation string) *Event {
	e := NewEvent(GraphWrite, agentID, tenantID, traceID)
	e.Payload["node_type"] = nodeType
	e.Payload["node_id"] = nodeID
	e.Payload["operation"] = operation
	return e
}
