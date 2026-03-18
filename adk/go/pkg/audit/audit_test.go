package audit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Event factory functions — correct types and fields
// ---------------------------------------------------------------------------

func TestNewEvent_CreatesCorrectType(t *testing.T) {
	e := NewEvent(AgentStarted, "agent-1", "tenant-1", "trace-1")

	assert.Equal(t, AgentStarted, e.EventType)
	assert.Equal(t, "agent-1", e.AgentID)
	assert.Equal(t, "tenant-1", e.TenantID)
	assert.Equal(t, "trace-1", e.TraceID)
	assert.NotNil(t, e.Payload)
	assert.WithinDuration(t, time.Now().UTC(), e.Timestamp, 2*time.Second)
}

func TestNewEvent_WithPayload(t *testing.T) {
	e := NewEvent(ToolCalled, "agent-1", "tenant-1", "trace-1").
		WithPayload("tool_name", "nmap").
		WithPayload("status", "running")

	assert.Equal(t, "nmap", e.Payload["tool_name"])
	assert.Equal(t, "running", e.Payload["status"])
}

func TestAgentStartedEvent(t *testing.T) {
	e := AgentStartedEvent("agent-1", "tenant-1", "trace-1")
	assert.Equal(t, AgentStarted, e.EventType)
	assert.Equal(t, "agent-1", e.AgentID)
	assert.Equal(t, "tenant-1", e.TenantID)
	assert.Equal(t, "trace-1", e.TraceID)
}

func TestAgentCompletedEvent(t *testing.T) {
	e := AgentCompletedEvent("agent-1", "tenant-1", "trace-1", true, 1234.5)
	assert.Equal(t, AgentCompleted, e.EventType)
	assert.Equal(t, true, e.Payload["success"])
	assert.Equal(t, 1234.5, e.Payload["duration_ms"])
}

func TestAgentCompletedEvent_Failure(t *testing.T) {
	e := AgentCompletedEvent("agent-1", "tenant-1", "trace-1", false, 500.0)
	assert.Equal(t, AgentCompleted, e.EventType)
	assert.Equal(t, false, e.Payload["success"])
	assert.Equal(t, 500.0, e.Payload["duration_ms"])
}

func TestAgentFailedEvent(t *testing.T) {
	e := AgentFailedEvent("agent-1", "tenant-1", "trace-1", "timeout exceeded")
	assert.Equal(t, AgentFailed, e.EventType)
	assert.Equal(t, "timeout exceeded", e.Payload["error"])
}

func TestPolicyBlockedEvent(t *testing.T) {
	e := PolicyBlockedEvent("agent-1", "tenant-1", "trace-1", "deploy_payload", "denied by policy")
	assert.Equal(t, PolicyBlocked, e.EventType)
	assert.Equal(t, "deploy_payload", e.Payload["action"])
	assert.Equal(t, "denied by policy", e.Payload["reason"])
}

func TestToolCalledEvent(t *testing.T) {
	e := ToolCalledEvent("agent-1", "tenant-1", "trace-1", "nmap_scan", "target=10.0.0.1")
	assert.Equal(t, ToolCalled, e.EventType)
	assert.Equal(t, "nmap_scan", e.Payload["tool_name"])
	assert.Equal(t, "target=10.0.0.1", e.Payload["input_summary"])
}

func TestGraphWriteEvent(t *testing.T) {
	e := GraphWriteEvent("agent-1", "tenant-1", "trace-1", "Vulnerability", "vuln-123", "create")
	assert.Equal(t, GraphWrite, e.EventType)
	assert.Equal(t, "Vulnerability", e.Payload["node_type"])
	assert.Equal(t, "vuln-123", e.Payload["node_id"])
	assert.Equal(t, "create", e.Payload["operation"])
}

// ---------------------------------------------------------------------------
// EventType constants
// ---------------------------------------------------------------------------

func TestEventTypeConstants(t *testing.T) {
	expectedTypes := map[EventType]string{
		AgentStarted:           "agent.started",
		AgentCompleted:         "agent.completed",
		AgentFailed:            "agent.failed",
		ToolCalled:             "agent.tool_called",
		ToolResult:             "agent.tool_result",
		DecisionMade:           "agent.decision",
		PolicyAllowed:          "policy.allowed",
		PolicyBlocked:          "policy.blocked",
		GraphRead:              "sif.graph_read",
		GraphWrite:             "sif.graph_write",
		HumanApprovalRequested: "governance.approval_requested",
		HumanApprovalGranted:   "governance.approval_granted",
		HumanApprovalDenied:    "governance.approval_denied",
	}

	for et, expected := range expectedTypes {
		assert.Equal(t, expected, string(et), "EventType %q should have value %q", et, expected)
	}
}

// ---------------------------------------------------------------------------
// Logger — Emit events
// ---------------------------------------------------------------------------

func TestLogger_EmitWritesJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithWriter("acme", "risk-quant-v1", "trace-abc", &buf)

	event := AgentStartedEvent("risk-quant-v1", "acme", "trace-abc")
	logger.Emit(event)

	output := buf.String()
	require.NotEmpty(t, output, "logger should write output")

	// Parse the JSON output
	var logLine map[string]interface{}
	err := json.Unmarshal([]byte(output), &logLine)
	require.NoError(t, err, "output should be valid JSON")

	assert.Equal(t, "agent.started", logLine["message"])
	assert.Equal(t, "acme", logLine["tenant_id"])
	assert.Equal(t, "risk-quant-v1", logLine["agent_id"])
	assert.Equal(t, "trace-abc", logLine["trace_id"])
	assert.Contains(t, logLine, "timestamp")
}

func TestLogger_EmitIncludesPayload(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithWriter("acme", "agent-1", "trace-1", &buf)

	event := AgentCompletedEvent("agent-1", "acme", "trace-1", true, 999.0)
	logger.Emit(event)

	var logLine map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logLine)
	require.NoError(t, err)

	assert.Equal(t, "agent.completed", logLine["message"])
	assert.Equal(t, true, logLine["success"])
	assert.Equal(t, 999.0, logLine["duration_ms"])
}

func TestLogger_EmitMultipleEvents(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithWriter("acme", "agent-1", "trace-1", &buf)

	logger.Emit(AgentStartedEvent("agent-1", "acme", "trace-1"))
	logger.Emit(ToolCalledEvent("agent-1", "acme", "trace-1", "scanner", "target=x"))
	logger.Emit(AgentCompletedEvent("agent-1", "acme", "trace-1", true, 1000.0))

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	assert.Len(t, lines, 3, "should emit exactly 3 log lines")

	// Verify each line is valid JSON
	for i, line := range lines {
		var logLine map[string]interface{}
		err := json.Unmarshal(line, &logLine)
		assert.NoError(t, err, "line %d should be valid JSON", i)
	}
}

// ---------------------------------------------------------------------------
// Logger — LogRaw
// ---------------------------------------------------------------------------

func TestLogger_LogRaw(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithWriter("acme", "agent-1", "trace-1", &buf)

	fields := map[string]interface{}{
		"custom_field": "custom_value",
		"count":        42,
	}
	logger.LogRaw(DecisionMade, fields)

	output := buf.String()
	require.NotEmpty(t, output)

	var logLine map[string]interface{}
	err := json.Unmarshal([]byte(output), &logLine)
	require.NoError(t, err, "output should be valid JSON")

	assert.Equal(t, "agent.decision", logLine["message"])
	assert.Equal(t, "custom_value", logLine["custom_field"])
	// JSON numbers are parsed as float64
	assert.Equal(t, float64(42), logLine["count"])
	assert.Equal(t, "acme", logLine["tenant_id"])
	assert.Equal(t, "agent-1", logLine["agent_id"])
	assert.Equal(t, "trace-1", logLine["trace_id"])
}

func TestLogger_LogRawEmptyFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithWriter("acme", "agent-1", "trace-1", &buf)

	logger.LogRaw(GraphRead, map[string]interface{}{})

	var logLine map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logLine)
	require.NoError(t, err)

	assert.Equal(t, "sif.graph_read", logLine["message"])
}

// ---------------------------------------------------------------------------
// Logger — constructor fields
// ---------------------------------------------------------------------------

func TestLogger_FieldsSet(t *testing.T) {
	logger := NewLoggerWithWriter("tenant-x", "agent-y", "trace-z", &bytes.Buffer{})

	assert.Equal(t, "tenant-x", logger.TenantID)
	assert.Equal(t, "agent-y", logger.AgentID)
	assert.Equal(t, "trace-z", logger.TraceID)
}

func TestNewLogger_DefaultsToStdout(t *testing.T) {
	// NewLogger should not panic; it writes to stdout by default.
	logger := NewLogger("tenant-1", "agent-1", "trace-1")
	assert.NotNil(t, logger)
	assert.Equal(t, "tenant-1", logger.TenantID)
}
