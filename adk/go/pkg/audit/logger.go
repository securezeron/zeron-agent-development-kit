package audit

import (
	"io"
	"os"

	"github.com/rs/zerolog"
)

// Logger is a tenant-scoped, agent-scoped structured audit logger.
//
// Usage:
//
//	logger := audit.NewLogger("acme", "risk-quant-v1", "abc123")
//	logger.Emit(audit.AgentStartedEvent("risk-quant-v1", "acme", "abc123"))
type Logger struct {
	TenantID string
	AgentID  string
	TraceID  string
	log      zerolog.Logger
}

// NewLogger creates a new AuditLogger that writes JSON to stdout.
func NewLogger(tenantID, agentID, traceID string) *Logger {
	return NewLoggerWithWriter(tenantID, agentID, traceID, os.Stdout)
}

// NewLoggerWithWriter creates a new AuditLogger with a custom writer.
func NewLoggerWithWriter(tenantID, agentID, traceID string, w io.Writer) *Logger {
	zl := zerolog.New(w).With().
		Str("tenant_id", tenantID).
		Str("agent_id", agentID).
		Str("trace_id", traceID).
		Logger()

	return &Logger{
		TenantID: tenantID,
		AgentID:  agentID,
		TraceID:  traceID,
		log:      zl,
	}
}

// Emit writes a typed audit event as a structured JSON log line.
func (l *Logger) Emit(event *Event) {
	logEvent := l.log.Info().
		Str("timestamp", event.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"))

	// Include all payload fields
	for k, v := range event.Payload {
		logEvent = logEvent.Interface(k, v)
	}

	logEvent.Msg(string(event.EventType))
}

// LogRaw emits an ad-hoc audit event without a typed model.
func (l *Logger) LogRaw(eventType EventType, fields map[string]interface{}) {
	logEvent := l.log.Info()
	for k, v := range fields {
		logEvent = logEvent.Interface(k, v)
	}
	logEvent.Msg(string(eventType))
}
