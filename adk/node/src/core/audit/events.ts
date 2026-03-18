/**
 * ZAK Audit Layer — typed event definitions.
 *
 * All events carry: eventType, agentId, tenantId, traceId, timestamp.
 *
 * TypeScript equivalent of zak/core/audit/events.py.
 */

// ---------------------------------------------------------------------------
// Audit Event Types (13 types)
// ---------------------------------------------------------------------------

export const AuditEventType = {
  AGENT_STARTED: "agent.started",
  AGENT_COMPLETED: "agent.completed",
  AGENT_FAILED: "agent.failed",
  TOOL_CALLED: "agent.tool_called",
  TOOL_RESULT: "agent.tool_result",
  DECISION_MADE: "agent.decision",
  POLICY_ALLOWED: "policy.allowed",
  POLICY_BLOCKED: "policy.blocked",
  GRAPH_READ: "sif.graph_read",
  GRAPH_WRITE: "sif.graph_write",
  HUMAN_APPROVAL_REQUESTED: "governance.approval_requested",
  HUMAN_APPROVAL_GRANTED: "governance.approval_granted",
  HUMAN_APPROVAL_DENIED: "governance.approval_denied",
} as const;

export type AuditEventType =
  (typeof AuditEventType)[keyof typeof AuditEventType];

// ---------------------------------------------------------------------------
// Base Audit Event
// ---------------------------------------------------------------------------

export interface AuditEvent {
  eventType: AuditEventType;
  agentId: string;
  tenantId: string;
  traceId: string;
  timestamp: string; // ISO 8601
  payload: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Typed Event Interfaces
// ---------------------------------------------------------------------------

export interface AgentStartedEvent extends AuditEvent {
  eventType: typeof AuditEventType.AGENT_STARTED;
}

export interface AgentCompletedEvent extends AuditEvent {
  eventType: typeof AuditEventType.AGENT_COMPLETED;
  success: boolean;
  durationMs: number;
}

export interface AgentFailedEvent extends AuditEvent {
  eventType: typeof AuditEventType.AGENT_FAILED;
  error: string;
}

export interface PolicyBlockedEvent extends AuditEvent {
  eventType: typeof AuditEventType.POLICY_BLOCKED;
  action: string;
  reason: string;
}

export interface ToolCalledEvent extends AuditEvent {
  eventType: typeof AuditEventType.TOOL_CALLED;
  toolName: string;
  inputSummary: string;
}

export interface GraphWriteEvent extends AuditEvent {
  eventType: typeof AuditEventType.GRAPH_WRITE;
  nodeType: string;
  nodeId: string;
  operation: string;
}

// ---------------------------------------------------------------------------
// Event Factories
// ---------------------------------------------------------------------------

function nowISO(): string {
  return new Date().toISOString();
}

function baseEvent(
  eventType: AuditEventType,
  agentId: string,
  tenantId: string,
  traceId: string,
  payload: Record<string, unknown> = {}
): AuditEvent {
  return {
    eventType,
    agentId,
    tenantId,
    traceId,
    timestamp: nowISO(),
    payload,
  };
}

export function agentStartedEvent(
  agentId: string,
  tenantId: string,
  traceId: string,
  payload: Record<string, unknown> = {}
): AgentStartedEvent {
  return {
    ...baseEvent(AuditEventType.AGENT_STARTED, agentId, tenantId, traceId, payload),
    eventType: AuditEventType.AGENT_STARTED,
  };
}

export function agentCompletedEvent(
  agentId: string,
  tenantId: string,
  traceId: string,
  success: boolean,
  durationMs: number,
  payload: Record<string, unknown> = {}
): AgentCompletedEvent {
  return {
    ...baseEvent(AuditEventType.AGENT_COMPLETED, agentId, tenantId, traceId, payload),
    eventType: AuditEventType.AGENT_COMPLETED,
    success,
    durationMs,
  };
}

export function agentFailedEvent(
  agentId: string,
  tenantId: string,
  traceId: string,
  error: string,
  payload: Record<string, unknown> = {}
): AgentFailedEvent {
  return {
    ...baseEvent(AuditEventType.AGENT_FAILED, agentId, tenantId, traceId, payload),
    eventType: AuditEventType.AGENT_FAILED,
    error,
  };
}

export function policyBlockedEvent(
  agentId: string,
  tenantId: string,
  traceId: string,
  action: string,
  reason: string,
  payload: Record<string, unknown> = {}
): PolicyBlockedEvent {
  return {
    ...baseEvent(AuditEventType.POLICY_BLOCKED, agentId, tenantId, traceId, payload),
    eventType: AuditEventType.POLICY_BLOCKED,
    action,
    reason,
  };
}

export function toolCalledEvent(
  agentId: string,
  tenantId: string,
  traceId: string,
  toolName: string,
  inputSummary: string,
  payload: Record<string, unknown> = {}
): ToolCalledEvent {
  return {
    ...baseEvent(AuditEventType.TOOL_CALLED, agentId, tenantId, traceId, payload),
    eventType: AuditEventType.TOOL_CALLED,
    toolName,
    inputSummary,
  };
}

export function graphWriteEvent(
  agentId: string,
  tenantId: string,
  traceId: string,
  nodeType: string,
  nodeId: string,
  operation = "upsert",
  payload: Record<string, unknown> = {}
): GraphWriteEvent {
  return {
    ...baseEvent(AuditEventType.GRAPH_WRITE, agentId, tenantId, traceId, payload),
    eventType: AuditEventType.GRAPH_WRITE,
    nodeType,
    nodeId,
    operation,
  };
}
