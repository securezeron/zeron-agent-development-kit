"""
ZAK Audit Layer — typed event definitions and structured logging.

All events carry: event_type, agent_id, tenant_id, trace_id, timestamp.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    AGENT_STARTED = "agent.started"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"
    TOOL_CALLED = "agent.tool_called"
    TOOL_RESULT = "agent.tool_result"
    DECISION_MADE = "agent.decision"
    POLICY_ALLOWED = "policy.allowed"
    POLICY_BLOCKED = "policy.blocked"
    GRAPH_READ = "sif.graph_read"
    GRAPH_WRITE = "sif.graph_write"
    HUMAN_APPROVAL_REQUESTED = "governance.approval_requested"
    HUMAN_APPROVAL_GRANTED = "governance.approval_granted"
    HUMAN_APPROVAL_DENIED = "governance.approval_denied"


class AuditEvent(BaseModel):
    """Immutable structured audit log entry."""
    event_type: AuditEventType
    agent_id: str
    tenant_id: str
    trace_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    payload: dict[str, Any] = Field(default_factory=dict)


class AgentStartedEvent(AuditEvent):
    event_type: AuditEventType = AuditEventType.AGENT_STARTED


class AgentCompletedEvent(AuditEvent):
    event_type: AuditEventType = AuditEventType.AGENT_COMPLETED
    success: bool = True
    duration_ms: float = 0.0


class AgentFailedEvent(AuditEvent):
    event_type: AuditEventType = AuditEventType.AGENT_FAILED
    error: str = ""


class PolicyBlockedEvent(AuditEvent):
    event_type: AuditEventType = AuditEventType.POLICY_BLOCKED
    action: str = ""
    reason: str = ""


class ToolCalledEvent(AuditEvent):
    event_type: AuditEventType = AuditEventType.TOOL_CALLED
    tool_name: str = ""
    input_summary: str = ""


class GraphWriteEvent(AuditEvent):
    event_type: AuditEventType = AuditEventType.GRAPH_WRITE
    node_type: str = ""
    node_id: str = ""
    operation: str = "upsert"
