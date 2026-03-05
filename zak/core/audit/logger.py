"""
ZAK Audit Logger — structured audit log emission using structlog.

All audit events are serialized as JSON and tagged with tenant_id + trace_id.
"""

from __future__ import annotations

import sys
from typing import Any

import structlog

from zak.core.audit.events import AuditEvent, AuditEventType


def _configure_structlog() -> None:
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


_configure_structlog()


class AuditLogger:
    """
    Tenant-scoped, agent-scoped structured audit logger.

    Usage:
        logger = AuditLogger(tenant_id="acme", agent_id="risk-quant-v1", trace_id="abc123")
        logger.emit(AgentStartedEvent(tenant_id="acme", agent_id="risk-quant-v1", trace_id="abc123"))
    """

    def __init__(self, tenant_id: str, agent_id: str, trace_id: str) -> None:
        self.tenant_id = tenant_id
        self.agent_id = agent_id
        self.trace_id = trace_id
        self._log = structlog.get_logger().bind(
            tenant_id=tenant_id,
            agent_id=agent_id,
            trace_id=trace_id,
        )

    def emit(self, event: AuditEvent) -> None:
        """Emit a typed audit event as a structured log line."""
        self._log.info(
            event.event_type.value,
            **event.payload,
            timestamp=event.timestamp.isoformat(),
        )

    def log_raw(self, event_type: AuditEventType, **kwargs: Any) -> None:
        """Emit an ad-hoc audit event without a typed model (convenience method)."""
        self._log.info(event_type.value, **kwargs)
