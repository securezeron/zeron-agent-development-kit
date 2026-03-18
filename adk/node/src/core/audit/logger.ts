/**
 * ZAK Audit Logger — structured audit log emission using pino.
 *
 * All audit events are serialized as JSON and tagged with tenantId + traceId.
 *
 * TypeScript equivalent of zak/core/audit/logger.py.
 */

import pino from "pino";
import type { AuditEvent, AuditEventType } from "./events.js";

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/**
 * Tenant-scoped, agent-scoped structured audit logger.
 *
 * @example
 * ```ts
 * const logger = new AuditLogger("acme", "risk-quant-v1", "abc123");
 * logger.emit(agentStartedEvent("risk-quant-v1", "acme", "abc123"));
 * ```
 */
export class AuditLogger {
  readonly tenantId: string;
  readonly agentId: string;
  readonly traceId: string;
  private readonly log: pino.Logger;

  constructor(tenantId: string, agentId: string, traceId: string) {
    this.tenantId = tenantId;
    this.agentId = agentId;
    this.traceId = traceId;
    this.log = pino({
      level: "info",
      formatters: {
        level(label) {
          return { level: label };
        },
      },
    }).child({
      tenant_id: tenantId,
      agent_id: agentId,
      trace_id: traceId,
    });
  }

  /**
   * Emit a typed audit event as a structured log line.
   */
  emit(event: AuditEvent): void {
    // Extract all fields except the base ones for extra logging
    const baseFields = new Set([
      "eventType",
      "agentId",
      "tenantId",
      "traceId",
      "timestamp",
    ]);
    const extra: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(event)) {
      if (!baseFields.has(key) && value !== undefined && value !== null) {
        extra[key] = value;
      }
    }

    this.log.info(
      {
        ...extra,
        timestamp: event.timestamp,
      },
      event.eventType
    );
  }

  /**
   * Emit an ad-hoc audit event without a typed model (convenience method).
   */
  logRaw(eventType: AuditEventType, data: Record<string, unknown> = {}): void {
    this.log.info(data, eventType);
  }
}
