/**
 * ZAK Audit Events + Logger Tests
 *
 * Covers:
 * - Event factory functions create correct event types
 * - AuditEvent base fields are populated
 * - AuditLogger emits events without crashing
 * - AuditLogger logRaw works
 * - AuditEventType constants
 */

import { describe, it, expect } from "vitest";

import {
  AuditEventType,
  agentStartedEvent,
  agentCompletedEvent,
  agentFailedEvent,
  policyBlockedEvent,
  toolCalledEvent,
  graphWriteEvent,
} from "../src/core/audit/events.js";
import type {
  AuditEvent,
  AgentStartedEvent,
  AgentCompletedEvent,
  AgentFailedEvent,
  PolicyBlockedEvent,
  ToolCalledEvent,
  GraphWriteEvent,
} from "../src/core/audit/events.js";
import { AuditLogger } from "../src/core/audit/logger.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const AGENT_ID = "test-agent-v1";
const TENANT_ID = "acme-corp";
const TRACE_ID = "trace-abc-123";

// ---------------------------------------------------------------------------
// AuditEventType constants
// ---------------------------------------------------------------------------
describe("AuditEventType constants", () => {
  it("has AGENT_STARTED type", () => {
    expect(AuditEventType.AGENT_STARTED).toBe("agent.started");
  });

  it("has AGENT_COMPLETED type", () => {
    expect(AuditEventType.AGENT_COMPLETED).toBe("agent.completed");
  });

  it("has AGENT_FAILED type", () => {
    expect(AuditEventType.AGENT_FAILED).toBe("agent.failed");
  });

  it("has TOOL_CALLED type", () => {
    expect(AuditEventType.TOOL_CALLED).toBe("agent.tool_called");
  });

  it("has TOOL_RESULT type", () => {
    expect(AuditEventType.TOOL_RESULT).toBe("agent.tool_result");
  });

  it("has DECISION_MADE type", () => {
    expect(AuditEventType.DECISION_MADE).toBe("agent.decision");
  });

  it("has POLICY_ALLOWED type", () => {
    expect(AuditEventType.POLICY_ALLOWED).toBe("policy.allowed");
  });

  it("has POLICY_BLOCKED type", () => {
    expect(AuditEventType.POLICY_BLOCKED).toBe("policy.blocked");
  });

  it("has GRAPH_READ type", () => {
    expect(AuditEventType.GRAPH_READ).toBe("sif.graph_read");
  });

  it("has GRAPH_WRITE type", () => {
    expect(AuditEventType.GRAPH_WRITE).toBe("sif.graph_write");
  });

  it("has HUMAN_APPROVAL_REQUESTED type", () => {
    expect(AuditEventType.HUMAN_APPROVAL_REQUESTED).toBe(
      "governance.approval_requested"
    );
  });

  it("has HUMAN_APPROVAL_GRANTED type", () => {
    expect(AuditEventType.HUMAN_APPROVAL_GRANTED).toBe(
      "governance.approval_granted"
    );
  });

  it("has HUMAN_APPROVAL_DENIED type", () => {
    expect(AuditEventType.HUMAN_APPROVAL_DENIED).toBe(
      "governance.approval_denied"
    );
  });

  it("has exactly 13 event types", () => {
    const keys = Object.keys(AuditEventType);
    expect(keys.length).toBe(13);
  });
});

// ---------------------------------------------------------------------------
// Event factory: agentStartedEvent
// ---------------------------------------------------------------------------
describe("agentStartedEvent factory", () => {
  it("creates an event with correct eventType", () => {
    const event = agentStartedEvent(AGENT_ID, TENANT_ID, TRACE_ID);
    expect(event.eventType).toBe(AuditEventType.AGENT_STARTED);
  });

  it("populates agentId, tenantId, traceId", () => {
    const event = agentStartedEvent(AGENT_ID, TENANT_ID, TRACE_ID);
    expect(event.agentId).toBe(AGENT_ID);
    expect(event.tenantId).toBe(TENANT_ID);
    expect(event.traceId).toBe(TRACE_ID);
  });

  it("generates an ISO 8601 timestamp", () => {
    const event = agentStartedEvent(AGENT_ID, TENANT_ID, TRACE_ID);
    expect(event.timestamp).toBeTruthy();
    // Should be parseable as a date
    const date = new Date(event.timestamp);
    expect(date.getTime()).not.toBeNaN();
  });

  it("has an empty payload by default", () => {
    const event = agentStartedEvent(AGENT_ID, TENANT_ID, TRACE_ID);
    expect(event.payload).toEqual({});
  });

  it("accepts custom payload", () => {
    const event = agentStartedEvent(AGENT_ID, TENANT_ID, TRACE_ID, {
      trigger: "manual",
    });
    expect(event.payload).toEqual({ trigger: "manual" });
  });
});

// ---------------------------------------------------------------------------
// Event factory: agentCompletedEvent
// ---------------------------------------------------------------------------
describe("agentCompletedEvent factory", () => {
  it("creates an event with correct eventType", () => {
    const event = agentCompletedEvent(AGENT_ID, TENANT_ID, TRACE_ID, true, 1500);
    expect(event.eventType).toBe(AuditEventType.AGENT_COMPLETED);
  });

  it("includes success and durationMs fields", () => {
    const event = agentCompletedEvent(AGENT_ID, TENANT_ID, TRACE_ID, true, 1500);
    expect(event.success).toBe(true);
    expect(event.durationMs).toBe(1500);
  });

  it("records failure with success=false", () => {
    const event = agentCompletedEvent(AGENT_ID, TENANT_ID, TRACE_ID, false, 500);
    expect(event.success).toBe(false);
    expect(event.durationMs).toBe(500);
  });

  it("populates base fields correctly", () => {
    const event = agentCompletedEvent(AGENT_ID, TENANT_ID, TRACE_ID, true, 100);
    expect(event.agentId).toBe(AGENT_ID);
    expect(event.tenantId).toBe(TENANT_ID);
    expect(event.traceId).toBe(TRACE_ID);
    expect(event.timestamp).toBeTruthy();
  });

  it("accepts custom payload", () => {
    const event = agentCompletedEvent(AGENT_ID, TENANT_ID, TRACE_ID, true, 200, {
      findings: 5,
    });
    expect(event.payload).toEqual({ findings: 5 });
  });
});

// ---------------------------------------------------------------------------
// Event factory: agentFailedEvent
// ---------------------------------------------------------------------------
describe("agentFailedEvent factory", () => {
  it("creates an event with correct eventType", () => {
    const event = agentFailedEvent(AGENT_ID, TENANT_ID, TRACE_ID, "Connection timeout");
    expect(event.eventType).toBe(AuditEventType.AGENT_FAILED);
  });

  it("includes the error message", () => {
    const event = agentFailedEvent(AGENT_ID, TENANT_ID, TRACE_ID, "Out of memory");
    expect(event.error).toBe("Out of memory");
  });

  it("populates base fields correctly", () => {
    const event = agentFailedEvent(AGENT_ID, TENANT_ID, TRACE_ID, "Error");
    expect(event.agentId).toBe(AGENT_ID);
    expect(event.tenantId).toBe(TENANT_ID);
    expect(event.traceId).toBe(TRACE_ID);
  });

  it("accepts custom payload", () => {
    const event = agentFailedEvent(AGENT_ID, TENANT_ID, TRACE_ID, "Error", {
      retryCount: 3,
    });
    expect(event.payload).toEqual({ retryCount: 3 });
  });
});

// ---------------------------------------------------------------------------
// Event factory: policyBlockedEvent
// ---------------------------------------------------------------------------
describe("policyBlockedEvent factory", () => {
  it("creates an event with correct eventType", () => {
    const event = policyBlockedEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "execute_exploit",
      "Risk budget too low"
    );
    expect(event.eventType).toBe(AuditEventType.POLICY_BLOCKED);
  });

  it("includes action and reason fields", () => {
    const event = policyBlockedEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "deploy_payload",
      "Denied by policy"
    );
    expect(event.action).toBe("deploy_payload");
    expect(event.reason).toBe("Denied by policy");
  });

  it("populates base fields correctly", () => {
    const event = policyBlockedEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "action",
      "reason"
    );
    expect(event.agentId).toBe(AGENT_ID);
    expect(event.tenantId).toBe(TENANT_ID);
    expect(event.traceId).toBe(TRACE_ID);
  });

  it("accepts custom payload", () => {
    const event = policyBlockedEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "action",
      "reason",
      { environment: "production" }
    );
    expect(event.payload).toEqual({ environment: "production" });
  });
});

// ---------------------------------------------------------------------------
// Event factory: toolCalledEvent
// ---------------------------------------------------------------------------
describe("toolCalledEvent factory", () => {
  it("creates an event with correct eventType", () => {
    const event = toolCalledEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "nmap_scan",
      "Scanning target 192.168.1.0/24"
    );
    expect(event.eventType).toBe(AuditEventType.TOOL_CALLED);
  });

  it("includes toolName and inputSummary fields", () => {
    const event = toolCalledEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "risk_calculator",
      "Computing ALE for scenario S-001"
    );
    expect(event.toolName).toBe("risk_calculator");
    expect(event.inputSummary).toBe("Computing ALE for scenario S-001");
  });

  it("populates base fields correctly", () => {
    const event = toolCalledEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "tool",
      "summary"
    );
    expect(event.agentId).toBe(AGENT_ID);
    expect(event.tenantId).toBe(TENANT_ID);
    expect(event.traceId).toBe(TRACE_ID);
  });
});

// ---------------------------------------------------------------------------
// Event factory: graphWriteEvent
// ---------------------------------------------------------------------------
describe("graphWriteEvent factory", () => {
  it("creates an event with correct eventType", () => {
    const event = graphWriteEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "Vulnerability",
      "vuln-001"
    );
    expect(event.eventType).toBe(AuditEventType.GRAPH_WRITE);
  });

  it("includes nodeType, nodeId, and operation fields", () => {
    const event = graphWriteEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "Asset",
      "asset-42",
      "create"
    );
    expect(event.nodeType).toBe("Asset");
    expect(event.nodeId).toBe("asset-42");
    expect(event.operation).toBe("create");
  });

  it("defaults operation to upsert", () => {
    const event = graphWriteEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "Risk",
      "risk-001"
    );
    expect(event.operation).toBe("upsert");
  });

  it("populates base fields correctly", () => {
    const event = graphWriteEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "Node",
      "id-1"
    );
    expect(event.agentId).toBe(AGENT_ID);
    expect(event.tenantId).toBe(TENANT_ID);
    expect(event.traceId).toBe(TRACE_ID);
  });

  it("accepts custom payload", () => {
    const event = graphWriteEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "Asset",
      "asset-1",
      "upsert",
      { properties: { name: "web-server" } }
    );
    expect(event.payload).toEqual({ properties: { name: "web-server" } });
  });
});

// ---------------------------------------------------------------------------
// AuditLogger — emit events without crashing
// ---------------------------------------------------------------------------
describe("AuditLogger", () => {
  it("constructs with tenantId, agentId, and traceId", () => {
    const logger = new AuditLogger(TENANT_ID, AGENT_ID, TRACE_ID);
    expect(logger.tenantId).toBe(TENANT_ID);
    expect(logger.agentId).toBe(AGENT_ID);
    expect(logger.traceId).toBe(TRACE_ID);
  });

  it("emits agentStartedEvent without throwing", () => {
    const logger = new AuditLogger(TENANT_ID, AGENT_ID, TRACE_ID);
    const event = agentStartedEvent(AGENT_ID, TENANT_ID, TRACE_ID);
    expect(() => logger.emit(event)).not.toThrow();
  });

  it("emits agentCompletedEvent without throwing", () => {
    const logger = new AuditLogger(TENANT_ID, AGENT_ID, TRACE_ID);
    const event = agentCompletedEvent(AGENT_ID, TENANT_ID, TRACE_ID, true, 1000);
    expect(() => logger.emit(event)).not.toThrow();
  });

  it("emits agentFailedEvent without throwing", () => {
    const logger = new AuditLogger(TENANT_ID, AGENT_ID, TRACE_ID);
    const event = agentFailedEvent(AGENT_ID, TENANT_ID, TRACE_ID, "Test error");
    expect(() => logger.emit(event)).not.toThrow();
  });

  it("emits policyBlockedEvent without throwing", () => {
    const logger = new AuditLogger(TENANT_ID, AGENT_ID, TRACE_ID);
    const event = policyBlockedEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "execute_exploit",
      "Denied by policy"
    );
    expect(() => logger.emit(event)).not.toThrow();
  });

  it("emits toolCalledEvent without throwing", () => {
    const logger = new AuditLogger(TENANT_ID, AGENT_ID, TRACE_ID);
    const event = toolCalledEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "nmap",
      "scan target"
    );
    expect(() => logger.emit(event)).not.toThrow();
  });

  it("emits graphWriteEvent without throwing", () => {
    const logger = new AuditLogger(TENANT_ID, AGENT_ID, TRACE_ID);
    const event = graphWriteEvent(
      AGENT_ID,
      TENANT_ID,
      TRACE_ID,
      "Vulnerability",
      "vuln-001"
    );
    expect(() => logger.emit(event)).not.toThrow();
  });

  it("logRaw emits without throwing", () => {
    const logger = new AuditLogger(TENANT_ID, AGENT_ID, TRACE_ID);
    expect(() =>
      logger.logRaw(AuditEventType.AGENT_STARTED, { custom: "data" })
    ).not.toThrow();
  });

  it("logRaw works with empty data", () => {
    const logger = new AuditLogger(TENANT_ID, AGENT_ID, TRACE_ID);
    expect(() =>
      logger.logRaw(AuditEventType.DECISION_MADE)
    ).not.toThrow();
  });

  it("emits multiple events sequentially without throwing", () => {
    const logger = new AuditLogger(TENANT_ID, AGENT_ID, TRACE_ID);
    const started = agentStartedEvent(AGENT_ID, TENANT_ID, TRACE_ID);
    const tool = toolCalledEvent(AGENT_ID, TENANT_ID, TRACE_ID, "scanner", "scan");
    const completed = agentCompletedEvent(AGENT_ID, TENANT_ID, TRACE_ID, true, 2000);

    expect(() => {
      logger.emit(started);
      logger.emit(tool);
      logger.emit(completed);
    }).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Timestamp consistency
// ---------------------------------------------------------------------------
describe("Timestamp consistency", () => {
  it("generates timestamps close to current time", () => {
    const before = Date.now();
    const event = agentStartedEvent(AGENT_ID, TENANT_ID, TRACE_ID);
    const after = Date.now();
    const eventTime = new Date(event.timestamp).getTime();
    expect(eventTime).toBeGreaterThanOrEqual(before);
    expect(eventTime).toBeLessThanOrEqual(after);
  });

  it("different events get different timestamps (or same if called fast)", () => {
    const event1 = agentStartedEvent(AGENT_ID, TENANT_ID, TRACE_ID);
    const event2 = agentStartedEvent(AGENT_ID, TENANT_ID, TRACE_ID);
    // Both should be valid ISO strings
    expect(new Date(event1.timestamp).getTime()).not.toBeNaN();
    expect(new Date(event2.timestamp).getTime()).not.toBeNaN();
  });
});
