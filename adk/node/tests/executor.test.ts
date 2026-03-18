/**
 * ZAK Agent Executor Tests (Phase 2)
 *
 * Covers:
 * - Successful execution produces correct AgentResult
 * - Policy denial produces failed result
 * - Exception during execution is caught and produces failed result
 * - preRun hook is called
 * - postRun hook is called
 * - checkAction() returns correct policy decisions
 * - Audit events are emitted (verify no crashes)
 * - Async agent execution works
 */

import { describe, it, expect, beforeEach, vi } from "vitest";

import { AgentExecutor } from "../src/core/runtime/executor.js";
import {
  BaseAgent,
  createAgentContext,
  agentResultOk,
  agentResultFail,
  getAgentId,
  type AgentContext,
  type AgentResult,
} from "../src/core/runtime/agent.js";
import { AgentDSLSchema } from "../src/core/dsl/schema.js";
import type { AgentDSL } from "../src/core/dsl/schema.js";

// ---------------------------------------------------------------------------
// Helper: create a valid AgentDSL for testing
// ---------------------------------------------------------------------------

function makeTestDSL(overrides: {
  id?: string;
  domain?: string;
  autonomy_level?: string;
  allowed_actions?: string[];
  denied_actions?: string[];
  environment_scope?: string[];
  tools?: string[];
} = {}): AgentDSL {
  return {
    agent: {
      id: overrides.id ?? "test-executor-v1",
      name: "Test Executor Agent",
      domain: overrides.domain ?? "appsec",
      version: "1.0.0",
    },
    intent: {
      goal: "Test executor lifecycle",
      success_criteria: [],
      priority: "medium",
    },
    reasoning: {
      mode: "deterministic",
      autonomy_level: overrides.autonomy_level ?? "bounded",
      confidence_threshold: 0.75,
      llm: null,
    },
    capabilities: {
      tools: overrides.tools ?? [],
      data_access: [],
      graph_access: [],
    },
    boundaries: {
      risk_budget: "medium",
      allowed_actions: overrides.allowed_actions ?? [],
      denied_actions: overrides.denied_actions ?? [],
      environment_scope: overrides.environment_scope ?? [],
      approval_gates: [],
    },
    safety: {
      guardrails: [],
      sandbox_profile: overrides.domain === "red_team" ? "offensive_isolated" : "standard",
      audit_level: overrides.domain === "red_team" ? "verbose" : "standard",
    },
  } as AgentDSL;
}

function makeTestContext(dslOverrides: Parameters<typeof makeTestDSL>[0] = {}): AgentContext {
  return createAgentContext({
    tenantId: "test-tenant",
    traceId: "trace-001",
    dsl: makeTestDSL(dslOverrides),
    environment: "staging",
  });
}

// ---------------------------------------------------------------------------
// Test agents
// ---------------------------------------------------------------------------

class SuccessAgent extends BaseAgent {
  execute(context: AgentContext): AgentResult {
    return agentResultOk(context, { finding: "all clear" });
  }
}

class FailingAgent extends BaseAgent {
  execute(context: AgentContext): AgentResult {
    return agentResultFail(context, ["Something went wrong"]);
  }
}

class ThrowingAgent extends BaseAgent {
  execute(_context: AgentContext): AgentResult {
    throw new Error("Unexpected runtime error");
  }
}

class AsyncSuccessAgent extends BaseAgent {
  async execute(context: AgentContext): Promise<AgentResult> {
    return agentResultOk(context, { async: true });
  }
}

class AsyncThrowingAgent extends BaseAgent {
  async execute(_context: AgentContext): Promise<AgentResult> {
    throw new Error("Async boom");
  }
}

class HookedAgent extends BaseAgent {
  preRunCalled = false;
  postRunCalled = false;
  postRunResult: AgentResult | null = null;

  preRun(_context: AgentContext): void {
    this.preRunCalled = true;
  }

  execute(context: AgentContext): AgentResult {
    return agentResultOk(context, { hooked: true });
  }

  postRun(_context: AgentContext, result: AgentResult): void {
    this.postRunCalled = true;
    this.postRunResult = result;
  }
}

class PreRunThrowingAgent extends BaseAgent {
  preRun(_context: AgentContext): void {
    throw new Error("preRun failed");
  }

  execute(context: AgentContext): AgentResult {
    return agentResultOk(context, {});
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AgentExecutor", () => {
  let executor: AgentExecutor;

  beforeEach(() => {
    executor = new AgentExecutor();
  });

  // -------------------------------------------------------------------------
  // Successful execution produces correct AgentResult
  // -------------------------------------------------------------------------
  describe("successful execution", () => {
    it("produces a result with success=true", async () => {
      const ctx = makeTestContext();
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(true);
    });

    it("includes the correct agentId", async () => {
      const ctx = makeTestContext({ id: "my-test-agent-v1" });
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.agentId).toBe("my-test-agent-v1");
    });

    it("includes the correct tenantId", async () => {
      const ctx = makeTestContext();
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.tenantId).toBe("test-tenant");
    });

    it("includes the correct traceId", async () => {
      const ctx = makeTestContext();
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.traceId).toBe("trace-001");
    });

    it("includes agent output", async () => {
      const ctx = makeTestContext();
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.output).toEqual({ finding: "all clear" });
    });

    it("has empty errors array on success", async () => {
      const ctx = makeTestContext();
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.errors).toEqual([]);
    });

    it("records a positive durationMs", async () => {
      const ctx = makeTestContext();
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it("sets completedAt date", async () => {
      const ctx = makeTestContext();
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.completedAt).toBeInstanceOf(Date);
    });
  });

  // -------------------------------------------------------------------------
  // Async agent execution
  // -------------------------------------------------------------------------
  describe("async agent execution", () => {
    it("handles async execute() returning a promise", async () => {
      const ctx = makeTestContext();
      const agent = new AsyncSuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(true);
      expect(result.output).toEqual({ async: true });
    });

    it("catches errors from async execute()", async () => {
      const ctx = makeTestContext();
      const agent = new AsyncThrowingAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(false);
      expect(result.errors).toContain("Async boom");
    });
  });

  // -------------------------------------------------------------------------
  // Policy denial produces failed result
  // -------------------------------------------------------------------------
  describe("policy denial produces failed result", () => {
    it("returns failed result when action is denied by policy", async () => {
      const ctx = makeTestContext({
        denied_actions: ["agent_execute"],
      });
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(false);
    });

    it("includes 'Policy denied' in errors", async () => {
      const ctx = makeTestContext({
        denied_actions: ["agent_execute"],
      });
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain("Policy denied");
    });

    it("does not call execute() when policy denies", async () => {
      const ctx = makeTestContext({
        denied_actions: ["agent_execute"],
      });
      const agent = new SuccessAgent();
      const executeSpy = vi.spyOn(agent, "execute");
      await executor.run(agent, ctx);
      expect(executeSpy).not.toHaveBeenCalled();
    });

    it("records durationMs even on policy denial", async () => {
      const ctx = makeTestContext({
        denied_actions: ["agent_execute"],
      });
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it("policy denial due to environment scope", async () => {
      const ctx = createAgentContext({
        tenantId: "test-tenant",
        traceId: "trace-002",
        dsl: makeTestDSL({
          environment_scope: ["dev"],
        }),
        environment: "production",
      });
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      // The policy checks "agent_execute" action. If the environment scope
      // blocks the environment, it depends on the policy engine's evaluation
      // of environment scope for "agent_execute".
      // environment_scope only fires when the environment is specified and not in scope.
      expect(result.success).toBe(false);
      expect(result.errors[0]).toContain("Policy denied");
    });
  });

  // -------------------------------------------------------------------------
  // Exception during execution is caught
  // -------------------------------------------------------------------------
  describe("exception during execution is caught", () => {
    it("produces failed result when execute() throws", async () => {
      const ctx = makeTestContext();
      const agent = new ThrowingAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(false);
    });

    it("captures the error message", async () => {
      const ctx = makeTestContext();
      const agent = new ThrowingAgent();
      const result = await executor.run(agent, ctx);
      expect(result.errors).toContain("Unexpected runtime error");
    });

    it("records durationMs on exception", async () => {
      const ctx = makeTestContext();
      const agent = new ThrowingAgent();
      const result = await executor.run(agent, ctx);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it("catches preRun exceptions", async () => {
      const ctx = makeTestContext();
      const agent = new PreRunThrowingAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(false);
      expect(result.errors).toContain("preRun failed");
    });

    it("captures non-Error thrown values", async () => {
      class StringThrowingAgent extends BaseAgent {
        execute(_context: AgentContext): AgentResult {
          throw "string error"; // eslint-disable-line no-throw-literal
        }
      }
      const ctx = makeTestContext();
      const agent = new StringThrowingAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(false);
      expect(result.errors).toContain("string error");
    });
  });

  // -------------------------------------------------------------------------
  // preRun hook is called
  // -------------------------------------------------------------------------
  describe("preRun hook is called", () => {
    it("calls preRun before execute", async () => {
      const ctx = makeTestContext();
      const agent = new HookedAgent();
      await executor.run(agent, ctx);
      expect(agent.preRunCalled).toBe(true);
    });

    it("preRun is called even if execute returns failure", async () => {
      class HookedFailAgent extends BaseAgent {
        preRunCalled = false;
        preRun(_context: AgentContext): void {
          this.preRunCalled = true;
        }
        execute(context: AgentContext): AgentResult {
          return agentResultFail(context, ["intentional failure"]);
        }
      }
      const ctx = makeTestContext();
      const agent = new HookedFailAgent();
      await executor.run(agent, ctx);
      expect(agent.preRunCalled).toBe(true);
    });

    it("preRun receives the correct context", async () => {
      let receivedContext: AgentContext | null = null;
      class ContextCapturingAgent extends BaseAgent {
        preRun(context: AgentContext): void {
          receivedContext = context;
        }
        execute(context: AgentContext): AgentResult {
          return agentResultOk(context, {});
        }
      }
      const ctx = makeTestContext({ id: "context-check-v1" });
      const agent = new ContextCapturingAgent();
      await executor.run(agent, ctx);
      expect(receivedContext).not.toBeNull();
      expect(getAgentId(receivedContext!)).toBe("context-check-v1");
    });
  });

  // -------------------------------------------------------------------------
  // postRun hook is called
  // -------------------------------------------------------------------------
  describe("postRun hook is called", () => {
    it("calls postRun after execute", async () => {
      const ctx = makeTestContext();
      const agent = new HookedAgent();
      await executor.run(agent, ctx);
      expect(agent.postRunCalled).toBe(true);
    });

    it("postRun receives the result", async () => {
      const ctx = makeTestContext();
      const agent = new HookedAgent();
      await executor.run(agent, ctx);
      expect(agent.postRunResult).not.toBeNull();
      expect(agent.postRunResult!.success).toBe(true);
      expect(agent.postRunResult!.output).toEqual({ hooked: true });
    });

    it("postRun is not called when policy denies execution", async () => {
      const ctx = makeTestContext({
        denied_actions: ["agent_execute"],
      });
      const agent = new HookedAgent();
      await executor.run(agent, ctx);
      expect(agent.postRunCalled).toBe(false);
    });

    it("postRun is not called when execute() throws", async () => {
      class HookedThrowingAgent extends BaseAgent {
        postRunCalled = false;
        execute(_context: AgentContext): AgentResult {
          throw new Error("boom");
        }
        postRun(_context: AgentContext, _result: AgentResult): void {
          this.postRunCalled = true;
        }
      }
      const ctx = makeTestContext();
      const agent = new HookedThrowingAgent();
      await executor.run(agent, ctx);
      expect(agent.postRunCalled).toBe(false);
    });

    it("postRun is called even when agent returns a failure result", async () => {
      class HookedFailReturnAgent extends BaseAgent {
        postRunCalled = false;
        execute(context: AgentContext): AgentResult {
          return agentResultFail(context, ["soft failure"]);
        }
        postRun(_context: AgentContext, _result: AgentResult): void {
          this.postRunCalled = true;
        }
      }
      const ctx = makeTestContext();
      const agent = new HookedFailReturnAgent();
      await executor.run(agent, ctx);
      expect(agent.postRunCalled).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // checkAction() returns correct policy decisions
  // -------------------------------------------------------------------------
  describe("checkAction() returns correct policy decisions", () => {
    it("returns allowed=true for permitted actions", () => {
      const ctx = makeTestContext();
      const decision = executor.checkAction(ctx, "read_asset");
      expect(decision.allowed).toBe(true);
    });

    it("returns allowed=false for denied actions", () => {
      const ctx = makeTestContext({
        denied_actions: ["delete_data"],
      });
      const decision = executor.checkAction(ctx, "delete_data");
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("explicitly denied");
    });

    it("returns allowed=false for out-of-scope environment", () => {
      const ctx = makeTestContext({
        environment_scope: ["staging"],
      });
      const decision = executor.checkAction(ctx, "read_asset", "production");
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("not in scope");
    });

    it("uses context.environment when no environment is specified", () => {
      const ctx = createAgentContext({
        tenantId: "test-tenant",
        traceId: "trace-003",
        dsl: makeTestDSL({
          environment_scope: ["staging"],
        }),
        environment: "staging",
      });
      const decision = executor.checkAction(ctx, "read_asset");
      expect(decision.allowed).toBe(true);
    });

    it("returns allowed=false for observe-only agent with mutating action", () => {
      const ctx = makeTestContext({
        autonomy_level: "observe",
      });
      const decision = executor.checkAction(ctx, "write_report");
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("mutating operation");
    });

    it("returns allowed=true for observe-only agent with read action", () => {
      const ctx = makeTestContext({
        autonomy_level: "observe",
      });
      const decision = executor.checkAction(ctx, "read_asset");
      expect(decision.allowed).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Audit events are emitted (verify no crashes)
  // -------------------------------------------------------------------------
  describe("audit events are emitted without crashes", () => {
    it("successful execution does not crash due to audit logging", async () => {
      const ctx = makeTestContext();
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(true);
    });

    it("failed execution does not crash due to audit logging", async () => {
      const ctx = makeTestContext();
      const agent = new FailingAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(false);
    });

    it("thrown exception does not crash audit logging", async () => {
      const ctx = makeTestContext();
      const agent = new ThrowingAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(false);
    });

    it("policy denial does not crash audit logging", async () => {
      const ctx = makeTestContext({
        denied_actions: ["agent_execute"],
      });
      const agent = new SuccessAgent();
      const result = await executor.run(agent, ctx);
      expect(result.success).toBe(false);
    });

    it("checkAction() with allowed decision does not crash audit logging", () => {
      const ctx = makeTestContext();
      expect(() => executor.checkAction(ctx, "read_asset")).not.toThrow();
    });

    it("checkAction() with denied decision does not crash audit logging", () => {
      const ctx = makeTestContext({
        denied_actions: ["dangerous_action"],
      });
      expect(() =>
        executor.checkAction(ctx, "dangerous_action")
      ).not.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // Agent result helpers
  // -------------------------------------------------------------------------
  describe("agentResultOk and agentResultFail helpers", () => {
    it("agentResultOk produces correct shape", () => {
      const ctx = makeTestContext();
      const result = agentResultOk(ctx, { key: "value" }, 42);
      expect(result.success).toBe(true);
      expect(result.agentId).toBe("test-executor-v1");
      expect(result.tenantId).toBe("test-tenant");
      expect(result.traceId).toBe("trace-001");
      expect(result.output).toEqual({ key: "value" });
      expect(result.errors).toEqual([]);
      expect(result.durationMs).toBe(42);
      expect(result.completedAt).toBeInstanceOf(Date);
    });

    it("agentResultFail produces correct shape", () => {
      const ctx = makeTestContext();
      const result = agentResultFail(ctx, ["err1", "err2"], 99);
      expect(result.success).toBe(false);
      expect(result.output).toEqual({});
      expect(result.errors).toEqual(["err1", "err2"]);
      expect(result.durationMs).toBe(99);
    });
  });

  // -------------------------------------------------------------------------
  // createAgentContext and getAgentId
  // -------------------------------------------------------------------------
  describe("createAgentContext and getAgentId", () => {
    it("createAgentContext applies default environment", () => {
      const ctx = createAgentContext({
        tenantId: "t1",
        traceId: "tr1",
        dsl: makeTestDSL(),
      });
      expect(ctx.environment).toBe("staging");
    });

    it("createAgentContext applies custom environment", () => {
      const ctx = createAgentContext({
        tenantId: "t1",
        traceId: "tr1",
        dsl: makeTestDSL(),
        environment: "production",
      });
      expect(ctx.environment).toBe("production");
    });

    it("createAgentContext applies default metadata", () => {
      const ctx = createAgentContext({
        tenantId: "t1",
        traceId: "tr1",
        dsl: makeTestDSL(),
      });
      expect(ctx.metadata).toEqual({});
    });

    it("createAgentContext sets startedAt", () => {
      const before = new Date();
      const ctx = createAgentContext({
        tenantId: "t1",
        traceId: "tr1",
        dsl: makeTestDSL(),
      });
      const after = new Date();
      expect(ctx.startedAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(ctx.startedAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it("getAgentId returns the agent ID from context", () => {
      const ctx = makeTestContext({ id: "my-agent-v2" });
      expect(getAgentId(ctx)).toBe("my-agent-v2");
    });
  });

  // -------------------------------------------------------------------------
  // BaseAgent name getter
  // -------------------------------------------------------------------------
  describe("BaseAgent name getter", () => {
    it("returns the constructor name", () => {
      const agent = new SuccessAgent();
      expect(agent.name).toBe("SuccessAgent");
    });

    it("returns different names for different classes", () => {
      const s = new SuccessAgent();
      const f = new FailingAgent();
      expect(s.name).not.toBe(f.name);
    });
  });
});
