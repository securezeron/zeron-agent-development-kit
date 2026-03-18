/**
 * ZAK Tool Substrate Tests (Phase 2)
 *
 * Covers:
 * - zakTool() registers a tool in the ToolRegistry
 * - ToolRegistry.get().allTools() lists registered tools
 * - ToolRegistry.get().isRegistered() works
 * - ToolExecutor.call() invokes the tool with context
 * - ToolExecutor.call() rejects tools not in capabilities.tools
 * - ToolExecutor.call() rejects policy-denied actions
 * - ToolRegistry.get().clear() empties registry
 * - ToolRegistry.get().summary() returns formatted string
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  zakTool,
  ToolRegistry,
  ToolExecutor,
  type ZakToolFunction,
  type ToolMetadata,
} from "../src/core/tools/substrate.js";
import {
  createAgentContext,
  type AgentContext,
} from "../src/core/runtime/agent.js";
import type { AgentDSL } from "../src/core/dsl/schema.js";

// ---------------------------------------------------------------------------
// Helper: create a valid AgentDSL for tool testing
// ---------------------------------------------------------------------------

function makeToolTestDSL(overrides: {
  tools?: string[];
  allowed_actions?: string[];
  denied_actions?: string[];
  environment_scope?: string[];
  autonomy_level?: string;
} = {}): AgentDSL {
  return {
    agent: {
      id: "tool-test-agent-v1",
      name: "Tool Test Agent",
      domain: "appsec",
      version: "1.0.0",
    },
    intent: {
      goal: "Test tool substrate",
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
      sandbox_profile: "standard",
      audit_level: "standard",
    },
  } as AgentDSL;
}

function makeToolTestContext(overrides: Parameters<typeof makeToolTestDSL>[0] = {}): AgentContext {
  return createAgentContext({
    tenantId: "test-tenant",
    traceId: "trace-tool-001",
    dsl: makeToolTestDSL(overrides),
    environment: "staging",
  });
}

// ---------------------------------------------------------------------------
// Clear tool registry before each test
// ---------------------------------------------------------------------------

beforeEach(() => {
  ToolRegistry.get().clear();
});

// ---------------------------------------------------------------------------
// zakTool() registers a tool in the ToolRegistry
// ---------------------------------------------------------------------------
describe("zakTool() registers a tool in the ToolRegistry", () => {
  it("registers a tool and returns the decorated function", () => {
    const myTool = zakTool({
      name: "read_asset",
      description: "Read an asset node",
    })((_ctx: AgentContext, assetId: string) => {
      return { id: assetId };
    });

    expect(myTool._zakTool).toBeDefined();
    expect(myTool._zakTool.name).toBe("read_asset");
  });

  it("sets the correct actionId from name by default", () => {
    const myTool = zakTool({
      name: "read_asset",
    })((_ctx: AgentContext) => null);

    expect(myTool._zakTool.actionId).toBe("read_asset");
  });

  it("uses custom actionId when provided", () => {
    const myTool = zakTool({
      name: "Read Asset",
      actionId: "custom_read_asset",
    })((_ctx: AgentContext) => null);

    expect(myTool._zakTool.actionId).toBe("custom_read_asset");
  });

  it("converts name to lowercase with underscores for actionId", () => {
    const myTool = zakTool({
      name: "Read Asset Data",
    })((_ctx: AgentContext) => null);

    // actionId is: opts.name.toLowerCase().replace(/ /g, "_")
    expect(myTool._zakTool.actionId).toBe("read_asset_data");
  });

  it("sets default description to empty string", () => {
    const myTool = zakTool({
      name: "my_tool",
    })((_ctx: AgentContext) => null);

    expect(myTool._zakTool.description).toBe("");
  });

  it("sets requiresContext to true by default", () => {
    const myTool = zakTool({
      name: "my_tool",
    })((_ctx: AgentContext) => null);

    expect(myTool._zakTool.requiresContext).toBe(true);
  });

  it("allows requiresContext=false", () => {
    const myTool = zakTool({
      name: "pure_tool",
      requiresContext: false,
    })(() => 42);

    expect(myTool._zakTool.requiresContext).toBe(false);
  });

  it("sets tags to empty array by default", () => {
    const myTool = zakTool({
      name: "my_tool",
    })((_ctx: AgentContext) => null);

    expect(myTool._zakTool.tags).toEqual([]);
  });

  it("accepts custom tags", () => {
    const myTool = zakTool({
      name: "my_tool",
      tags: ["read", "asset"],
    })((_ctx: AgentContext) => null);

    expect(myTool._zakTool.tags).toEqual(["read", "asset"]);
  });

  it("tool is findable in the registry after registration", () => {
    zakTool({
      name: "registered_tool",
      description: "A test tool",
    })((_ctx: AgentContext) => null);

    expect(ToolRegistry.get().isRegistered("registered_tool")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ToolRegistry.get().allTools() lists registered tools
// ---------------------------------------------------------------------------
describe("ToolRegistry.get().allTools() lists registered tools", () => {
  it("returns empty array when no tools are registered", () => {
    expect(ToolRegistry.get().allTools()).toEqual([]);
  });

  it("returns metadata for all registered tools", () => {
    zakTool({ name: "tool_a", description: "Tool A" })(
      (_ctx: AgentContext) => null
    );
    zakTool({ name: "tool_b", description: "Tool B" })(
      (_ctx: AgentContext) => null
    );

    const all = ToolRegistry.get().allTools();
    expect(all).toHaveLength(2);
    const names = all.map((m) => m.name);
    expect(names).toContain("tool_a");
    expect(names).toContain("tool_b");
  });

  it("returns ToolMetadata objects", () => {
    zakTool({
      name: "metadata_tool",
      description: "Has metadata",
      tags: ["test"],
    })((_ctx: AgentContext) => null);

    const all = ToolRegistry.get().allTools();
    expect(all[0].name).toBe("metadata_tool");
    expect(all[0].description).toBe("Has metadata");
    expect(all[0].tags).toEqual(["test"]);
    expect(all[0].actionId).toBe("metadata_tool");
    expect(all[0].requiresContext).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ToolRegistry.get().isRegistered() works
// ---------------------------------------------------------------------------
describe("ToolRegistry.get().isRegistered() works", () => {
  it("returns true for a registered tool", () => {
    zakTool({ name: "check_tool" })((_ctx: AgentContext) => null);
    expect(ToolRegistry.get().isRegistered("check_tool")).toBe(true);
  });

  it("returns false for an unregistered tool", () => {
    expect(ToolRegistry.get().isRegistered("nonexistent")).toBe(false);
  });

  it("returns false after clearing the registry", () => {
    zakTool({ name: "temp_tool" })((_ctx: AgentContext) => null);
    ToolRegistry.get().clear();
    expect(ToolRegistry.get().isRegistered("temp_tool")).toBe(false);
  });

  it("checks by actionId, not by name (when custom actionId differs)", () => {
    zakTool({
      name: "Display Name",
      actionId: "display_action",
    })((_ctx: AgentContext) => null);

    // The registry key is actionId, not name
    expect(ToolRegistry.get().isRegistered("display_action")).toBe(true);
    expect(ToolRegistry.get().isRegistered("Display Name")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ToolExecutor.call() invokes the tool with context
// ---------------------------------------------------------------------------
describe("ToolExecutor.call() invokes the tool with context", () => {
  it("calls the tool function and returns its result", () => {
    const readAsset = zakTool({
      name: "read_asset",
      description: "Read an asset",
    })((_ctx: AgentContext, assetId: string) => {
      return { id: assetId, type: "server" };
    });

    // tools list empty means all tools are allowed
    const ctx = makeToolTestContext({ tools: [] });
    const result = ToolExecutor.call(
      readAsset as ZakToolFunction,
      ctx,
      { assetId: "srv-001" }
    );
    expect(result).toEqual({ id: "srv-001", type: "server" });
  });

  it("injects AgentContext as first arg when requiresContext=true", () => {
    let receivedCtx: AgentContext | null = null;
    const ctxTool = zakTool({
      name: "ctx_tool",
      requiresContext: true,
    })((ctx: AgentContext) => {
      receivedCtx = ctx;
      return "ok";
    });

    const ctx = makeToolTestContext({ tools: [] });
    ToolExecutor.call(ctxTool as ZakToolFunction, ctx, {});
    expect(receivedCtx).not.toBeNull();
    expect(receivedCtx!.tenantId).toBe("test-tenant");
  });

  it("does not inject AgentContext when requiresContext=false", () => {
    const args: unknown[] = [];
    const pureTool = zakTool({
      name: "pure_fn",
      requiresContext: false,
    })((...a: unknown[]) => {
      args.push(...a);
      return "pure result";
    });

    const ctx = makeToolTestContext({ tools: [] });
    const result = ToolExecutor.call(
      pureTool as ZakToolFunction,
      ctx,
      { x: 1, y: 2 }
    );
    expect(result).toBe("pure result");
    // Should receive kwargs values, not context
    expect(args).toEqual([1, 2]);
  });

  it("allows tool when capabilities.tools is empty (wildcard)", () => {
    const myTool = zakTool({
      name: "any_tool",
    })((_ctx: AgentContext) => "allowed");

    const ctx = makeToolTestContext({ tools: [] });
    expect(() =>
      ToolExecutor.call(myTool as ZakToolFunction, ctx, {})
    ).not.toThrow();
  });

  it("allows tool when it is listed in capabilities.tools", () => {
    const myTool = zakTool({
      name: "listed_tool",
    })((_ctx: AgentContext) => "listed");

    const ctx = makeToolTestContext({ tools: ["listed_tool"] });
    const result = ToolExecutor.call(myTool as ZakToolFunction, ctx, {});
    expect(result).toBe("listed");
  });
});

// ---------------------------------------------------------------------------
// ToolExecutor.call() rejects tools not in capabilities.tools
// ---------------------------------------------------------------------------
describe("ToolExecutor.call() rejects tools not in capabilities.tools", () => {
  it("throws when tool actionId is not in capabilities.tools", () => {
    const unlisted = zakTool({
      name: "unlisted_tool",
    })((_ctx: AgentContext) => "should not run");

    const ctx = makeToolTestContext({ tools: ["other_tool"] });
    expect(() =>
      ToolExecutor.call(unlisted as ZakToolFunction, ctx, {})
    ).toThrow("not declared in agent capabilities.tools");
  });

  it("includes declared tools in error message", () => {
    const unlisted = zakTool({
      name: "missing_tool",
    })((_ctx: AgentContext) => null);

    const ctx = makeToolTestContext({ tools: ["read_asset", "list_assets"] });
    expect(() =>
      ToolExecutor.call(unlisted as ZakToolFunction, ctx, {})
    ).toThrow("read_asset");
  });

  it("throws for non-zakTool functions", () => {
    const plainFn = (() => "not a tool") as unknown as ZakToolFunction;
    const ctx = makeToolTestContext();
    expect(() => ToolExecutor.call(plainFn, ctx, {})).toThrow(
      "is not a zakTool"
    );
  });
});

// ---------------------------------------------------------------------------
// ToolExecutor.call() rejects policy-denied actions
// ---------------------------------------------------------------------------
describe("ToolExecutor.call() rejects policy-denied actions", () => {
  it("throws when the tool's action is in denied_actions", () => {
    const deniedTool = zakTool({
      name: "denied_tool",
    })((_ctx: AgentContext) => "should not run");

    const ctx = makeToolTestContext({
      tools: [],
      denied_actions: ["denied_tool"],
    });
    expect(() =>
      ToolExecutor.call(deniedTool as ZakToolFunction, ctx, {})
    ).toThrow("Policy denied");
  });

  it("includes tool name in the policy error message", () => {
    const blockedTool = zakTool({
      name: "blocked_action",
      description: "A blocked tool",
    })((_ctx: AgentContext) => null);

    const ctx = makeToolTestContext({
      tools: [],
      denied_actions: ["blocked_action"],
    });
    expect(() =>
      ToolExecutor.call(blockedTool as ZakToolFunction, ctx, {})
    ).toThrow("blocked_action");
  });

  it("throws when tool action is not in allow-list (when allow-list is non-empty)", () => {
    const notAllowed = zakTool({
      name: "not_allowed_tool",
    })((_ctx: AgentContext) => null);

    const ctx = makeToolTestContext({
      tools: [],
      allowed_actions: ["some_other_action"],
    });
    expect(() =>
      ToolExecutor.call(notAllowed as ZakToolFunction, ctx, {})
    ).toThrow("Policy denied");
  });

  it("throws for observe-only agent with mutating tool action", () => {
    const writeTool = zakTool({
      name: "write_data",
    })((_ctx: AgentContext) => null);

    const ctx = makeToolTestContext({
      tools: [],
      autonomy_level: "observe",
    });
    expect(() =>
      ToolExecutor.call(writeTool as ZakToolFunction, ctx, {})
    ).toThrow("Policy denied");
  });
});

// ---------------------------------------------------------------------------
// ToolRegistry.get().clear() empties registry
// ---------------------------------------------------------------------------
describe("ToolRegistry.get().clear() empties registry", () => {
  it("removes all tools", () => {
    zakTool({ name: "tool_1" })((_ctx: AgentContext) => null);
    zakTool({ name: "tool_2" })((_ctx: AgentContext) => null);
    expect(ToolRegistry.get().allTools()).toHaveLength(2);

    ToolRegistry.get().clear();
    expect(ToolRegistry.get().allTools()).toEqual([]);
  });

  it("isRegistered returns false after clear", () => {
    zakTool({ name: "clearable" })((_ctx: AgentContext) => null);
    expect(ToolRegistry.get().isRegistered("clearable")).toBe(true);

    ToolRegistry.get().clear();
    expect(ToolRegistry.get().isRegistered("clearable")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ToolRegistry.get().summary() returns formatted string
// ---------------------------------------------------------------------------
describe("ToolRegistry.get().summary() returns formatted string", () => {
  it("returns 'No tools registered.' when empty", () => {
    expect(ToolRegistry.get().summary()).toBe("No tools registered.");
  });

  it("includes header and tool details when tools are registered", () => {
    zakTool({
      name: "scan_asset",
      description: "Scan an asset for vulnerabilities",
    })((_ctx: AgentContext) => null);

    const summary = ToolRegistry.get().summary();
    expect(summary).toContain("Registered tools:");
    expect(summary).toContain("scan_asset");
    expect(summary).toContain("Scan an asset for vulnerabilities");
  });

  it("lists multiple tools", () => {
    zakTool({ name: "tool_alpha", description: "Alpha tool" })(
      (_ctx: AgentContext) => null
    );
    zakTool({ name: "tool_beta", description: "Beta tool" })(
      (_ctx: AgentContext) => null
    );

    const summary = ToolRegistry.get().summary();
    expect(summary).toContain("tool_alpha");
    expect(summary).toContain("tool_beta");
    expect(summary).toContain("Alpha tool");
    expect(summary).toContain("Beta tool");
  });
});

// ---------------------------------------------------------------------------
// ToolRegistry.get().getTool() returns metadata and function
// ---------------------------------------------------------------------------
describe("ToolRegistry.get().getTool()", () => {
  it("returns [metadata, fn] for a registered tool", () => {
    const fn = (_ctx: AgentContext) => "result";
    zakTool({ name: "get_test", description: "Get test tool" })(fn);

    const entry = ToolRegistry.get().getTool("get_test");
    expect(entry).toBeDefined();
    const [meta, toolFn] = entry!;
    expect(meta.name).toBe("get_test");
    expect(meta.description).toBe("Get test tool");
    expect(typeof toolFn).toBe("function");
  });

  it("returns undefined for unregistered actionId", () => {
    const entry = ToolRegistry.get().getTool("nonexistent");
    expect(entry).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// ToolRegistry singleton
// ---------------------------------------------------------------------------
describe("ToolRegistry.get() singleton", () => {
  it("returns the same instance across calls", () => {
    const r1 = ToolRegistry.get();
    const r2 = ToolRegistry.get();
    expect(r1).toBe(r2);
  });
});
