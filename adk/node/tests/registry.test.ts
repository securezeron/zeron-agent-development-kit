/**
 * ZAK Agent Registry Tests (Phase 2)
 *
 * Covers:
 * - register() adds an agent to the registry
 * - resolve() returns the registered agent class
 * - resolve() throws for unknown domain
 * - resolve() throws EditionError for enterprise agents in open-source mode
 * - allDomains() returns sorted domains (filtered by edition)
 * - allRegistrations() filters by edition
 * - isRegistered() works
 * - unregister() removes agents
 * - clear() empties registry
 * - override inserts at front
 * - registerAgent() convenience function
 * - summary() returns formatted string
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";

import {
  AgentRegistry,
  registerAgent,
  type AgentRegistration,
} from "../src/core/runtime/registry.js";
import {
  BaseAgent,
  type AgentContext,
  type AgentResult,
  agentResultOk,
} from "../src/core/runtime/agent.js";
import { EditionError } from "../src/core/edition.js";

// ---------------------------------------------------------------------------
// Test agent classes
// ---------------------------------------------------------------------------

class TestAppsecAgent extends BaseAgent {
  execute(context: AgentContext): AgentResult {
    return agentResultOk(context, { scanned: true });
  }
}

class TestRiskAgent extends BaseAgent {
  execute(context: AgentContext): AgentResult {
    return agentResultOk(context, { risk: 0.42 });
  }
}

class TestSupplyChainAgent extends BaseAgent {
  execute(context: AgentContext): AgentResult {
    return agentResultOk(context, { deps: [] });
  }
}

class OverrideAppsecAgent extends BaseAgent {
  execute(context: AgentContext): AgentResult {
    return agentResultOk(context, { overridden: true });
  }
}

class EnterpriseOnlyAgent extends BaseAgent {
  execute(context: AgentContext): AgentResult {
    return agentResultOk(context, { enterprise: true });
  }
}

// ---------------------------------------------------------------------------
// Save and restore ZAK_EDITION
// ---------------------------------------------------------------------------
let originalEdition: string | undefined;

beforeEach(() => {
  originalEdition = process.env.ZAK_EDITION;
  // Default to open-source for most tests
  delete process.env.ZAK_EDITION;
  AgentRegistry.get().clear();
});

afterEach(() => {
  if (originalEdition === undefined) {
    delete process.env.ZAK_EDITION;
  } else {
    process.env.ZAK_EDITION = originalEdition;
  }
  AgentRegistry.get().clear();
});

// ---------------------------------------------------------------------------
// register() adds an agent to the registry
// ---------------------------------------------------------------------------
describe("register() adds an agent to the registry", () => {
  it("registers an agent class for a domain", () => {
    const reg = AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    expect(reg.domain).toBe("appsec");
    expect(reg.agentClass).toBe(TestAppsecAgent);
    expect(reg.className).toBe("TestAppsecAgent");
  });

  it("returns an AgentRegistration with correct defaults", () => {
    const reg = AgentRegistry.get().register("risk_quant", TestRiskAgent);
    expect(reg.version).toBe("1.0.0");
    expect(reg.edition).toBe("enterprise");
    expect(reg.description).toBe("TestRiskAgent");
  });

  it("accepts custom description and version", () => {
    const reg = AgentRegistry.get().register("appsec", TestAppsecAgent, {
      description: "Application Security Scanner",
      version: "2.1.0",
      edition: "open-source",
    });
    expect(reg.description).toBe("Application Security Scanner");
    expect(reg.version).toBe("2.1.0");
  });

  it("can register multiple agents for the same domain", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("appsec", OverrideAppsecAgent, {
      edition: "open-source",
    });
    const all = AgentRegistry.get().resolveAll("appsec");
    expect(all).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// resolve() returns the registered agent class
// ---------------------------------------------------------------------------
describe("resolve() returns the registered agent class", () => {
  it("resolves a registered open-source agent", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    const cls = AgentRegistry.get().resolve("appsec");
    expect(cls).toBe(TestAppsecAgent);
  });

  it("resolves an enterprise agent when edition is enterprise", () => {
    process.env.ZAK_EDITION = "enterprise";
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "enterprise",
    });
    const cls = AgentRegistry.get().resolve("risk_quant");
    expect(cls).toBe(TestRiskAgent);
  });

  it("resolves the first registered agent when multiple exist", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("appsec", OverrideAppsecAgent, {
      edition: "open-source",
    });
    const cls = AgentRegistry.get().resolve("appsec");
    expect(cls).toBe(TestAppsecAgent);
  });

  it("can instantiate the resolved agent class", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    const cls = AgentRegistry.get().resolve("appsec");
    const agent = new cls();
    expect(agent).toBeInstanceOf(TestAppsecAgent);
    expect(agent).toBeInstanceOf(BaseAgent);
  });
});

// ---------------------------------------------------------------------------
// resolve() throws for unknown domain
// ---------------------------------------------------------------------------
describe("resolve() throws for unknown domain", () => {
  it("throws when no agent is registered for the domain", () => {
    expect(() => AgentRegistry.get().resolve("unknown_domain")).toThrow(
      "No agent registered for domain 'unknown_domain'"
    );
  });

  it("throws with available domains listed", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    expect(() => AgentRegistry.get().resolve("risk_quant")).toThrow(
      "Available domains:"
    );
  });

  it("includes the requested domain name in the error", () => {
    expect(() => AgentRegistry.get().resolve("nonexistent")).toThrow(
      "nonexistent"
    );
  });
});

// ---------------------------------------------------------------------------
// resolve() throws EditionError for enterprise agents in open-source mode
// ---------------------------------------------------------------------------
describe("resolve() throws EditionError for enterprise agents in open-source mode", () => {
  it("throws EditionError when resolving enterprise agent in OSS mode", () => {
    delete process.env.ZAK_EDITION;
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "enterprise",
    });
    expect(() => AgentRegistry.get().resolve("risk_quant")).toThrow(
      EditionError
    );
  });

  it("error message mentions enterprise edition", () => {
    delete process.env.ZAK_EDITION;
    AgentRegistry.get().register("api_security", EnterpriseOnlyAgent, {
      edition: "enterprise",
    });
    expect(() => AgentRegistry.get().resolve("api_security")).toThrow(
      "enterprise edition only"
    );
  });

  it("error message mentions ZAK_EDITION env var", () => {
    delete process.env.ZAK_EDITION;
    AgentRegistry.get().register("cloud_posture", EnterpriseOnlyAgent, {
      edition: "enterprise",
    });
    expect(() => AgentRegistry.get().resolve("cloud_posture")).toThrow(
      "ZAK_EDITION"
    );
  });

  it("does not throw when ZAK_EDITION is enterprise", () => {
    process.env.ZAK_EDITION = "enterprise";
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "enterprise",
    });
    expect(() => AgentRegistry.get().resolve("risk_quant")).not.toThrow();
  });

  it("does not throw for open-source agents regardless of edition", () => {
    delete process.env.ZAK_EDITION;
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    expect(() => AgentRegistry.get().resolve("appsec")).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// allDomains() returns sorted domains
// ---------------------------------------------------------------------------
describe("allDomains() returns sorted domains", () => {
  it("returns domains in alphabetical order", () => {
    AgentRegistry.get().register("supply_chain", TestSupplyChainAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "open-source",
    });
    const domains = AgentRegistry.get().allDomains();
    expect(domains).toEqual(["appsec", "risk_quant", "supply_chain"]);
  });

  it("returns empty array when no agents are registered", () => {
    const domains = AgentRegistry.get().allDomains();
    expect(domains).toEqual([]);
  });

  it("excludes enterprise domains in open-source mode", () => {
    delete process.env.ZAK_EDITION;
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "enterprise",
    });
    const domains = AgentRegistry.get().allDomains();
    expect(domains).toEqual(["appsec"]);
    expect(domains).not.toContain("risk_quant");
  });

  it("includes all domains in enterprise mode", () => {
    process.env.ZAK_EDITION = "enterprise";
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "enterprise",
    });
    const domains = AgentRegistry.get().allDomains();
    expect(domains).toContain("appsec");
    expect(domains).toContain("risk_quant");
  });
});

// ---------------------------------------------------------------------------
// allRegistrations() filters by edition
// ---------------------------------------------------------------------------
describe("allRegistrations() filters by edition", () => {
  it("returns only open-source registrations in OSS mode", () => {
    delete process.env.ZAK_EDITION;
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "enterprise",
    });
    const regs = AgentRegistry.get().allRegistrations();
    expect(regs).toHaveLength(1);
    expect(regs[0].domain).toBe("appsec");
  });

  it("returns all registrations in enterprise mode", () => {
    process.env.ZAK_EDITION = "enterprise";
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "enterprise",
    });
    const regs = AgentRegistry.get().allRegistrations();
    expect(regs).toHaveLength(2);
  });

  it("returns empty array when no agents are registered", () => {
    const regs = AgentRegistry.get().allRegistrations();
    expect(regs).toEqual([]);
  });

  it("allRegistrationsUnfiltered() returns everything regardless of edition", () => {
    delete process.env.ZAK_EDITION;
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "enterprise",
    });
    const regs = AgentRegistry.get().allRegistrationsUnfiltered();
    expect(regs).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// isRegistered() works
// ---------------------------------------------------------------------------
describe("isRegistered() works", () => {
  it("returns true for a registered domain", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    expect(AgentRegistry.get().isRegistered("appsec")).toBe(true);
  });

  it("returns false for an unregistered domain", () => {
    expect(AgentRegistry.get().isRegistered("unknown_domain")).toBe(false);
  });

  it("returns false after unregistering", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().unregister("appsec");
    expect(AgentRegistry.get().isRegistered("appsec")).toBe(false);
  });

  it("returns true even for enterprise agents (edition-agnostic)", () => {
    delete process.env.ZAK_EDITION;
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "enterprise",
    });
    // isRegistered only checks if the domain has entries, not edition
    expect(AgentRegistry.get().isRegistered("risk_quant")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// unregister() removes agents
// ---------------------------------------------------------------------------
describe("unregister() removes agents", () => {
  it("removes all agents for a domain when no class specified", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().unregister("appsec");
    expect(AgentRegistry.get().isRegistered("appsec")).toBe(false);
  });

  it("removes only the specified class when class is provided", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("appsec", OverrideAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().unregister("appsec", TestAppsecAgent);
    const all = AgentRegistry.get().resolveAll("appsec");
    expect(all).toHaveLength(1);
    expect(all[0].agentClass).toBe(OverrideAppsecAgent);
  });

  it("removes the domain entirely when last class is removed", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().unregister("appsec", TestAppsecAgent);
    expect(AgentRegistry.get().isRegistered("appsec")).toBe(false);
  });

  it("is a no-op for unregistered domain", () => {
    // Should not throw
    expect(() =>
      AgentRegistry.get().unregister("nonexistent")
    ).not.toThrow();
  });

  it("is a no-op when the specified class is not found for that domain", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().unregister("appsec", OverrideAppsecAgent);
    // Original should still be registered
    expect(AgentRegistry.get().isRegistered("appsec")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// clear() empties registry
// ---------------------------------------------------------------------------
describe("clear() empties registry", () => {
  it("removes all registrations", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("risk_quant", TestRiskAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().clear();
    expect(AgentRegistry.get().isRegistered("appsec")).toBe(false);
    expect(AgentRegistry.get().isRegistered("risk_quant")).toBe(false);
  });

  it("allDomains returns empty after clear", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().clear();
    expect(AgentRegistry.get().allDomains()).toEqual([]);
  });

  it("allRegistrations returns empty after clear", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().clear();
    expect(AgentRegistry.get().allRegistrations()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// override inserts at front
// ---------------------------------------------------------------------------
describe("override inserts at front", () => {
  it("override=true inserts the new agent before existing ones", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("appsec", OverrideAppsecAgent, {
      edition: "open-source",
      override: true,
    });
    const cls = AgentRegistry.get().resolve("appsec");
    expect(cls).toBe(OverrideAppsecAgent);
  });

  it("resolveAll shows override agent at index 0", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("appsec", OverrideAppsecAgent, {
      edition: "open-source",
      override: true,
    });
    const all = AgentRegistry.get().resolveAll("appsec");
    expect(all[0].agentClass).toBe(OverrideAppsecAgent);
    expect(all[1].agentClass).toBe(TestAppsecAgent);
  });

  it("without override, new agent is appended at end", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("appsec", OverrideAppsecAgent, {
      edition: "open-source",
      override: false,
    });
    const all = AgentRegistry.get().resolveAll("appsec");
    expect(all[0].agentClass).toBe(TestAppsecAgent);
    expect(all[1].agentClass).toBe(OverrideAppsecAgent);
  });
});

// ---------------------------------------------------------------------------
// registerAgent() convenience function
// ---------------------------------------------------------------------------
describe("registerAgent() convenience function", () => {
  it("registers an agent via the top-level function", () => {
    const reg = registerAgent("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    expect(reg.domain).toBe("appsec");
    expect(reg.agentClass).toBe(TestAppsecAgent);
  });

  it("the agent is resolvable after registerAgent()", () => {
    registerAgent("supply_chain", TestSupplyChainAgent, {
      edition: "open-source",
    });
    const cls = AgentRegistry.get().resolve("supply_chain");
    expect(cls).toBe(TestSupplyChainAgent);
  });

  it("accepts all options", () => {
    const reg = registerAgent("appsec", TestAppsecAgent, {
      description: "My agent",
      version: "3.0.0",
      edition: "open-source",
      override: false,
    });
    expect(reg.description).toBe("My agent");
    expect(reg.version).toBe("3.0.0");
    expect(reg.edition).toBe("open-source");
  });

  it("defaults to enterprise edition when edition is not specified", () => {
    const reg = registerAgent("risk_quant", TestRiskAgent);
    expect(reg.edition).toBe("enterprise");
  });
});

// ---------------------------------------------------------------------------
// summary() returns formatted string
// ---------------------------------------------------------------------------
describe("summary() returns formatted string", () => {
  it("returns 'No agents registered.' when registry is empty", () => {
    const summary = AgentRegistry.get().summary();
    expect(summary).toBe("No agents registered.");
  });

  it("includes header line and agent class names", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    const summary = AgentRegistry.get().summary();
    expect(summary).toContain("Registered agents:");
    expect(summary).toContain("appsec");
    expect(summary).toContain("TestAppsecAgent");
  });

  it("shows alternatives count when multiple agents are registered", () => {
    process.env.ZAK_EDITION = "enterprise";
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("appsec", OverrideAppsecAgent, {
      edition: "open-source",
    });
    const summary = AgentRegistry.get().summary();
    expect(summary).toContain("+1 alternatives");
  });

  it("lists multiple domains sorted", () => {
    AgentRegistry.get().register("supply_chain", TestSupplyChainAgent, {
      edition: "open-source",
    });
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    const summary = AgentRegistry.get().summary();
    // appsec should appear before supply_chain (alphabetical)
    const appsecIdx = summary.indexOf("appsec");
    const supplyIdx = summary.indexOf("supply_chain");
    expect(appsecIdx).toBeLessThan(supplyIdx);
  });
});

// ---------------------------------------------------------------------------
// resolveAll() returns a defensive copy
// ---------------------------------------------------------------------------
describe("resolveAll()", () => {
  it("returns empty array for unregistered domain", () => {
    const all = AgentRegistry.get().resolveAll("nonexistent");
    expect(all).toEqual([]);
  });

  it("returns a copy (mutations do not affect the registry)", () => {
    AgentRegistry.get().register("appsec", TestAppsecAgent, {
      edition: "open-source",
    });
    const all = AgentRegistry.get().resolveAll("appsec");
    all.pop();
    const allAgain = AgentRegistry.get().resolveAll("appsec");
    expect(allAgain).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Singleton behavior
// ---------------------------------------------------------------------------
describe("AgentRegistry.get() singleton", () => {
  it("returns the same instance across calls", () => {
    const r1 = AgentRegistry.get();
    const r2 = AgentRegistry.get();
    expect(r1).toBe(r2);
  });
});
