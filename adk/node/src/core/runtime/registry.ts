/**
 * ZAK Agent Registry — function-based agent registration and domain discovery.
 *
 * Design:
 * - registerAgent(domain, cls, opts) registers a BaseAgent subclass as the handler for a domain
 * - AgentRegistry is a singleton that holds all registrations
 * - AgentExecutor uses it to resolve the right class for a DSL domain
 *
 * TypeScript equivalent of zak/core/runtime/registry.py.
 */

import { Edition, EditionError, getEdition } from "../edition.js";
import type { BaseAgent } from "./agent.js";

// ---------------------------------------------------------------------------
// AgentRegistration
// ---------------------------------------------------------------------------

export interface AgentRegistration {
  domain: string;
  agentClass: new () => BaseAgent;
  description: string;
  version: string;
  edition: string;
  className: string;
}

// ---------------------------------------------------------------------------
// Internal Registry
// ---------------------------------------------------------------------------

/** Agent constructor type */
export type AgentConstructor = new () => BaseAgent;

class InternalRegistry {
  private _registry = new Map<string, AgentRegistration[]>();

  register(
    domain: string,
    agentClass: AgentConstructor,
    opts: {
      description?: string;
      version?: string;
      edition?: string;
      override?: boolean;
    } = {}
  ): AgentRegistration {
    const {
      description = "",
      version = "1.0.0",
      edition = "enterprise",
      override = false,
    } = opts;

    const reg: AgentRegistration = {
      domain,
      agentClass,
      description: description || agentClass.name,
      version,
      edition,
      className: agentClass.name,
    };

    if (!this._registry.has(domain)) {
      this._registry.set(domain, []);
    }

    const entries = this._registry.get(domain)!;
    if (override) {
      entries.unshift(reg);
    } else {
      entries.push(reg);
    }

    return reg;
  }

  resolve(domain: string): AgentConstructor {
    const entries = this._registry.get(domain);
    if (!entries || entries.length === 0) {
      throw new Error(
        `No agent registered for domain '${domain}'. ` +
          `Available domains: [${[...this._registry.keys()].join(", ")}]`
      );
    }

    const reg = entries[0];
    if (reg.edition === "enterprise" && getEdition() !== Edition.ENTERPRISE) {
      throw new EditionError(
        `Agent '${domain}' is available in the enterprise edition only. ` +
          `Set ZAK_EDITION=enterprise to unlock all agents.`
      );
    }

    return reg.agentClass;
  }

  resolveAll(domain: string): AgentRegistration[] {
    return [...(this._registry.get(domain) ?? [])];
  }

  allDomains(): string[] {
    const current = getEdition();
    const domains: string[] = [];

    for (const [domain, regs] of this._registry.entries()) {
      if (
        regs.length > 0 &&
        (current === Edition.ENTERPRISE || regs[0].edition === "open-source")
      ) {
        domains.push(domain);
      }
    }

    return domains.sort();
  }

  allRegistrations(): AgentRegistration[] {
    const current = getEdition();
    const result: AgentRegistration[] = [];

    for (const regs of this._registry.values()) {
      for (const reg of regs) {
        if (current === Edition.ENTERPRISE || reg.edition === "open-source") {
          result.push(reg);
        }
      }
    }

    return result;
  }

  allRegistrationsUnfiltered(): AgentRegistration[] {
    const result: AgentRegistration[] = [];
    for (const regs of this._registry.values()) {
      result.push(...regs);
    }
    return result;
  }

  isRegistered(domain: string): boolean {
    const entries = this._registry.get(domain);
    return !!entries && entries.length > 0;
  }

  unregister(domain: string, agentClass?: AgentConstructor): void {
    if (!this._registry.has(domain)) return;

    if (!agentClass) {
      this._registry.delete(domain);
    } else {
      const filtered = (this._registry.get(domain) ?? []).filter(
        (r) => r.agentClass !== agentClass
      );
      if (filtered.length === 0) {
        this._registry.delete(domain);
      } else {
        this._registry.set(domain, filtered);
      }
    }
  }

  clear(): void {
    this._registry.clear();
  }

  summary(): string {
    if (this._registry.size === 0) {
      return "No agents registered.";
    }

    const lines = ["Registered agents:"];
    for (const domain of this.allDomains()) {
      const regs = this._registry.get(domain) ?? [];
      const primary = regs[0];
      const extras =
        regs.length > 1 ? ` (+${regs.length - 1} alternatives)` : "";
      lines.push(
        `  ${domain.padEnd(20)} \u2192 ${primary.className}${extras}`
      );
    }
    return lines.join("\n");
  }
}

// ---------------------------------------------------------------------------
// Global Singleton
// ---------------------------------------------------------------------------

let _registryInstance: InternalRegistry | null = null;

/**
 * Public access point for the global agent registry.
 */
export class AgentRegistry {
  static get(): InternalRegistry {
    if (_registryInstance === null) {
      _registryInstance = new InternalRegistry();
    }
    return _registryInstance;
  }
}

// ---------------------------------------------------------------------------
// registerAgent() — decorator-like function
// ---------------------------------------------------------------------------

/**
 * Register a BaseAgent subclass with the global AgentRegistry.
 *
 * @param domain     The security domain this agent handles.
 * @param agentClass The BaseAgent subclass to register.
 * @param opts       Optional: description, version, edition, override.
 *
 * @example
 * ```ts
 * class MyRiskAgent extends BaseAgent {
 *   execute(context: AgentContext): AgentResult {
 *     return agentResultOk(context, { score: 0.42 });
 *   }
 * }
 * registerAgent("risk_quant", MyRiskAgent, { edition: "open-source" });
 * ```
 */
export function registerAgent(
  domain: string,
  agentClass: AgentConstructor,
  opts: {
    description?: string;
    version?: string;
    edition?: string;
    override?: boolean;
  } = {}
): AgentRegistration {
  return AgentRegistry.get().register(domain, agentClass, opts);
}
