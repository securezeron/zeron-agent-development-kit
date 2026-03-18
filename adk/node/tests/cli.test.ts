/**
 * ZAK CLI Tests — Domain Templates and CLI infrastructure.
 *
 * Covers:
 * - DOMAIN_TEMPLATES contains all 5 OSS domains
 * - OSS_DOMAINS matches expected domain list
 * - Each template's YAML validates against AgentDSLSchema
 * - Template placeholder substitution works correctly
 * - DomainTemplate structure is correct
 */

import { describe, it, expect } from "vitest";

import {
  DOMAIN_TEMPLATES,
  OSS_DOMAINS,
  type DomainTemplate,
} from "../src/cli/templates.js";
import { AgentDSLSchema } from "../src/core/dsl/schema.js";
import { validateAgentString } from "../src/core/dsl/parser.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Replace template placeholders with safe test values. */
function renderYaml(template: string): string {
  return template
    .replaceAll("{agentId}", "test-agent-v1")
    .replaceAll("{agentName}", "Test Agent")
    .replaceAll("{className}", "TestAgent");
}

// ---------------------------------------------------------------------------
// 1. OSS_DOMAINS contains expected domains
// ---------------------------------------------------------------------------
describe("OSS_DOMAINS", () => {
  it("contains exactly 5 domains", () => {
    expect(OSS_DOMAINS).toHaveLength(5);
  });

  it("includes generic", () => {
    expect(OSS_DOMAINS).toContain("generic");
  });

  it("includes risk_quant", () => {
    expect(OSS_DOMAINS).toContain("risk_quant");
  });

  it("includes vuln_triage", () => {
    expect(OSS_DOMAINS).toContain("vuln_triage");
  });

  it("includes appsec", () => {
    expect(OSS_DOMAINS).toContain("appsec");
  });

  it("includes compliance", () => {
    expect(OSS_DOMAINS).toContain("compliance");
  });

  it("matches the expected domain list exactly", () => {
    expect([...OSS_DOMAINS]).toEqual([
      "generic",
      "risk_quant",
      "vuln_triage",
      "appsec",
      "compliance",
    ]);
  });
});

// ---------------------------------------------------------------------------
// 2. DOMAIN_TEMPLATES has all 5 OSS domains
// ---------------------------------------------------------------------------
describe("DOMAIN_TEMPLATES", () => {
  it("has an entry for every OSS domain", () => {
    for (const domain of OSS_DOMAINS) {
      expect(DOMAIN_TEMPLATES).toHaveProperty(domain);
    }
  });

  it("has at least 5 templates", () => {
    expect(Object.keys(DOMAIN_TEMPLATES).length).toBeGreaterThanOrEqual(5);
  });

  it("each template has the required DomainTemplate fields", () => {
    for (const [domain, tmpl] of Object.entries(DOMAIN_TEMPLATES)) {
      expect(tmpl).toHaveProperty("domain");
      expect(tmpl).toHaveProperty("yamlTemplate");
      expect(tmpl).toHaveProperty("tsTemplate");
      expect(typeof tmpl.domain).toBe("string");
      expect(typeof tmpl.yamlTemplate).toBe("string");
      expect(typeof tmpl.tsTemplate).toBe("string");
      expect(tmpl.domain).toBe(domain);
    }
  });

  it("each YAML template contains {agentId} placeholder", () => {
    for (const tmpl of Object.values(DOMAIN_TEMPLATES)) {
      expect(tmpl.yamlTemplate).toContain("{agentId}");
    }
  });

  it("each YAML template contains {agentName} placeholder", () => {
    for (const tmpl of Object.values(DOMAIN_TEMPLATES)) {
      expect(tmpl.yamlTemplate).toContain("{agentName}");
    }
  });

  it("each TS template contains {className} placeholder", () => {
    for (const tmpl of Object.values(DOMAIN_TEMPLATES)) {
      expect(tmpl.tsTemplate).toContain("{className}");
    }
  });

  it("each TS template contains {agentName} placeholder", () => {
    for (const tmpl of Object.values(DOMAIN_TEMPLATES)) {
      expect(tmpl.tsTemplate).toContain("{agentName}");
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Each template's YAML validates against AgentDSLSchema
// ---------------------------------------------------------------------------
describe("Template YAML schema validation", () => {
  for (const [domain, tmpl] of Object.entries(DOMAIN_TEMPLATES)) {
    describe(`${domain} template`, () => {
      it("produces valid YAML after placeholder substitution", () => {
        const yamlContent = renderYaml(tmpl.yamlTemplate);
        const result = validateAgentString(yamlContent);
        expect(result.valid).toBe(true);
        expect(result.errors).toEqual([]);
      });

      it("has the correct agent ID after substitution", () => {
        const yamlContent = renderYaml(tmpl.yamlTemplate);
        const result = validateAgentString(yamlContent);
        expect(result.agentId).toBe("test-agent-v1");
      });

      it("parses successfully through AgentDSLSchema", () => {
        const yamlContent = renderYaml(tmpl.yamlTemplate);
        // Use js-yaml to parse the rendered template, then validate with Zod
        // This is equivalent to what validateAgentString does internally
        const yaml = require("js-yaml");
        const raw = yaml.load(yamlContent);
        const parsed = AgentDSLSchema.parse(raw);

        expect(parsed.agent.id).toBe("test-agent-v1");
        expect(parsed.agent.name).toBe("Test Agent");
        expect(parsed.agent.version).toBe("1.0.0");
        expect(parsed.intent.goal).toBeTruthy();
        expect(parsed.reasoning.mode).toBeTruthy();
      });

      it("uses a valid domain in the YAML", () => {
        const yamlContent = renderYaml(tmpl.yamlTemplate);
        const yaml = require("js-yaml");
        const raw = yaml.load(yamlContent) as Record<string, Record<string, string>>;
        // The domain in the YAML must be a valid Domain enum value
        const agentDomain = raw.agent.domain;
        expect(typeof agentDomain).toBe("string");
        expect(agentDomain.length).toBeGreaterThan(0);
      });

      it("includes intent.goal in the YAML", () => {
        const yamlContent = renderYaml(tmpl.yamlTemplate);
        const yaml = require("js-yaml");
        const raw = yaml.load(yamlContent) as Record<string, Record<string, string>>;
        expect(raw.intent.goal).toBeTruthy();
      });

      it("includes reasoning.mode in the YAML", () => {
        const yamlContent = renderYaml(tmpl.yamlTemplate);
        const yaml = require("js-yaml");
        const raw = yaml.load(yamlContent) as Record<string, Record<string, string>>;
        expect(raw.reasoning.mode).toBeTruthy();
      });
    });
  }
});

// ---------------------------------------------------------------------------
// 4. Template TS code contains expected patterns
// ---------------------------------------------------------------------------
describe("Template TypeScript code structure", () => {
  for (const [domain, tmpl] of Object.entries(DOMAIN_TEMPLATES)) {
    describe(`${domain} TS template`, () => {
      it("extends BaseAgent", () => {
        expect(tmpl.tsTemplate).toContain("BaseAgent");
      });

      it("has an execute() method", () => {
        expect(tmpl.tsTemplate).toContain("execute(context: AgentContext)");
      });

      it("returns an AgentResult", () => {
        expect(tmpl.tsTemplate).toContain("agentResultOk(context");
      });

      it("calls registerAgent", () => {
        expect(tmpl.tsTemplate).toContain("registerAgent(");
      });

      it("imports from @zeron/zak", () => {
        expect(tmpl.tsTemplate).toContain("from \"@zeron/zak\"");
      });
    });
  }
});

// ---------------------------------------------------------------------------
// 5. YAML templates produce no-overlap in allowed/denied actions
// ---------------------------------------------------------------------------
describe("Template YAML boundary consistency", () => {
  for (const [domain, tmpl] of Object.entries(DOMAIN_TEMPLATES)) {
    it(`${domain} template has no overlap between allowed and denied actions`, () => {
      const yamlContent = renderYaml(tmpl.yamlTemplate);
      const yaml = require("js-yaml");
      const raw = yaml.load(yamlContent) as Record<
        string,
        Record<string, string[]>
      >;
      const allowed = raw.boundaries?.allowed_actions ?? [];
      const denied = raw.boundaries?.denied_actions ?? [];
      const overlap = allowed.filter((a: string) => denied.includes(a));
      expect(overlap).toEqual([]);
    });
  }
});
