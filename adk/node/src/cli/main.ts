/**
 * ZAK CLI -- developer-facing commands for scaffolding, validating, and running agents.
 *
 * Commands:
 *   zak init --name <name> --domain <domain>  -- scaffold a new agent (YAML + TS class)
 *   zak validate <path>                        -- validate a YAML agent definition
 *   zak run <path> --tenant <id>               -- run an agent in a tenant context
 *   zak agents                                 -- list all registered agent classes
 *   zak info                                   -- show ZAK version and config
 *
 * TypeScript equivalent of zak/cli/main.py.
 */

import { Command } from "commander";
import chalk from "chalk";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { loadAgentYaml, validateAgent } from "../core/dsl/parser.js";
import { Edition, getEdition, EditionError } from "../core/edition.js";
import { AgentRegistry } from "../core/runtime/registry.js";
import { AgentExecutor } from "../core/runtime/executor.js";
import { createAgentContext } from "../core/runtime/agent.js";
import { DOMAIN_TEMPLATES, OSS_DOMAINS } from "./templates.js";

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function getVersion(): string {
  // Walk up to find package.json (handles both src/ and dist/ layouts)
  const candidates = [
    resolve(__dirname, "../../package.json"),
    resolve(__dirname, "../../../package.json"),
  ];
  for (const p of candidates) {
    try {
      const pkg = JSON.parse(readFileSync(p, "utf-8"));
      return pkg.version ?? "0.0.0";
    } catch {
      // try next
    }
  }
  return "0.0.0";
}

const VERSION = getVersion();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toAgentId(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function toClassName(name: string): string {
  let cls = name
    .split(/[^a-zA-Z0-9]+/)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join("");
  if (!cls.endsWith("Agent")) {
    cls += "Agent";
  }
  return cls;
}

function renderTemplate(template: string, vars: Record<string, string>): string {
  let result = template;
  for (const [key, value] of Object.entries(vars)) {
    result = result.replaceAll(`{${key}}`, value);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Program
// ---------------------------------------------------------------------------

const program = new Command();

program
  .name("zak")
  .description("ZAK -- Zeron Universal Security Agent Development Kit")
  .version(VERSION, "-v, --version", "Show ZAK version");

// ---------------------------------------------------------------------------
// zak init
// ---------------------------------------------------------------------------

program
  .command("init")
  .description("Scaffold a new agent -- generates a YAML definition and TypeScript class")
  .requiredOption("-n, --name <name>", "Human-readable agent name (e.g. 'My Risk Agent')")
  .requiredOption("-d, --domain <domain>", "Security domain for this agent")
  .option("-o, --out <dir>", "Output directory", ".")
  .action((opts: { name: string; domain: string; out: string }) => {
    const currentEdition = getEdition();
    const validDomains: readonly string[] =
      currentEdition === Edition.ENTERPRISE
        ? Object.keys(DOMAIN_TEMPLATES)
        : OSS_DOMAINS;

    if (!validDomains.includes(opts.domain)) {
      // Check if it is an enterprise-only domain
      if (currentEdition !== Edition.ENTERPRISE && opts.domain in DOMAIN_TEMPLATES) {
        console.error(
          chalk.red.bold(`Domain '${opts.domain}' is an enterprise-only domain.\n`) +
            chalk.dim(`Available on open-source: `) +
            OSS_DOMAINS.join(", ") +
            "\n" +
            chalk.dim(`Visit ${chalk.cyan("https://zeron.one")} for enterprise domains.`)
        );
      } else {
        console.error(
          chalk.red(`Invalid domain '${opts.domain}'.\n`) +
            `Valid choices: ${validDomains.join(", ")}`
        );
      }
      process.exit(1);
    }

    const tmpl = DOMAIN_TEMPLATES[opts.domain];
    if (!tmpl) {
      console.error(chalk.red(`No template found for domain '${opts.domain}'.`));
      process.exit(1);
    }

    const agentId = toAgentId(opts.name);
    const className = toClassName(opts.name);

    const vars = { agentId, agentName: opts.name, className };

    const outDir = resolve(opts.out);
    mkdirSync(outDir, { recursive: true });

    const yamlPath = join(outDir, `${agentId}.yaml`);
    const tsPath = join(outDir, `${agentId.replace(/-/g, "_")}.ts`);

    writeFileSync(yamlPath, renderTemplate(tmpl.yamlTemplate, vars), "utf-8");
    writeFileSync(tsPath, renderTemplate(tmpl.tsTemplate, vars), "utf-8");

    // Validate the generated YAML
    const result = validateAgent(yamlPath);

    const editionNote =
      currentEdition === Edition.ENTERPRISE
        ? ""
        : chalk.dim(
            `\nEnterprise edition adds more domains -- visit ${chalk.cyan("https://zeron.one")}`
          );

    console.log(
      chalk.blue.bold(`--- zak init -- ${opts.name} ---`) +
        "\n\n" +
        chalk.green.bold("Agent scaffolded!") +
        "\n\n" +
        chalk.bold("YAML:  ") + chalk.cyan(yamlPath) + "\n" +
        chalk.bold("Class: ") + chalk.cyan(tsPath) + "\n\n" +
        chalk.bold("Next steps:") + "\n" +
        `  1. Implement ${chalk.cyan(className + ".execute()")}` + "\n" +
        `  2. ${chalk.white("zak validate " + yamlPath)}` + "\n" +
        `  3. ${chalk.white("zak run " + yamlPath + " --tenant <id>")}` +
        editionNote
    );

    if (!result.valid) {
      console.warn(chalk.yellow("\nValidation warnings in generated YAML:"));
      for (const e of result.errors) {
        console.warn(chalk.yellow(`  - ${e}`));
      }
    }
  });

// ---------------------------------------------------------------------------
// zak validate
// ---------------------------------------------------------------------------

program
  .command("validate")
  .description("Validate a US-ADSL agent YAML definition")
  .argument("<path>", "Path to the YAML agent definition file")
  .action((path: string) => {
    const resolvedPath = resolve(path);

    if (!existsSync(resolvedPath)) {
      console.error(chalk.red(`File not found: ${resolvedPath}`));
      process.exit(1);
    }

    const result = validateAgent(resolvedPath);

    if (result.valid) {
      console.log(
        chalk.green.bold("Valid") +
          ` -- Agent ID: ${chalk.cyan(result.agentId)}`
      );
    } else {
      console.error(
        chalk.red.bold(`Validation Failed (${result.errors.length} error(s))`)
      );
      for (const e of result.errors) {
        console.error(chalk.red(`  - ${e}`));
      }
      process.exit(1);
    }
  });

// ---------------------------------------------------------------------------
// zak run
// ---------------------------------------------------------------------------

program
  .command("run")
  .description("Run an agent defined by a YAML file under a tenant context")
  .argument("<path>", "Path to the YAML agent definition file")
  .requiredOption("-t, --tenant <id>", "Tenant ID to run the agent under")
  .option("-e, --env <env>", "Target environment (production, staging, dev)", "staging")
  .action(async (path: string, opts: { tenant: string; env: string }) => {
    const resolvedPath = resolve(path);

    if (!existsSync(resolvedPath)) {
      console.error(chalk.red(`File not found: ${resolvedPath}`));
      process.exit(1);
    }

    // Validate first
    const validationResult = validateAgent(resolvedPath);
    if (!validationResult.valid) {
      console.error(chalk.red("Cannot run: agent YAML is invalid."));
      for (const e of validationResult.errors) {
        console.error(chalk.red(`  - ${e}`));
      }
      process.exit(1);
    }

    const dsl = loadAgentYaml(resolvedPath);
    const { ulid } = await import("ulid");
    const traceId = ulid();

    console.log(
      chalk.blue.bold("--- ZAK Agent Run ---") + "\n" +
        chalk.bold("Agent:       ") + `${dsl.agent.name} (${chalk.cyan(dsl.agent.id)})` + "\n" +
        chalk.bold("Tenant:      ") + opts.tenant + "\n" +
        chalk.bold("Environment: ") + opts.env + "\n" +
        chalk.bold("Trace ID:    ") + traceId
    );

    // Resolve agent class from registry
    const domain = dsl.agent.domain;
    const registry = AgentRegistry.get();

    if (!registry.isRegistered(domain)) {
      console.warn(
        chalk.yellow(`\nNo agent registered for domain '${domain}'.`) +
          `\n  Implement a BaseAgent subclass and register it with ` +
          chalk.cyan(`registerAgent("${domain}", YourAgent, { ... })`) +
          "."
      );
      console.log(`\nRegistered domains: ${registry.allDomains().join(", ") || "none"}`);
      process.exit(0);
    }

    let agentClass;
    try {
      agentClass = registry.resolve(domain);
    } catch (err) {
      if (err instanceof EditionError) {
        const currentEdition = getEdition();
        console.error(
          chalk.red.bold(err.message) + "\n\n" +
            chalk.dim(`Current edition: `) + chalk.yellow(currentEdition) + "\n" +
            chalk.dim(`Upgrade at ${chalk.cyan("https://zeron.one")}`)
        );
        process.exit(1);
      }
      throw err;
    }

    const context = createAgentContext({
      tenantId: opts.tenant,
      traceId,
      dsl,
      environment: opts.env,
    });

    const agent = new agentClass();
    const executor = new AgentExecutor();
    const result = await executor.run(agent, context);

    if (result.success) {
      console.log(
        chalk.green.bold(`\nAgent completed successfully`) +
          ` in ${result.durationMs.toFixed(1)}ms`
      );
      if (result.output && Object.keys(result.output).length > 0) {
        console.log(
          chalk.green.bold("--- Agent Output ---") + "\n" +
            JSON.stringify(result.output, null, 2)
        );
      }
    } else {
      console.error(chalk.red.bold("\nAgent failed"));
      for (const err of result.errors) {
        console.error(chalk.red(`  - ${err}`));
      }
      process.exit(1);
    }
  });

// ---------------------------------------------------------------------------
// zak agents
// ---------------------------------------------------------------------------

program
  .command("agents")
  .description("List all registered agent classes and their domains")
  .action(() => {
    const registry = AgentRegistry.get();
    const regs = registry.allRegistrations();
    const currentEdition = getEdition();

    const editionLabel =
      currentEdition === Edition.ENTERPRISE
        ? chalk.green.bold("enterprise")
        : chalk.yellow.bold("open-source");

    if (regs.length === 0) {
      console.log(chalk.yellow("No agents registered."));
      return;
    }

    console.log(
      `\nEdition: ${editionLabel}  |  Showing ${regs.length} agent(s)\n`
    );

    // Table header
    const cols = {
      domain: 20,
      className: 30,
      version: 10,
      edition: 14,
      description: 40,
    };

    const header =
      "Domain".padEnd(cols.domain) +
      "Class".padEnd(cols.className) +
      "Version".padEnd(cols.version) +
      "Edition".padEnd(cols.edition) +
      "Description";

    console.log(chalk.cyan.bold(header));
    console.log(chalk.dim("-".repeat(header.length)));

    for (const r of regs) {
      const editionCell =
        r.edition === "open-source"
          ? chalk.green("open-source")
          : chalk.blue("enterprise");

      console.log(
        r.domain.padEnd(cols.domain) +
          r.className.padEnd(cols.className) +
          r.version.padEnd(cols.version) +
          editionCell.padEnd(cols.edition + 10) + // account for chalk escape codes
          r.description.slice(0, 55)
      );
    }

    if (currentEdition !== Edition.ENTERPRISE) {
      console.log(
        chalk.dim(
          `\nAdditional enterprise agents available at ${chalk.cyan("https://zeron.one")}`
        )
      );
    }
  });

// ---------------------------------------------------------------------------
// zak info
// ---------------------------------------------------------------------------

program
  .command("info")
  .description("Show ZAK platform info")
  .action(() => {
    const registry = AgentRegistry.get();
    const currentEdition = getEdition();
    const editionLabel =
      currentEdition === Edition.ENTERPRISE
        ? chalk.green.bold("enterprise")
        : chalk.yellow.bold("open-source");

    const domains = registry.allDomains();

    console.log(chalk.blue.bold("\n--- ZAK Platform Info ---\n"));

    const rows: [string, string][] = [
      ["Version", VERSION],
      ["Edition", editionLabel],
      ["Agents Available", String(domains.length)],
      ["Registered Domains", domains.join(", ") || "none"],
      ["OSS Domains", OSS_DOMAINS.join(", ")],
      ["Multi-tenant", "Namespace isolation"],
      ["Audit", "Structured JSON (pino)"],
    ];

    if (currentEdition !== Edition.ENTERPRISE) {
      rows.push(["Upgrade", chalk.cyan("https://zeron.one")]);
    }

    for (const [key, value] of rows) {
      console.log(`  ${chalk.cyan.bold(key.padEnd(22))} ${value}`);
    }

    console.log();
  });

// ---------------------------------------------------------------------------
// CLI Entry Point
// ---------------------------------------------------------------------------

export function runCli(argv?: string[]): void {
  program.parse(argv ?? process.argv);
}

export { program };
