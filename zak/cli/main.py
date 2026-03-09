"""
ZAK CLI — developer-facing commands for scaffolding, validating, and running agents.

Commands:
  zak init --name <name> --domain <domain>  — scaffold a new agent (YAML + Python class)
  zak validate <path>                        — validate a YAML agent definition
  zak run <path> --tenant <id>               — run an agent in a tenant context
  zak agents                                 — list all registered agent classes
  zak info                                   — show ZAK version and config
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import zak
from zak.core.dsl.parser import load_agent_yaml, validate_agent
from zak.core.edition import Edition, EditionError, get_edition

from zak.agents import load_all_agents as _load_all_agents

console = Console()


@click.group()
@click.version_option(zak.__version__, prog_name="zak")
def cli() -> None:
    """ZAK — Zeron Universal Security Agent Development Kit."""


_OSS_DOMAINS = ["risk_quant", "vuln_triage", "appsec"]


@cli.command(name="init")
@click.option("--name", "-n", required=True, help="Human-readable agent name (e.g. 'My Risk Agent')")
@click.option(
    "--domain", "-d", required=True,
    help="Security domain for this agent",
)
@click.option("--out", "-o", default=".", show_default=True, help="Output directory")
def init(name: str, domain: str, out: str) -> None:
    """Scaffold a new agent — generates a YAML definition and Python class."""
    from zak.cli.templates import DOMAIN_TEMPLATES

    current_edition = get_edition()
    valid_domains = _OSS_DOMAINS if current_edition != Edition.ENTERPRISE else list(DOMAIN_TEMPLATES.keys())

    if domain not in valid_domains:
        if current_edition != Edition.ENTERPRISE and domain in DOMAIN_TEMPLATES:
            console.print(Panel(
                f"[bold red]Domain '{domain}' is an enterprise-only domain.[/bold red]\n\n"
                f"[dim]Available on open-source:[/dim] {', '.join(_OSS_DOMAINS)}\n\n"
                "[dim]Visit [cyan]https://zeron.one[/cyan] for enterprise domains.[/dim]",
                title="[bold red]Enterprise Domain[/bold red]",
                border_style="red",
            ))
        else:
            console.print(
                f"[red]Invalid domain '{domain}'.[/red]\n"
                f"Valid choices: {', '.join(valid_domains)}"
            )
        raise SystemExit(1)

    tmpl = DOMAIN_TEMPLATES[domain]

    # Derive safe ID and class name from the human name
    agent_id = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    class_name = "".join(w.capitalize() for w in re.split(r"[^a-zA-Z0-9]+", name))
    if not class_name.endswith("Agent"):
        class_name += "Agent"

    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)

    yaml_path = out_dir / f"{agent_id}.yaml"
    python_path = out_dir / f"{agent_id.replace('-', '_')}.py"

    yaml_path.write_text(tmpl.yaml_template.format(agent_id=agent_id, agent_name=name))
    python_path.write_text(tmpl.python_template.format(
        agent_id=agent_id, agent_name=name, class_name=class_name
    ))

    result = validate_agent(yaml_path)

    edition_note = (
        ""
        if current_edition == Edition.ENTERPRISE
        else "\n[dim]Enterprise edition adds 19 more domains — visit https://zeron.one[/dim]"
    )
    console.print(Panel(
        f"[bold green]✅ Agent scaffolded![/bold green]\n\n"
        f"[bold]YAML:[/bold]   [cyan]{yaml_path}[/cyan]\n"
        f"[bold]Class:[/bold]  [cyan]{python_path}[/cyan]\n\n"
        f"[bold]Next:[/bold]\n"
        f"  1. Implement [cyan]{class_name}.execute()[/cyan]\n"
        f"  2. [white]zak validate {yaml_path}[/white]\n"
        f"  3. [white]zak run {yaml_path} --tenant <id>[/white]"
        + edition_note,
        title=f"[bold blue]🚀 zak init — {name}[/bold blue]",
        border_style="blue",
    ))

    if not result.valid:
        console.print("[yellow]⚠ Validation warnings in generated YAML:[/yellow]")
        for e in result.errors:
            console.print(f"  [yellow]• {e}[/yellow]")


@cli.command()
@click.argument("path", type=click.Path(exists=True))
def validate(path: str) -> None:
    """Validate a US-ADSL agent YAML definition."""
    result = validate_agent(path)
    if result.valid:
        console.print(
            Panel(
                f"[bold green]✅ Valid[/bold green] — Agent ID: [cyan]{result.agent_id}[/cyan]",
                title="[bold]ZAK Validation[/bold]",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                "\n".join(f"[red]• {e}[/red]" for e in result.errors),
                title=f"[bold red]❌ Validation Failed ({len(result.errors)} error(s))[/bold red]",
                border_style="red",
            )
        )
        sys.exit(1)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--tenant", "-t", required=True, help="Tenant ID to run the agent under")
@click.option("--env", "-e", default="staging", show_default=True,
              help="Target environment (production, staging, dev)")
@click.option("--meta", "-m", multiple=True, help="Metadata in KEY=VALUE format (e.g. -m target_url=https://...)")
def run(path: str, tenant: str, env: str, meta: list[str]) -> None:
    """Run an agent defined by a YAML file under a tenant context."""
    from ulid import ULID
    from zak.core.runtime.agent import AgentContext
    from zak.core.runtime.executor import AgentExecutor
    from zak.tenants.context import TenantRegistry

    # Parse metadata
    metadata = {}
    for m in meta:
        if "=" in m:
            k, v = m.split("=", 1)
            metadata[k] = v

    # Validate DSL first
    result = validate_agent(path)
    if not result.valid:
        console.print("[red]Cannot run: agent YAML is invalid.[/red]")
        for e in result.errors:
            console.print(f"  [red]• {e}[/red]")
        sys.exit(1)

    dsl = load_agent_yaml(path)
    trace_id = str(ULID())

    console.print(Panel(
        f"[bold]Agent:[/bold] {dsl.agent.name} ([cyan]{dsl.agent.id}[/cyan])\n"
        f"[bold]Tenant:[/bold] {tenant}\n"
        f"[bold]Environment:[/bold] {env}\n"
        f"[bold]Trace ID:[/bold] {trace_id}",
        title="[bold blue]🚀 ZAK Agent Run[/bold blue]",
        border_style="blue",
    ))

    # Set up executor
    registry = TenantRegistry()
    if not registry.exists(tenant):
        registry.register(tenant_id=tenant, name=tenant)

    context = AgentContext(
        tenant_id=tenant,
        trace_id=trace_id,
        dsl=dsl,
        environment=env,
        metadata=metadata,
    )

    # Trigger agent module imports so @register_agent decorators fire
    _load_all_agents()

    from zak.core.runtime.registry import AgentRegistry

    domain = dsl.agent.domain.value
    registry_instance = AgentRegistry.get()

    if not registry_instance.is_registered(domain):
        console.print(
            f"[yellow]⚠ No agent registered for domain '{domain}'.[/yellow]\n"
            f"  Implement a BaseAgent subclass and decorate it with "
            f"[cyan]@register_agent(domain=\"{domain}\")[/cyan]."
        )
        console.print(f"\nRegistered domains: {registry_instance.all_domains()}")
        sys.exit(0)

    try:
        agent_cls = registry_instance.resolve(domain)
    except EditionError as exc:
        console.print(Panel(
            f"[bold red]{exc}[/bold red]\n\n"
            f"[dim]Current edition:[/dim] [yellow]{get_edition().value}[/yellow]\n"
            "[dim]Upgrade at [cyan]https://zeron.one[/cyan][/dim]",
            title="[bold red]Enterprise Edition Required[/bold red]",
            border_style="red",
        ))
        sys.exit(1)

    # Inject graph adapter for agents that need it (check constructor signature)
    import inspect
    sig = inspect.signature(agent_cls.__init__)
    if "adapter" in sig.parameters:
        from zak.sif.graph.adapter import KuzuAdapter
        adapter = KuzuAdapter()
        adapter.initialize_schema(tenant)
        agent = agent_cls(adapter)
    else:
        agent = agent_cls()


    executor = AgentExecutor()
    result_obj = executor.run(agent, context)

    if result_obj.success:
        console.print(f"\n[bold green]✅ Agent completed successfully[/bold green] "
                      f"in {result_obj.duration_ms:.1f}ms")
    else:
        console.print("\n[bold red]❌ Agent failed[/bold red]")
        for err in result_obj.errors:
            console.print(f"  [red]• {err}[/red]")
        sys.exit(1)


@cli.command()
def info() -> None:
    """Show ZAK platform info."""
    _load_all_agents()
    from zak.core.runtime.registry import AgentRegistry

    reg = AgentRegistry.get()
    current_edition = get_edition()
    edition_label = (
        "[bold green]enterprise[/bold green]"
        if current_edition == Edition.ENTERPRISE
        else "[bold yellow]open-source[/bold yellow]"
    )

    table = Table(title="ZAK Platform Info", border_style="blue")
    table.add_column("Property", style="bold cyan")
    table.add_column("Value")
    table.add_row("Version", zak.__version__)
    table.add_row("Author", zak.__author__)
    table.add_row("Edition", edition_label)
    table.add_row("Agents Available", str(len(reg.all_domains())))
    table.add_row("Registered Domains", ", ".join(reg.all_domains()) or "none")
    table.add_row("Graph Backend", "Kuzu (embedded) → Memgraph (production)")
    table.add_row("Multi-tenant", "✅ Namespace isolation")
    table.add_row("Audit", "✅ Structured JSON (structlog)")
    if current_edition != Edition.ENTERPRISE:
        table.add_row("Upgrade", "https://zeron.one")
    console.print(table)


@cli.command(name="agents")
def list_agents() -> None:
    """List all registered agent classes and their domains."""
    _load_all_agents()
    from zak.core.runtime.registry import AgentRegistry

    reg = AgentRegistry.get()
    regs = reg.all_registrations()
    current_edition = get_edition()

    if not regs:
        console.print("[yellow]No agents registered.[/yellow]")
        return

    edition_label = (
        "[bold green]enterprise[/bold green]"
        if current_edition == Edition.ENTERPRISE
        else "[bold yellow]open-source[/bold yellow]"
    )
    console.print(f"\nEdition: {edition_label}  |  Showing {len(regs)} agent(s)\n")

    table = Table(title="Registered Agents", border_style="cyan")
    table.add_column("Domain", style="bold cyan")
    table.add_column("Class")
    table.add_column("Version")
    table.add_column("Edition")
    table.add_column("Description")

    for r in regs:
        edition_cell = (
            "[green]open-source[/green]"
            if r.edition == "open-source"
            else "[blue]enterprise[/blue]"
        )
        table.add_row(r.domain, r.class_name, r.version, edition_cell, r.description[:55])

    console.print(table)

    if current_edition != Edition.ENTERPRISE:
        console.print(
            "\n[dim]Additional enterprise agents available at [cyan]https://zeron.one[/cyan][/dim]"
        )



if __name__ == "__main__":
    cli()
