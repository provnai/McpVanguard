"""
core/cli.py
The `vanguard` CLI — entry point for the McpVanguard proxy.

Usage:
    vanguard start --server "npx @modelcontextprotocol/server-filesystem ."
    vanguard start --server "python mcp_servers/vulnerable_fs_server.py" --no-semantic
    vanguard info
"""

from __future__ import annotations
import logging
import os
import sys
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console

# Load environment variables from .env
load_dotenv()
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from core import __version__
from core.proxy import ProxyConfig, run_proxy
from core.rules_engine import RulesEngine
from core import semantic, behavioral

app = typer.Typer(
    name="vanguard",
    help="🛡️ McpVanguard — Real-time AI security proxy for MCP agents.",
    add_completion=False,
)
console = Console(stderr=True)


# ---------------------------------------------------------------------------
# vanguard start
# ---------------------------------------------------------------------------

@app.command()
def start(
    server: str = typer.Option(
        ...,
        "--server", "-s",
        help='The MCP server command to wrap. e.g. "npx @modelcontextprotocol/server-filesystem ."',
    ),
    rules_dir: str = typer.Option(
        "rules",
        "--rules-dir", "-r",
        help="Path to the YAML rules directory.",
    ),
    log_file: str = typer.Option(
        "audit.log",
        "--log-file", "-l",
        help="Path to write the audit log.",
    ),
    semantic: bool = typer.Option(
        False,
        "--semantic/--no-semantic",
        help="Enable Layer 2 semantic scoring via Ollama (requires Ollama running).",
    ),
    behavioral: bool = typer.Option(
        True,
        "--behavioral/--no-behavioral",
        help="Enable Layer 3 behavioral analysis.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose debug logging.",
    ),
    ollama_url: str = typer.Option(
        "http://localhost:11434",
        "--ollama-url",
        help="Ollama API URL for semantic scoring.",
    ),
    ollama_model: str = typer.Option(
        "phi4-mini",
        "--ollama-model", "-m",
        help="Ollama model to use for semantic analysis.",
    ),
):
    """
    Start the Vanguard proxy, wrapping a real MCP server.
    All traffic between the agent and server will be inspected.
    """
    # Configure logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        stream=sys.stderr,
    )

    # Load config from options + environment
    config = ProxyConfig()
    config.rules_dir = rules_dir
    config.log_file = log_file
    config.semantic_enabled = semantic
    config.behavioral_enabled = behavioral

    # Phase 5 overrides
    if semantic:
        os.environ["VANGUARD_SEMANTIC_ENABLED"] = "true"
        os.environ["VANGUARD_OLLAMA_URL"] = ollama_url
        os.environ["VANGUARD_OLLAMA_MODEL"] = ollama_model

    # Check semantic health if enabled
    semantic_ready = False
    if semantic:
        with console.status("[bold yellow]Checking Ollama health..."):
            import asyncio
            from core import semantic as semantic_mod
            semantic_ready = asyncio.run(semantic_mod.check_ollama_health())

    # Load and display rules summary
    engine = RulesEngine(rules_dir=rules_dir)

    console.print(Panel.fit(
        f"[bold green]🛡️ McpVanguard v{__version__}[/bold green]\n"
        f"[dim]Real-time security layer for MCP agents[/dim]",
        border_style="green",
    ))
    console.print(f"[bold]Server:[/bold]    {server}")
    console.print(f"[bold]Rules:[/bold]     {engine.rule_count} loaded from '{rules_dir}/'")
    console.print(f"[bold]Layer 1:[/bold]    ✅ Static rules")
    
    if behavioral:
        console.print(f"[bold]Layer 3:[/bold]    ✅ Behavioral analysis (Active)")
    else:
        console.print(f"[bold]Layer 3:[/bold]    ⏸️  Behavioral analysis (Disabled)")

    if semantic:
        status = "✅ Ready" if semantic_ready else "❌ Offline (Scoring will be skipped)"
        console.print(f"[bold]Layer 2:[/bold]    {status} — Ollama ({ollama_model})")
    else:
        console.print(f"[bold]Layer 2:[/bold]    ⏸️  Semantic scoring (Use --semantic to enable)")

    console.print(f"[bold]Audit log:[/bold]  {log_file}\n")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    # Parse the server command string into a list
    import shlex
    server_cmd = shlex.split(server)

    if not server_cmd:
        console.print("[bold red]Error:[/bold red] The --server argument is practically empty. "
                      "If you are deploying on Railway or via Docker, ensure that you have provided "
                      "a valid value for the MCP_SERVER_COMMAND environment variable.")
        sys.exit(1)

    # Start the proxy (blocks until server exits or Ctrl+C)
    run_proxy(server_command=server_cmd, config=config)


# ---------------------------------------------------------------------------
# vanguard sse
# ---------------------------------------------------------------------------

@app.command()
def sse(
    server: str = typer.Option(
        ...,
        "--server", "-s",
        help='The MCP server command to wrap. e.g. "npx @modelcontextprotocol/server-filesystem ."',
    ),
    host: str = typer.Option("0.0.0.0", "--host", help="Binding host for the SSE server."),
    port: int = typer.Option(
        int(os.getenv("PORT", "8080")),
        "--port", "-p",
        help="Port to listen on. Defaults to $PORT or 8080.",
    ),
    rules_dir: str = typer.Option("rules", "--rules-dir", "-r"),
    log_file: str = typer.Option("audit.log", "--log-file", "-l"),
    semantic: bool = typer.Option(False, "--semantic/--no-semantic"),
    behavioral: bool = typer.Option(True, "--behavioral/--no-behavioral"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """
    Start the Vanguard proxy in SSE (Network) mode.
    Exposes a public HTTP endpoint for remote MCP agents.
    """
    # Configure logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(message)s", stream=sys.stderr)

    # Load config
    config = ProxyConfig()
    config.rules_dir = rules_dir
    config.log_file = log_file
    config.semantic_enabled = semantic
    config.behavioral_enabled = behavioral

    import shlex
    server_cmd = shlex.split(server)

    from core.sse_server import run_sse_server
    import asyncio
    asyncio.run(run_sse_server(
        server_command=server_cmd,
        host=host,
        port=port,
        config=config
    ))


# ---------------------------------------------------------------------------
# vanguard info
# ---------------------------------------------------------------------------

@app.command()
def info(
    rules_dir: str = typer.Option("rules", "--rules-dir", "-r"),
):
    """Show loaded rules and proxy configuration."""
    engine = RulesEngine(rules_dir=rules_dir)

    console.print(Panel.fit(
        f"[bold green]🛡️ McpVanguard v{__version__}[/bold green]",
        border_style="green",
    ))

    table = Table(title=f"Loaded Rules ({engine.rule_count} total)")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="bold")
    table.add_column("Action")
    table.add_column("Description")
    table.add_column("Source")

    severity_color = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "dim",
    }

    for rule in engine.rules:
        color = severity_color.get(rule.severity, "white")
        table.add_row(
            rule.rule_id,
            f"[{color}]{rule.severity}[/{color}]",
            rule.action,
            rule.description[:60],
            rule.source_file,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# vanguard version
# ---------------------------------------------------------------------------

@app.command()
def version():
    """Show version information."""
    rprint(f"[bold green]McpVanguard[/bold green] v{__version__}")


# ---------------------------------------------------------------------------
# vanguard update
# ---------------------------------------------------------------------------

@app.command()
def update(
    repo: str = typer.Option(
        "ModelContextProtocol/McpVanguard",
        "--repo",
        help="GitHub repository to fetch signatures from.",
    ),
):
    """
    Fetch the latest security signatures from the official registry.
    This updates your local rules/ directory with the newest threats.
    """
    import httpx

    RULE_FILES = [
        "commands.yaml",
        "filesystem.yaml",
        "network.yaml",
        "privilege.yaml",
        "jailbreak.yaml",
    ]
    base_url = f"https://raw.githubusercontent.com/{repo}/main/rules"
    rules_dir_path = rules_dir

    console.print(f"[bold blue]🔄 Syncing signatures from {repo}...[/bold blue]")

    updated = 0
    failed = 0
    with console.status("[bold yellow]Fetching latest rules...[/bold yellow]"):
        for filename in RULE_FILES:
            url = f"{base_url}/{filename}"
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.get(url)
                    resp.raise_for_status()
                dest = os.path.join(rules_dir_path, filename)
                os.makedirs(rules_dir_path, exist_ok=True)
                with open(dest, "w", encoding="utf-8") as f:
                    f.write(resp.text)
                console.print(f"  [green]✅ Updated[/green] {filename}")
                updated += 1
            except Exception as exc:
                console.print(f"  [red]❌ Failed[/red] {filename}: {exc}")
                failed += 1

    if failed == 0:
        console.print(f"\n[bold green]✅ All {updated} signature files updated successfully.[/bold green]")
    else:
        console.print(f"\n[yellow]⚠️  Updated {updated} files, {failed} failed. Check your connection.[/yellow]")


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
