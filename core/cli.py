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
    help="McpVanguard — Real-time AI security proxy for MCP agents.",
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
        f"[bold green]McpVanguard v{__version__}[/bold green]\n"
        f"[dim]Real-time security layer for MCP agents[/dim]",
        border_style="green",
    ))
    console.print(f"[bold]Server:[/bold]    {server}")
    console.print(f"[bold]Rules:[/bold]     {engine.rule_count} loaded from '{rules_dir}/'")
    console.print(f"[bold]Layer 1:[/bold]    [green]Enabled[/green] (Static rules)")
    
    if behavioral:
        console.print(f"[bold]Layer 3:[/bold]    [green]Enabled[/green] (Behavioral analysis)")
    else:
        console.print(f"[bold]Layer 3:[/bold]    [yellow]Disabled[/yellow] (Behavioral analysis)")

    if semantic:
        status = "Ready" if semantic_ready else "Offline (Scoring will be skipped)"
        console.print(f"[bold]Layer 2:[/bold]    {status} — Ollama ({ollama_model})")
    else:
        console.print(f"[bold]Layer 2:[/bold]    [dim]Disabled[/dim] (Semantic scoring)")

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
        f"[bold green]McpVanguard v{__version__}[/bold green]",
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

    console.print(f"[bold blue]Syncing signatures from {repo}...[/bold blue]")

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
                console.print(f"  [green]SUCCESS:[/green] Updated {filename}")
                updated += 1
            except Exception as exc:
                console.print(f"  [red]FAILURE:[/red] {filename}: {exc}")
                failed += 1

    if failed == 0:
        console.print(f"\n[bold green]All {updated} signature files updated successfully.[/bold green]")
    else:
        console.print(f"\n[yellow]Updated {updated} files, {failed} failed. Check your connection.[/yellow]")


# ---------------------------------------------------------------------------
# vanguard init
# ---------------------------------------------------------------------------

@app.command()
def init():
    """
    Initialize a new McpVanguard workspace.
    Creates a .env template and default security rules.
    """
    console.print(Panel.fit(
        "[bold green]Initializing McpVanguard Workspace[/bold green]",
        border_style="green"
    ))

    # 1. Create .env if missing
    env_path = ".env"
    if not os.path.exists(env_path):
        console.print("[dim]Creating .env from template...[/dim]")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write("# McpVanguard Configuration\n")
            f.write("VANGUARD_LOG_LEVEL=INFO\n")
            f.write("VANGUARD_MODE=audit  # Recommended for new setups\n")
            f.write("VANGUARD_RULES_DIR=rules\n")
            f.write("# VANGUARD_OPENAI_API_KEY=\n")
            f.write("# VANGUARD_REDIS_URL=\n")
        console.print(f"  [green]SUCCESS:[/green] Created {env_path}")
    else:
        console.print(f"  [yellow]SKIP:[/yellow] {env_path} already exists")

    # 2. Ensure rules directory exists
    rules_path = "rules"
    if not os.path.exists(rules_path):
        console.print("[dim]Initializing default rules directory...[/dim]")
        os.makedirs(rules_path, exist_ok=True)
        # Create a dummy safe_zones.yaml
        safe_zones_content = """# McpVanguard: Safe Zones
# Define absolute paths that the agent is allowed to access.
allowed_prefixes:
  - C:\\Users\\  # Adjust as needed for your system
"""
        with open(os.path.join(rules_path, "safe_zones.yaml"), "w", encoding="utf-8") as f:
            f.write(safe_zones_content)
        console.print(f"  [green]SUCCESS:[/green] Created {rules_path}/safe_zones.yaml")
    else:
        console.print(f"  [yellow]SKIP:[/yellow] {rules_path}/ already exists")

    console.print("\n[bold green]Workspace ready![/bold green]")
    console.print("1. Edit .env to add your API keys.")
    console.print("2. Run 'vanguard info' to verify rules.")
    console.print("3. Run 'vanguard start --server <cmd>' to protect your server.")


# ---------------------------------------------------------------------------
# vanguard configure-claude
# ---------------------------------------------------------------------------

@app.command()
def configure_claude():
    """
    Automatically inject McpVanguard into your Claude Desktop configuration.
    This wraps all your existing MCP servers with Vanguard security.
    """
    import json
    
    # Path logic for Windows
    appdata = os.getenv("APPDATA")
    if not appdata:
        console.print("[bold red]Error:[/bold red] Could not find APPDATA environment variable.")
        return
        
    config_path = os.path.join(appdata, "Claude", "claude_desktop_config.json")
    
    if not os.path.exists(config_path):
        console.print(f"[bold red]Error:[/bold red] Claude Desktop config not found at: {config_path}")
        return

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
            
        mcp_servers = config.get("mcpServers", {})
        if not mcp_servers:
            console.print("[yellow]Warning:[/yellow] No MCP servers found in Claude config.")
            return

        updated_count = 0
        for name, server_cfg in mcp_servers.items():
            command = server_cfg.get("command")
            args = server_cfg.get("args", [])
            
            # Skip if already wrapped
            if command == "vanguard" or (command == "npx" and "mcp-vanguard" in args):
                continue
                
            # Wrap it
            full_cmd = f"{command} {' '.join(args)}"
            server_cfg["command"] = "vanguard"
            server_cfg["args"] = ["start", "--server", full_cmd]
            updated_count += 1
            
        if updated_count > 0:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            console.print(f"[bold green]SUCCESS:[/bold green] Wrapped {updated_count} servers with Vanguard security.")
        else:
            console.print("[green]All servers are already protected by Vanguard.[/green]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to update Claude config: {e}")


# ---------------------------------------------------------------------------
# vanguard ui
# ---------------------------------------------------------------------------

@app.command()
def ui(
    host: str = typer.Option("127.0.0.1", "--host", help="Binding host for the dashboard."),
    port: int = typer.Option(4040, "--port", help="Port to listen on."),
):
    """
    Open the McpVanguard Audit Dashboard in your browser.
    Provides a real-time visual feed of security events.
    """
    from core.dashboard import start_dashboard
    console.print(f"[bold green]Starting McpVanguard Dashboard on http://{host}:{port}...[/bold green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    start_dashboard(host=host, port=port)


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
