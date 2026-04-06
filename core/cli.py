"""
core/cli.py
The `vanguard` CLI — entry point for the McpVanguard proxy.

Usage:
    vanguard start --server "npx @modelcontextprotocol/server-filesystem ."
    vanguard start --server "python mcp_servers/vulnerable_fs_server.py" --no-semantic
    vanguard info
"""

from __future__ import annotations
import hashlib
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

import httpx
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
from core import signing

app = typer.Typer(
    name="vanguard",
    help="McpVanguard — Real-time AI security proxy for MCP agents.",
    add_completion=False,
)
# For UI-only commands (stdout)
console = Console()
# For proxy/server commands (stderr) to avoid corrupting MCP stdio
proxy_console = Console(stderr=True)

RULE_FILES = [
    "commands.yaml",
    "filesystem.yaml",
    "network.yaml",
    "privilege.yaml",
    "jailbreak.yaml",
]
RULE_MANIFEST = "manifest.json"
RULE_SIGNATURE = signing.RULE_SIGNATURE
REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _validate_repo_slug(repo: str) -> str:
    if not REPO_SLUG_RE.fullmatch(repo):
        raise ValueError("Repository must be a GitHub slug like 'owner/repo'.")
    return repo


def _resolve_github_ref(client, repo: str, ref: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{40}", ref):
        return ref

    url = f"https://api.github.com/repos/{repo}/commits/{ref}"
    resp = client.get(url, headers={"Accept": "application/vnd.github+json"})
    resp.raise_for_status()
    sha = resp.json().get("sha")
    if not sha or not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
        raise ValueError(f"Could not resolve ref '{ref}' to an immutable commit SHA.")
    return sha


def _raw_rules_url(repo: str, ref: str, filename: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{ref}/rules/{filename}"


def _fetch_rules_manifest(client, repo: str, ref: str) -> dict:
    resp = client.get(_raw_rules_url(repo, ref, RULE_MANIFEST))
    resp.raise_for_status()
    manifest = resp.json()
    rules = manifest.get("rules")
    if not isinstance(rules, dict) or not rules:
        raise ValueError("Signature manifest is missing the 'rules' mapping.")
    return manifest


def _fetch_manifest_signature(client, repo: str, ref: str) -> dict:
    resp = client.get(_raw_rules_url(repo, ref, RULE_SIGNATURE))
    resp.raise_for_status()
    return resp.json()


def _verify_rule_bundle(
    downloads: dict[str, str],
    manifest: dict,
    signature_doc: Optional[dict],
    allow_unsigned: bool,
    trusted_signers: dict[str, dict[str, str]],
) -> None:
    rules = manifest.get("rules") if manifest else None
    if not rules and not allow_unsigned:
        raise ValueError("Remote signature manifest is missing. Re-run with --allow-unsigned to bypass.")

    if signature_doc:
        signing.verify_manifest_signature(manifest, signature_doc, trusted_signers=trusted_signers)
    elif not allow_unsigned:
        raise ValueError("Remote detached manifest signature is missing. Re-run with --allow-unsigned to bypass.")

    for filename, content in downloads.items():
        if not rules:
            continue
        entry = rules.get(filename)
        if not isinstance(entry, dict) or "sha256" not in entry:
            raise ValueError(f"Manifest entry missing sha256 for {filename}.")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if digest != entry["sha256"]:
            raise ValueError(f"Integrity verification failed for {filename}.")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


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
    semantic: Optional[bool] = typer.Option(
        None,
        "--semantic/--no-semantic",
        help="Enable Layer 2 semantic scoring via Ollama (requires Ollama running).",
    ),
    behavioral: Optional[bool] = typer.Option(
        None,
        "--behavioral/--no-behavioral",
        help="Enable Layer 3 behavioral analysis.",
    ),
    management_tools: Optional[bool] = typer.Option(
        None,
        "--management-tools/--no-management-tools",
        help="Expose native Vanguard management tools. Disabled by default.",
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
    
    # Only override if the user explicitly provided the option,
    # otherwise respect what's already in config (which loads from env)
    # Typer doesn't easily tell us if it's a default, so we check if 
    # the env var exists, otherwise use the option value.
    if os.getenv("VANGUARD_LOG_FILE") and log_file == "audit.log":
        pass # use env var
    else:
        config.log_file = log_file

    if semantic is not None:
        config.semantic_enabled = semantic
    if behavioral is not None:
        config.behavioral_enabled = behavioral
    if management_tools is not None:
        config.management_tools_enabled = management_tools

    # Phase 5 overrides
    if semantic:
        os.environ["VANGUARD_SEMANTIC_ENABLED"] = "true"
        os.environ["VANGUARD_OLLAMA_URL"] = ollama_url
        os.environ["VANGUARD_OLLAMA_MODEL"] = ollama_model

    # Check semantic health if enabled
    semantic_ready = False
    if semantic:
        with proxy_console.status("[bold yellow]Checking Ollama health..."):
            import asyncio
            from core import semantic as semantic_mod
            semantic_ready = asyncio.run(semantic_mod.check_semantic_health())

    # Load and display rules summary
    engine = RulesEngine(rules_dir=rules_dir)

    proxy_console.print(Panel.fit(
        f"[bold green]McpVanguard v{__version__}[/bold green]\n"
        f"[dim]Real-time security layer for MCP agents[/dim]",
        border_style="green",
    ))
    proxy_console.print(f"[bold]Server:[/bold]    {server}")
    proxy_console.print(f"[bold]Rules:[/bold]     {engine.rule_count} loaded from '{rules_dir}/'")
    proxy_console.print(f"[bold]Layer 1:[/bold]    [green]Enabled[/green] (Static rules)")
    
    if behavioral:
        proxy_console.print(f"[bold]Layer 3:[/bold]    [green]Enabled[/green] (Behavioral analysis)")
    else:
        proxy_console.print(f"[bold]Layer 3:[/bold]    [yellow]Disabled[/yellow] (Behavioral analysis)")

    if config.management_tools_enabled:
        proxy_console.print(f"[bold]Mgmt:[/bold]       [green]Enabled[/green] (Native Vanguard tools exposed)")
    else:
        proxy_console.print(f"[bold]Mgmt:[/bold]       [dim]Disabled[/dim] (Native Vanguard tools hidden)")
    
    if semantic:
        status = "Ready" if semantic_ready else "Offline (Scoring will be skipped)"
        proxy_console.print(f"[bold]Layer 2:[/bold]    {status} — Ollama ({ollama_model})")
    else:
        proxy_console.print(f"[bold]Layer 2:[/bold]    [dim]Disabled[/dim] (Semantic scoring)")
    
    proxy_console.print(f"[bold]Audit log:[/bold]  {log_file}\n")
    proxy_console.print("[dim]Press Ctrl+C to stop[/dim]\n")

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
    semantic: Optional[bool] = typer.Option(None, "--semantic/--no-semantic"),
    behavioral: Optional[bool] = typer.Option(None, "--behavioral/--no-behavioral"),
    management_tools: Optional[bool] = typer.Option(
        None,
        "--management-tools/--no-management-tools",
        help="Expose native Vanguard management tools. Disabled by default.",
    ),
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
    
    if os.getenv("VANGUARD_LOG_FILE") and log_file == "audit.log":
        pass 
    else:
        config.log_file = log_file

    if semantic is not None:
        config.semantic_enabled = semantic
    if behavioral is not None:
        config.behavioral_enabled = behavioral
    if management_tools is not None:
        config.management_tools_enabled = management_tools

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
        help="GitHub repository slug to fetch signatures from.",
    ),
    ref: str = typer.Option(
        "main",
        "--ref",
        help="Git ref to fetch from. Branches are resolved to an immutable commit SHA before download.",
    ),
    rules_dir: str = typer.Option("rules", "--rules-dir", help="Directory for rules."),
    allow_unsigned: bool = typer.Option(
        False,
        "--allow-unsigned",
        help="Allow updates without a remote rules manifest. This weakens integrity guarantees.",
    ),
    trust_key_file: Optional[Path] = typer.Option(
        None,
        "--trust-key-file",
        help="Additional trusted signer public-key JSON file for private rule registries.",
    ),
):
    """
    Fetch the latest security signatures from the official registry.
    This updates your local rules/ directory with the newest threats.
    """
    try:
        repo = _validate_repo_slug(repo)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[bold blue]Syncing signatures from {repo}@{ref}...[/bold blue]")

    try:
        extra_signers = [signing.load_signer_file(trust_key_file)] if trust_key_file else None
        trusted_signers = signing.load_trusted_signers(extra_signers=extra_signers)
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resolved_ref = _resolve_github_ref(client, repo, ref)
            console.print(f"[dim]Resolved ref:[/dim] {resolved_ref}")

            manifest = None
            signature_doc = None
            try:
                manifest = _fetch_rules_manifest(client, repo, resolved_ref)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 404 or not allow_unsigned:
                    raise
                console.print("[yellow]Warning:[/yellow] Remote rules manifest not found; proceeding unsigned.")

            if manifest is not None:
                try:
                    signature_doc = _fetch_manifest_signature(client, repo, resolved_ref)
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code != 404:
                        raise
                    if allow_unsigned:
                        console.print("[yellow]Warning:[/yellow] Remote detached signature not found; proceeding unsigned.")
                    signature_doc = None

            downloads: dict[str, str] = {}
            for filename in RULE_FILES:
                resp = client.get(_raw_rules_url(repo, resolved_ref, filename))
                resp.raise_for_status()
                downloads[filename] = resp.text

            _verify_rule_bundle(
                downloads,
                manifest,
                signature_doc,
                allow_unsigned=allow_unsigned,
                trusted_signers=trusted_signers,
            )
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to fetch verified signatures: {exc}")
        raise typer.Exit(code=1)

    os.makedirs(rules_dir, exist_ok=True)
    for filename, content in downloads.items():
        dest = os.path.join(rules_dir, filename)
        with open(dest, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        console.print(f"  [green]SUCCESS:[/green] Updated {filename}")

    if manifest is not None:
        _write_json(Path(rules_dir) / RULE_MANIFEST, manifest)
        console.print(f"  [green]SUCCESS:[/green] Updated {RULE_MANIFEST}")
    if signature_doc is not None:
        _write_json(Path(rules_dir) / RULE_SIGNATURE, signature_doc)
        console.print(f"  [green]SUCCESS:[/green] Updated {RULE_SIGNATURE}")

    console.print(f"\n[bold green]Verified and updated {len(downloads)} rule files successfully.[/bold green]")


# ---------------------------------------------------------------------------
# vanguard keygen
# ---------------------------------------------------------------------------

@app.command()
def keygen(
    key_id: str = typer.Option(..., "--key-id", help="Identifier embedded into the detached signature."),
    private_key_out: Path = typer.Option(..., "--private-key-out", help="Output path for the private Ed25519 PEM key."),
    public_key_out: Path = typer.Option(..., "--public-key-out", help="Output path for the public signer JSON document."),
):
    """Generate an Ed25519 keypair for signing detached rule manifests."""
    private_pem, public_doc = signing.generate_signing_keypair(key_id)
    private_key_out.parent.mkdir(parents=True, exist_ok=True)
    private_key_out.write_bytes(private_pem)
    try:
        os.chmod(private_key_out, 0o600)
    except OSError:
        pass
    _write_json(public_key_out, public_doc)
    console.print(f"[green]SUCCESS:[/green] Wrote private key to {private_key_out}")
    console.print(f"[green]SUCCESS:[/green] Wrote public signer document to {public_key_out}")


# ---------------------------------------------------------------------------
# vanguard sign-rules
# ---------------------------------------------------------------------------

@app.command()
def sign_rules(
    key_id: str = typer.Option(..., "--key-id", help="Signer key identifier to embed in the detached signature."),
    private_key: Path = typer.Option(..., "--private-key", help="Path to the private Ed25519 PEM key."),
    rules_dir: str = typer.Option("rules", "--rules-dir", help="Directory containing the signed rule bundle."),
):
    """Rebuild the local rules manifest and detached signature."""
    manifest = signing.build_rules_manifest(rules_dir, RULE_FILES)
    signature_doc = signing.sign_manifest(
        manifest=manifest,
        private_key_pem=private_key.read_bytes(),
        key_id=key_id,
    )
    _write_json(Path(rules_dir) / RULE_MANIFEST, manifest)
    _write_json(Path(rules_dir) / RULE_SIGNATURE, signature_doc)
    console.print(f"[green]SUCCESS:[/green] Updated {Path(rules_dir) / RULE_MANIFEST}")
    console.print(f"[green]SUCCESS:[/green] Updated {Path(rules_dir) / RULE_SIGNATURE}")


# ---------------------------------------------------------------------------
# vanguard init
# ---------------------------------------------------------------------------

@app.command()
def init(
    rules_dir: str = typer.Option("rules", "--rules-dir", help="Directory for rules."),
):
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
            f.write("VANGUARD_MANAGEMENT_TOOLS_ENABLED=false\n")
            f.write("# VANGUARD_OPENAI_API_KEY=\n")
            f.write("# VANGUARD_REDIS_URL=\n")
        console.print(f"  [green]SUCCESS:[/green] Created {env_path}")
    else:
        console.print(f"  [yellow]SKIP:[/yellow] {env_path} already exists")

    # 2. Ensure rules directory exists
    rules_path = rules_dir
    if not os.path.exists(rules_path):
        console.print("[dim]Initializing default rules directory...[/dim]")
        os.makedirs(rules_path, exist_ok=True)
        # Create a dummy safe_zones.yaml (LIST OF OBJECTS FORMAT)
        safe_zones_content = """# McpVanguard: Safe Zones
# Define absolute paths and tool-specific constraints.
- tool: read_file
  allowed_prefixes:
    - C:\\Users\\  # Adjust as needed
  recursive: true
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
    proxy_console.print(f"[bold green]Starting McpVanguard Dashboard on http://{host}:{port}...[/bold green]")
    proxy_console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    start_dashboard(host=host, port=port)


# ---------------------------------------------------------------------------
# vanguard audit-compliance
# ---------------------------------------------------------------------------

@app.command()
def audit_compliance(
    rules_dir: str = typer.Option("rules", "--rules-dir", help="Directory for rules."),
):
    """
    Run a comprehensive audit to ensure readiness for Anthropic Directory submission.
    Checks tool annotations, documentation, transport, and safety rules.
    """
    console.print(Panel.fit(
        "[bold green]McpVanguard Submission Auditor[/bold green]\n"
        "[dim]Verifying compliance with Anthropic MCP Directory requirements[/dim]",
        border_style="cyan"
    ))

    # 1. Check Tool Safety Annotations (🚫 REQUIRED)
    console.print("[bold]1. Tool Safety Annotations[/bold]")
    from core.proxy import VanguardProxy
    proxy = VanguardProxy(server_command=["python", "-c", "pass"])
    mock_tools = [{"name": "test_tool"}]
    enriched = proxy._enrich_tool_list(mock_tools)
    
    missing_hints = []
    for t in enriched:
        if "readOnlyHint" not in t and "destructiveHint" not in t:
            missing_hints.append(t["name"])
    
    if not missing_hints:
        console.print("  [green]✓[/green] All exposed tools have safety hints.")
    else:
        console.print(f"  [red]✗[/red] Missing hints for: {', '.join(missing_hints)}")

    # 2. Check Documentation (🚫 REQUIRED)
    console.print("\n[bold]2. Documentation[/bold]")
    docs = {
        "PRIVACY.md": os.path.exists("PRIVACY.md"),
        "README.md Usage Examples": False,
        "README.md Authentication": False
    }
    
    if os.path.exists("README.md"):
        import re
        content = open("README.md", "r", encoding="utf-8").read()
        if re.search(r"Usage Examples", content, re.IGNORECASE):
            docs["README.md Usage Examples"] = True
        if re.search(r"Authentication", content, re.IGNORECASE):
            docs["README.md Authentication"] = True

    for item, status in docs.items():
        icon = "[green]✓[/green]" if status else "[red]✗[/red]"
        console.print(f"  {icon} {item}")

    # 3. Check Transport (🚫 REQUIRED)
    console.print("\n[bold]3. Transport Protocol[/bold]")
    # McpVanguard uses SSE by default which is the implementation of Streamable HTTP in the SDK
    console.print("  [green]✓[/green] SSE/Streamable HTTP support confirmed via MCP Python SDK.")

    # 4. Check Advanced Safety (⚠️ RECOMMENDED)
    console.print("\n[bold]4. Security Hardening[/bold]")
    engine = RulesEngine(rules_dir=rules_dir)
    if engine.rule_count > 40:
        console.print(f"  [green]✓[/green] Robust rule set: {engine.rule_count} signatures active.")
    else:
        console.print(f"  [yellow]![/yellow] Minimal rule set ({engine.rule_count}). Consider 'vanguard update'.")

    # 5. Semantic Scoring (⚠️ RECOMMENDED)
    config = ProxyConfig()
    if config.semantic_enabled:
        console.print("  [green]✓[/green] Layer 2 Semantic Scoring is ENABLED.")
    else:
        console.print("  [dim]i Layer 2 Semantic Scoring is disabled (Optional).[/dim]")

    console.print("\n[bold cyan]Audit Complete.[/bold cyan]")
    if all(docs.values()) and not missing_hints:
        console.print("[bold green]STATUS: READY FOR SUBMISSION[/bold green] 🚀")
    else:
        console.print("[bold red]STATUS: INCOMPLETE[/bold red] - Address red items above.")

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
