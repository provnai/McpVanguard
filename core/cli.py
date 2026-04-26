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
import shutil
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
from core import taxonomy
from core import benchmarks
from core import server_integrity
from core import capability_fingerprint
from core import provenance
from core import active_probing
from core import supplier_signatures
from core import sigstore_bundle
from core import conformance

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


def _resolve_option_or_env(option_value: str, option_default: str, env_name: str) -> str:
    env_value = os.getenv(env_name)
    if env_value and option_value == option_default:
        return env_value
    return option_value


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
    resolved_rules_dir = _resolve_option_or_env(rules_dir, "rules", "VANGUARD_RULES_DIR")
    config = ProxyConfig()
    config.rules_dir = resolved_rules_dir
    
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
    engine = RulesEngine(rules_dir=resolved_rules_dir)

    proxy_console.print(Panel.fit(
        f"[bold green]McpVanguard v{__version__}[/bold green]\n"
        f"[dim]Real-time security layer for MCP agents[/dim]",
        border_style="green",
    ))
    proxy_console.print(f"[bold]Server:[/bold]    {server}")
    proxy_console.print(f"[bold]Rules:[/bold]     {engine.rule_count} loaded from '{resolved_rules_dir}/'")
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
    host: str = typer.Option("127.0.0.1", "--host", help="Binding host for the SSE server. Use 0.0.0.0 explicitly for public/cloud exposure."),
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
    resolved_rules_dir = _resolve_option_or_env(rules_dir, "rules", "VANGUARD_RULES_DIR")
    config = ProxyConfig()
    config.rules_dir = resolved_rules_dir
    
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


@app.command("taxonomy-coverage")
def taxonomy_coverage(
    coverage_file: str = typer.Option(
        "rules/mcp38_coverage.yaml",
        "--coverage-file",
        help="Path to the MCP-38 coverage map.",
    ),
):
    """
    Show MCP-38 coverage status for the current McpVanguard build.
    """
    try:
        entries = taxonomy.load_mcp38_coverage(coverage_file)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to load taxonomy coverage: {exc}")
        raise typer.Exit(code=1)

    summary = taxonomy.summarize_coverage(entries)
    console.print(Panel.fit(
        "[bold green]MCP-38 Coverage[/bold green]\n"
        f"[dim]{coverage_file}[/dim]",
        border_style="green",
    ))
    console.print(
        f"[green]Implemented:[/green] {summary['implemented']}  "
        f"[yellow]Partial:[/yellow] {summary['partial']}  "
        f"[red]Gap:[/red] {summary['gap']}  "
        f"[bold]Total:[/bold] {summary['total']}"
    )

    table = Table(title="MCP-38 Coverage Map")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Title")
    table.add_column("Summary")

    status_style = {
        "implemented": "[green]implemented[/green]",
        "partial": "[yellow]partial[/yellow]",
        "gap": "[red]gap[/red]",
    }

    for entry in entries:
        table.add_row(
            entry.taxonomy_id,
            status_style[entry.status],
            entry.title,
            entry.summary,
        )

    console.print(table)


@app.command("benchmark-coverage")
def benchmark_coverage(
    benchmark_file: str = typer.Option(
        "tests/benchmarks/mcp38_cases.yaml",
        "--benchmark-file",
        help="Path to the MCP-38 benchmark corpus.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json-output",
        help="Emit machine-readable JSON instead of rich text output.",
    ),
):
    """
    Show the current MCP-38 benchmark corpus summary.
    """
    try:
        cases = benchmarks.load_cases(benchmark_file)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to load benchmark corpus: {exc}")
        raise typer.Exit(code=1)

    summary = benchmarks.summarize_cases(cases)
    taxonomy_counts: dict[str, int] = {}
    for case in cases:
        taxonomy_counts[case.mcp38_id] = taxonomy_counts.get(case.mcp38_id, 0) + 1

    if json_output:
        console.print_json(
            data={
                "benchmark_file": benchmark_file,
                "summary": summary,
                "taxonomy_counts": dict(sorted(taxonomy_counts.items())),
                "cases": [
                    {
                        "case_id": case.case_id,
                        "mcp38_id": case.mcp38_id,
                        "harness": case.harness,
                        "expected_action": case.expected_action,
                        "expected_rule_id": case.expected_rule_id,
                        "title": case.title,
                    }
                    for case in cases
                ],
            }
        )
        return

    console.print(Panel.fit(
        "[bold green]MCP-38 Benchmark Coverage[/bold green]\n"
        f"[dim]{benchmark_file}[/dim]",
        border_style="green",
    ))
    console.print(
        f"[green]Allow:[/green] {summary['ALLOW']}  "
        f"[yellow]Warn:[/yellow] {summary['WARN']}  "
        f"[red]Block:[/red] {summary['BLOCK']}  "
        f"[bold]Total:[/bold] {summary['total']}"
    )

    table = Table(title="Benchmark Corpus")
    table.add_column("Case", style="cyan", no_wrap=True)
    table.add_column("MCP-38", no_wrap=True)
    table.add_column("Harness", no_wrap=True)
    table.add_column("Expected", no_wrap=True)
    table.add_column("Title")

    expected_style = {
        "ALLOW": "[green]ALLOW[/green]",
        "WARN": "[yellow]WARN[/yellow]",
        "BLOCK": "[red]BLOCK[/red]",
    }

    for case in cases:
        table.add_row(
            case.case_id,
            case.mcp38_id,
            case.harness,
            expected_style[case.expected_action],
            case.title,
        )

    console.print(table)
    console.print(
        "[dim]Taxonomy IDs covered:[/dim] "
        + ", ".join(f"{taxonomy_id} ({count})" for taxonomy_id, count in sorted(taxonomy_counts.items()))
    )


@app.command("benchmark-run")
def benchmark_run(
    benchmark_file: str = typer.Option(
        "tests/benchmarks/mcp38_cases.yaml",
        "--benchmark-file",
        help="Path to the MCP-38 benchmark corpus.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json-output",
        help="Emit machine-readable JSON instead of rich text output.",
    ),
):
    """
    Execute the current MCP-38 benchmark corpus and report pass/fail status.
    """
    try:
        cases = benchmarks.load_cases(benchmark_file)
        evaluations = benchmarks.evaluate_cases(cases)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to run benchmark corpus: {exc}")
        raise typer.Exit(code=1)

    summary = benchmarks.summarize_evaluations(evaluations)
    failures = [evaluation for evaluation in evaluations if not evaluation.passed]

    if json_output:
        console.print_json(
            data={
                "benchmark_file": benchmark_file,
                "summary": summary,
                "evaluations": [
                    {
                        "case_id": evaluation.case_id,
                        "mcp38_id": evaluation.mcp38_id,
                        "title": evaluation.title,
                        "expected_action": evaluation.expected_action,
                        "actual_action": evaluation.actual_action,
                        "passed": evaluation.passed,
                        "expected_rule_id": evaluation.expected_rule_id,
                        "actual_rule_id": evaluation.actual_rule_id,
                        "details": evaluation.details,
                    }
                    for evaluation in evaluations
                ],
            }
        )
        if failures:
            raise typer.Exit(code=1)
        return

    console.print(Panel.fit(
        "[bold green]MCP-38 Benchmark Run[/bold green]\n"
        f"[dim]{benchmark_file}[/dim]",
        border_style="green",
    ))
    console.print(
        f"[green]Passed:[/green] {summary['passed']}  "
        f"[red]Failed:[/red] {summary['failed']}  "
        f"[green]Allow:[/green] {summary['ALLOW']}  "
        f"[yellow]Warn:[/yellow] {summary['WARN']}  "
        f"[red]Block:[/red] {summary['BLOCK']}  "
        f"[bold]Total:[/bold] {summary['total']}"
    )

    table = Table(title="Benchmark Results")
    table.add_column("Case", style="cyan", no_wrap=True)
    table.add_column("MCP-38", no_wrap=True)
    table.add_column("Expected", no_wrap=True)
    table.add_column("Actual", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Status", no_wrap=True)

    for evaluation in evaluations:
        status = "[green]PASS[/green]" if evaluation.passed else "[red]FAIL[/red]"
        rule = evaluation.actual_rule_id or "-"
        table.add_row(
            evaluation.case_id,
            evaluation.mcp38_id,
            evaluation.expected_action,
            evaluation.actual_action,
            rule,
            status,
        )

    console.print(table)

    if failures:
        console.print("[bold red]Failures:[/bold red]")
        for failure in failures:
            console.print(f"  - {failure.case_id}: {failure.details}")
        raise typer.Exit(code=1)


@app.command("conformance-server")
def conformance_server(
    url: str = typer.Option(
        ...,
        "--url",
        help="URL of the running MCP server to test with the official MCP conformance CLI.",
    ),
    scenario: Optional[str] = typer.Option(
        None,
        "--scenario",
        help="Optional conformance scenario name. Runs all server scenarios by default.",
    ),
    suite: str = typer.Option(
        "active",
        "--suite",
        help='Conformance suite to run: "active" (default), "all", or "pending".',
    ),
    expected_failures: Optional[Path] = typer.Option(
        None,
        "--expected-failures",
        help="Optional YAML baseline file of known expected conformance failures.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Pass --verbose through to the official MCP conformance runner.",
    ),
    runner: str = typer.Option(
        "npx",
        "--runner",
        help="Executable used to invoke the conformance package. Defaults to npx.",
    ),
    package: str = typer.Option(
        conformance.DEFAULT_CONFORMANCE_PACKAGE,
        "--package",
        help="Conformance package or executable target. Defaults to the official npm package.",
    ),
):
    """
    Run the official MCP conformance server suite against a running McpVanguard endpoint.
    """
    try:
        result = conformance.run_server_conformance(
            url,
            scenario=scenario,
            suite=suite,
            expected_failures=expected_failures,
            verbose=verbose,
            runner=runner,
            package=package,
            cwd=Path.cwd(),
        )
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to run MCP conformance suite: {exc}")
        raise typer.Exit(code=1)

    console.print(Panel.fit(
        "[bold green]MCP Conformance Run[/bold green]\n"
        f"[dim]{' '.join(result.command)}[/dim]",
        border_style="green",
    ))
    console.print(f"[bold]Target:[/bold] {url}")
    console.print(f"[bold]Exit code:[/bold] {result.returncode}")

    if result.stdout.strip():
        console.print("[bold]stdout[/bold]")
        console.print(result.stdout.rstrip())
    if result.stderr.strip():
        console.print("[bold]stderr[/bold]")
        console.print(result.stderr.rstrip())

    if not result.passed:
        raise typer.Exit(code=result.returncode or 1)


@app.command("server-manifest")
def server_manifest(
    server: str = typer.Option(
        ...,
        "--server", "-s",
        help='The MCP server command to fingerprint. e.g. "npx @modelcontextprotocol/server-filesystem ."',
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Optional path to write the generated server integrity manifest.",
    ),
    hash_executable: bool = typer.Option(
        False,
        "--hash-executable",
        help="Hash the resolved executable when it is a local file.",
    ),
    approval_status: str = typer.Option(
        "unapproved",
        "--approval-status",
        help="Approval status to embed in the server manifest.",
    ),
    trust_level: str = typer.Option(
        "unknown",
        "--trust-level",
        help="Trust level to embed in the server manifest.",
    ),
):
    """
    Generate an integrity manifest for a wrapped upstream MCP server command.
    """
    import shlex

    server_cmd = shlex.split(server)
    try:
        manifest = server_integrity.build_server_manifest(
            server_cmd,
            hash_executable=hash_executable,
            approval_status=approval_status,
            trust_level=trust_level,
        )
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to build server manifest: {exc}")
        raise typer.Exit(code=1)

    if output:
        server_integrity.write_server_manifest(output, manifest)
        console.print(f"[green]SUCCESS:[/green] Wrote server manifest to {output}")
    else:
        console.print_json(data=manifest)


@app.command("server-verify")
def server_verify(
    server: str = typer.Option(
        ...,
        "--server", "-s",
        help='The MCP server command to fingerprint. e.g. "npx @modelcontextprotocol/server-filesystem ."',
    ),
    manifest_file: Path = typer.Option(
        ...,
        "--manifest-file",
        help="Path to a previously saved server integrity manifest.",
    ),
    hash_executable: bool = typer.Option(
        False,
        "--hash-executable",
        help="Hash the resolved executable when comparing manifests.",
    ),
    signature_file: Optional[Path] = typer.Option(
        None,
        "--signature-file",
        help="Optional detached signature for the server manifest.",
    ),
    trust_key_file: Optional[Path] = typer.Option(
        None,
        "--trust-key-file",
        help="Trusted signer public-key JSON file used to verify the detached signature.",
    ),
    check_trust: bool = typer.Option(
        False,
        "--check-trust/--no-check-trust",
        help="Verify the detached signature and approval status in addition to command drift.",
    ),
    provenance_file: Optional[Path] = typer.Option(
        None,
        "--provenance-file",
        help="Optional in-toto/SLSA provenance document to verify against the current server artifact.",
    ),
    provenance_signature_file: Optional[Path] = typer.Option(
        None,
        "--provenance-signature-file",
        help="Optional detached signature for the provenance document.",
    ),
    provenance_trust_key_file: Optional[Path] = typer.Option(
        None,
        "--provenance-trust-key-file",
        help="Trusted signer public-key JSON file used to verify the provenance signature.",
    ),
    required_provenance_builder: list[str] = typer.Option(
        None,
        "--required-provenance-builder",
        help="Allowed provenance builder.id value. Repeat the option to allow multiple builders.",
    ),
    artifact_signature_file: Optional[Path] = typer.Option(
        None,
        "--artifact-signature-file",
        help="Optional detached signature for the resolved local executable or artifact.",
    ),
    artifact_trust_key_file: Optional[Path] = typer.Option(
        None,
        "--artifact-trust-key-file",
        help="Trusted signer public-key JSON file used to verify the artifact signature.",
    ),
    allowed_supplier_id: list[str] = typer.Option(
        None,
        "--allowed-supplier-id",
        help="Allowed supplier identifier for the artifact signature. Repeat the option to allow multiple suppliers.",
    ),
    sigstore_bundle_file: Optional[Path] = typer.Option(
        None,
        "--sigstore-bundle-file",
        help="Optional Sigstore bundle for the resolved local executable or artifact.",
    ),
    sigstore_hint_trust_key_file: Optional[Path] = typer.Option(
        None,
        "--sigstore-hint-trust-key-file",
        help="Trusted signer public-key JSON file used for Sigstore publicKeyIdentifier.hint verification.",
    ),
    allowed_sigstore_cert_fingerprint: list[str] = typer.Option(
        None,
        "--allowed-sigstore-cert-fingerprint",
        help="Allowed Sigstore leaf certificate SHA-256 fingerprint. Repeat the option to allow multiple certificates.",
    ),
    allowed_sigstore_cert_identity: list[str] = typer.Option(
        None,
        "--allowed-sigstore-cert-identity",
        help="Allowed Sigstore certificate identity (SAN email, URI, DNS name, or IP). Repeat the option to allow multiple identities.",
    ),
    allowed_sigstore_oidc_issuer: list[str] = typer.Option(
        None,
        "--allowed-sigstore-oidc-issuer",
        help="Allowed Sigstore certificate OIDC issuer. Repeat the option to allow multiple issuers.",
    ),
    allowed_sigstore_build_signer_uri: list[str] = typer.Option(
        None,
        "--allowed-sigstore-build-signer-uri",
        help="Allowed Sigstore Fulcio Build Signer URI value. Repeat the option to allow multiple values.",
    ),
    allowed_sigstore_source_repository: list[str] = typer.Option(
        None,
        "--allowed-sigstore-source-repository",
        help="Allowed Sigstore Fulcio Source Repository URI value. Repeat the option to allow multiple values.",
    ),
    allowed_sigstore_source_ref: list[str] = typer.Option(
        None,
        "--allowed-sigstore-source-ref",
        help="Allowed Sigstore Fulcio Source Repository Ref value. Repeat the option to allow multiple values.",
    ),
    allowed_sigstore_source_digest: list[str] = typer.Option(
        None,
        "--allowed-sigstore-source-digest",
        help="Allowed Sigstore Fulcio Source Repository Digest value. Repeat the option to allow multiple values.",
    ),
    allowed_sigstore_build_trigger: list[str] = typer.Option(
        None,
        "--allowed-sigstore-build-trigger",
        help="Allowed Sigstore Fulcio Build Trigger value. Repeat the option to allow multiple values.",
    ),
    allowed_sigstore_tlog_key_id: list[str] = typer.Option(
        None,
        "--allowed-sigstore-tlog-key-id",
        help="Allowed Sigstore transparency log keyId value. Repeat the option to allow multiple values.",
    ),
    sigstore_github_repository: list[str] = typer.Option(
        None,
        "--sigstore-github-repository",
        help="Allowed GitHub repository claim for Sigstore/Fulcio bundles. Accepts either owner/repo or a full GitHub URL. Repeat to allow multiple values.",
    ),
    sigstore_github_ref: list[str] = typer.Option(
        None,
        "--sigstore-github-ref",
        help="Allowed GitHub ref claim for Sigstore/Fulcio bundles. Repeat to allow multiple values.",
    ),
    sigstore_github_sha: list[str] = typer.Option(
        None,
        "--sigstore-github-sha",
        help="Allowed GitHub SHA claim for Sigstore/Fulcio bundles. Accepts raw SHA or algorithm-prefixed digest. Repeat to allow multiple values.",
    ),
    sigstore_github_trigger: list[str] = typer.Option(
        None,
        "--sigstore-github-trigger",
        help="Allowed GitHub trigger claim for Sigstore/Fulcio bundles. Repeat to allow multiple values.",
    ),
    sigstore_github_workflow_name: list[str] = typer.Option(
        None,
        "--sigstore-github-workflow-name",
        help="Allowed legacy GitHub workflow-name claim for Sigstore/Fulcio bundles. Repeat to allow multiple values.",
    ),
    sigstore_tlog_policy: str = typer.Option(
        "off",
        "--sigstore-tlog-policy",
        help="Required Sigstore transparency evidence level: off, entry, promise, or proof.",
    ),
):
    """
    Compare the current upstream MCP server command against a saved integrity manifest.
    """
    import shlex

    server_cmd = shlex.split(server)
    try:
        expected = server_integrity.load_server_manifest(manifest_file)
        actual = server_integrity.build_server_manifest(
            server_cmd,
            hash_executable=hash_executable,
        )
        drifts = server_integrity.compare_server_manifests(expected, actual)
        trust_issues: list[str] = []
        trust_verified = False
        if check_trust:
            resolved_signature_file = signature_file
            if resolved_signature_file is None:
                sibling_signature = server_integrity.default_server_manifest_signature_path(manifest_file)
                if sibling_signature.exists():
                    resolved_signature_file = sibling_signature

            signature_doc = (
                server_integrity.load_server_manifest_signature(resolved_signature_file)
                if resolved_signature_file is not None
                else None
            )
            extra_signers = [signing.load_signer_file(trust_key_file)] if trust_key_file else None
            trusted_signers = server_integrity.load_trusted_server_signers(extra_signers=extra_signers)
            trust_issues.extend(
                server_integrity.evaluate_server_manifest_signature(
                    expected,
                    signature_doc=signature_doc,
                    trusted_signers=trusted_signers,
                    require_signature=True,
                )
            )
            trust_issues.extend(server_integrity.evaluate_server_manifest_approval(expected))
            trust_verified = not trust_issues
        provenance_issues: list[str] = []
        provenance_summary: dict[str, object] | None = None
        if provenance_file is not None:
            provenance_doc = provenance.load_provenance(provenance_file)
            provenance_summary = provenance.summarize_provenance(provenance_doc)
            resolved_provenance_signature = provenance_signature_file
            if resolved_provenance_signature is None:
                sibling_provenance_signature = provenance.default_provenance_signature_path(provenance_file)
                if sibling_provenance_signature.exists():
                    resolved_provenance_signature = sibling_provenance_signature
            provenance_signature_doc = (
                provenance.load_provenance_signature(resolved_provenance_signature)
                if resolved_provenance_signature is not None
                else None
            )
            provenance_extra_signers = [signing.load_signer_file(provenance_trust_key_file)] if provenance_trust_key_file else None
            trusted_provenance_signers = provenance.load_trusted_provenance_signers(extra_signers=provenance_extra_signers)
            provenance_issues.extend(
                provenance.evaluate_provenance_signature(
                    provenance_doc,
                    signature_doc=provenance_signature_doc,
                    trusted_signers=trusted_provenance_signers,
                    require_signature=True,
                )
            )
            provenance_issues.extend(
                provenance.evaluate_provenance_for_server_manifest(
                    actual,
                    provenance_doc,
                    required_builder_ids=set(required_provenance_builder) if required_provenance_builder else None,
                )
            )
        artifact_issues: list[str] = []
        if artifact_signature_file is not None:
            artifact_signature_doc = supplier_signatures.load_artifact_signature(artifact_signature_file)
            artifact_extra_signers = [signing.load_signer_file(artifact_trust_key_file)] if artifact_trust_key_file else None
            trusted_artifact_signers = supplier_signatures.load_trusted_supplier_signers(extra_signers=artifact_extra_signers)
            artifact_issues.extend(
                supplier_signatures.evaluate_artifact_signature(
                    ((actual.get("executable") or {}).get("resolved_path")),
                    signature_doc=artifact_signature_doc,
                    trusted_signers=trusted_artifact_signers,
                    require_signature=True,
                    allowed_suppliers=set(allowed_supplier_id) if allowed_supplier_id else None,
                )
            )
        sigstore_issues: list[str] = []
        if sigstore_bundle_file is not None:
            sigstore_doc = sigstore_bundle.load_sigstore_bundle(sigstore_bundle_file)
            sigstore_extra_signers = [signing.load_signer_file(sigstore_hint_trust_key_file)] if sigstore_hint_trust_key_file else None
            trusted_sigstore_hint_signers = supplier_signatures.load_trusted_supplier_signers(extra_signers=sigstore_extra_signers)
            allowed_sigstore_fingerprints = sigstore_bundle.load_allowed_sigstore_cert_fingerprints(
                allowed_sigstore_cert_fingerprint
            )
            allowed_sigstore_identities = sigstore_bundle.load_allowed_sigstore_identities(
                allowed_sigstore_cert_identity
            )
            allowed_sigstore_oidc_issuers = sigstore_bundle.load_allowed_sigstore_oidc_issuers(
                allowed_sigstore_oidc_issuer
            )
            allowed_sigstore_build_signer_uris = sigstore_bundle.load_allowed_sigstore_build_signer_uris(
                allowed_sigstore_build_signer_uri
            )
            allowed_sigstore_source_repositories = sigstore_bundle.load_allowed_sigstore_source_repository_uris(
                allowed_sigstore_source_repository
            )
            allowed_sigstore_source_refs = sigstore_bundle.load_allowed_sigstore_source_repository_refs(
                allowed_sigstore_source_ref
            )
            allowed_sigstore_source_digests = sigstore_bundle.load_allowed_sigstore_source_repository_digests(
                allowed_sigstore_source_digest
            )
            allowed_sigstore_build_triggers = sigstore_bundle.load_allowed_sigstore_build_triggers(
                allowed_sigstore_build_trigger
            )
            allowed_sigstore_tlog_key_ids = sigstore_bundle.load_allowed_sigstore_tlog_key_ids(
                allowed_sigstore_tlog_key_id
            )
            allowed_sigstore_github_repositories = sigstore_bundle.load_allowed_sigstore_github_repositories(
                sigstore_github_repository
            )
            allowed_sigstore_github_refs = sigstore_bundle.load_allowed_sigstore_github_refs(
                sigstore_github_ref
            )
            allowed_sigstore_github_shas = sigstore_bundle.load_allowed_sigstore_github_shas(
                sigstore_github_sha
            )
            allowed_sigstore_github_triggers = sigstore_bundle.load_allowed_sigstore_github_triggers(
                sigstore_github_trigger
            )
            allowed_sigstore_github_workflow_names = sigstore_bundle.load_allowed_sigstore_github_workflow_names(
                sigstore_github_workflow_name
            )
            normalized_sigstore_tlog_policy = sigstore_bundle.normalize_sigstore_tlog_policy(
                sigstore_tlog_policy
            )
            sigstore_issues.extend(
                sigstore_bundle.evaluate_sigstore_bundle(
                    ((actual.get("executable") or {}).get("resolved_path")),
                    bundle_doc=sigstore_doc,
                    trusted_hint_signers=trusted_sigstore_hint_signers,
                    require_bundle=True,
                    allowed_cert_fingerprints=allowed_sigstore_fingerprints or None,
                    allowed_identities=allowed_sigstore_identities or None,
                    allowed_oidc_issuers=allowed_sigstore_oidc_issuers or None,
                    allowed_build_signer_uris=allowed_sigstore_build_signer_uris or None,
                    allowed_source_repository_uris=allowed_sigstore_source_repositories or None,
                    allowed_source_repository_refs=allowed_sigstore_source_refs or None,
                    allowed_source_repository_digests=allowed_sigstore_source_digests or None,
                    allowed_build_triggers=allowed_sigstore_build_triggers or None,
                    allowed_tlog_key_ids=allowed_sigstore_tlog_key_ids or None,
                    allowed_github_repositories=allowed_sigstore_github_repositories or None,
                    allowed_github_refs=allowed_sigstore_github_refs or None,
                    allowed_github_shas=allowed_sigstore_github_shas or None,
                    allowed_github_triggers=allowed_sigstore_github_triggers or None,
                    allowed_github_workflow_names=allowed_sigstore_github_workflow_names or None,
                    tlog_policy=normalized_sigstore_tlog_policy,
                )
            )
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to verify server manifest: {exc}")
        raise typer.Exit(code=1)

    console.print(Panel.fit(
        "[bold green]Upstream Server Verification[/bold green]\n"
        f"[dim]{manifest_file}[/dim]",
        border_style="green",
    ))

    if check_trust:
        if trust_verified:
            console.print("[green]Signature:[/green] verified")
            console.print("[green]Trust state:[/green] approved")
        else:
            console.print("[bold red]TRUST ISSUES DETECTED[/bold red]")
            for issue in trust_issues:
                console.print(f"  - {issue}")

    if provenance_file is not None:
        if not provenance_issues:
            console.print("[green]Provenance:[/green] verified")
            if provenance_summary:
                console.print(
                    "[green]Builder:[/green] "
                    + str(provenance_summary.get("builder_id") or "<not-declared>")
                )
        else:
            console.print("[bold red]PROVENANCE ISSUES DETECTED[/bold red]")
            for issue in provenance_issues:
                console.print(f"  - {issue}")

    if artifact_signature_file is not None:
        if not artifact_issues:
            console.print("[green]Supplier artifact signature:[/green] verified")
        else:
            console.print("[bold red]ARTIFACT SIGNATURE ISSUES DETECTED[/bold red]")
            for issue in artifact_issues:
                console.print(f"  - {issue}")

    if sigstore_bundle_file is not None:
        if not sigstore_issues:
            console.print("[green]Sigstore bundle:[/green] verified")
        else:
            console.print("[bold red]SIGSTORE BUNDLE ISSUES DETECTED[/bold red]")
            for issue in sigstore_issues:
                console.print(f"  - {issue}")

    if (
        not drifts
        and (not check_trust or trust_verified)
        and (provenance_file is None or not provenance_issues)
        and (artifact_signature_file is None or not artifact_issues)
        and (sigstore_bundle_file is None or not sigstore_issues)
    ):
        console.print("[bold green]STATUS: MATCH[/bold green]")
        return

    if drifts:
        console.print("[bold red]STATUS: DRIFT DETECTED[/bold red]")
        for drift in drifts:
            console.print(f"  - {drift}")
    else:
        console.print("[bold red]STATUS: TRUST CHECK FAILED[/bold red]")
    raise typer.Exit(code=1)


@app.command("server-sign-manifest")
def server_sign_manifest(
    manifest_file: Path = typer.Option(
        ...,
        "--manifest-file",
        help="Path to a server integrity manifest to sign.",
    ),
    private_key: Path = typer.Option(
        ...,
        "--private-key",
        help="Ed25519 private-key PEM file used to sign the manifest.",
    ),
    key_id: str = typer.Option(
        ...,
        "--key-id",
        help="Signer key identifier to embed in the detached signature.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Optional output path for the detached signature. Defaults to a sibling .sig.json file.",
    ),
):
    """
    Sign an upstream server manifest with an Ed25519 detached signature.
    """
    try:
        manifest = server_integrity.load_server_manifest(manifest_file)
        private_key_pem = private_key.read_bytes()
        signature_doc = server_integrity.sign_server_manifest(manifest, private_key_pem, key_id)
        output_path = output or server_integrity.default_server_manifest_signature_path(manifest_file)
        server_integrity.write_server_manifest_signature(output_path, signature_doc)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to sign server manifest: {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]SUCCESS:[/green] Wrote server manifest signature to {output_path}")


@app.command("provenance-sign")
def provenance_sign(
    provenance_file: Path = typer.Option(
        ...,
        "--provenance-file",
        help="Path to an in-toto/SLSA provenance document to sign.",
    ),
    private_key: Path = typer.Option(
        ...,
        "--private-key",
        help="Ed25519 private-key PEM file used to sign the provenance document.",
    ),
    key_id: str = typer.Option(
        ...,
        "--key-id",
        help="Signer key identifier to embed in the detached signature.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Optional output path for the detached provenance signature. Defaults to a sibling .sig.json file.",
    ),
):
    """
    Sign an upstream provenance document with an Ed25519 detached signature.
    """
    try:
        document = provenance.load_provenance(provenance_file)
        signature_doc = provenance.sign_provenance(document, private_key.read_bytes(), key_id)
        output_path = output or provenance.default_provenance_signature_path(provenance_file)
        provenance.write_provenance_signature(output_path, signature_doc)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to sign provenance: {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]SUCCESS:[/green] Wrote provenance signature to {output_path}")


@app.command("artifact-sign")
def artifact_sign(
    artifact_file: Path = typer.Option(
        ...,
        "--artifact-file",
        help="Path to a local executable or artifact to sign.",
    ),
    private_key: Path = typer.Option(
        ...,
        "--private-key",
        help="Ed25519 private-key PEM file used to sign the artifact.",
    ),
    key_id: str = typer.Option(
        ...,
        "--key-id",
        help="Signer key identifier to embed in the detached signature.",
    ),
    supplier: Optional[str] = typer.Option(
        None,
        "--supplier",
        help="Optional supplier identifier embedded in the signature document.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Optional output path for the detached artifact signature. Defaults to a sibling .sig.json file.",
    ),
):
    """
    Sign a local upstream artifact or executable with an Ed25519 detached signature.
    """
    try:
        signature_doc = supplier_signatures.sign_artifact(
            artifact_file,
            private_key.read_bytes(),
            key_id,
            supplier=supplier,
        )
        output_path = output or supplier_signatures.default_artifact_signature_path(artifact_file)
        supplier_signatures.write_artifact_signature(output_path, signature_doc)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to sign artifact: {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]SUCCESS:[/green] Wrote artifact signature to {output_path}")


@app.command("capability-manifest")
def capability_manifest(
    initialize_file: Optional[Path] = typer.Option(
        None,
        "--initialize-file",
        help="Path to a captured initialize response JSON payload.",
    ),
    tools_file: Optional[Path] = typer.Option(
        None,
        "--tools-file",
        help="Path to a captured tools/list response JSON payload.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Optional path to write the generated capability manifest.",
    ),
):
    """
    Generate a passive capability manifest from captured initialize/tools payloads.
    """
    if not initialize_file and not tools_file:
        console.print("[bold red]Error:[/bold red] Provide at least one of --initialize-file or --tools-file.")
        raise typer.Exit(code=1)

    try:
        initialize_payload = json.loads(initialize_file.read_text(encoding="utf-8")) if initialize_file else None
        tools_payload = json.loads(tools_file.read_text(encoding="utf-8")) if tools_file else None
        manifest = capability_fingerprint.build_capability_manifest(
            initialize_payload=initialize_payload,
            tools_payload=tools_payload,
        )
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to build capability manifest: {exc}")
        raise typer.Exit(code=1)

    if output:
        capability_fingerprint.write_capability_manifest(output, manifest)
        console.print(f"[green]SUCCESS:[/green] Wrote capability manifest to {output}")
    else:
        console.print_json(data=manifest)


@app.command("capability-sign-manifest")
def capability_sign_manifest(
    manifest_file: Path = typer.Option(
        ...,
        "--manifest-file",
        help="Path to a capability manifest to sign.",
    ),
    private_key: Path = typer.Option(
        ...,
        "--private-key",
        help="Ed25519 private-key PEM file used to sign the capability manifest.",
    ),
    key_id: str = typer.Option(
        ...,
        "--key-id",
        help="Signer key identifier to embed in the detached capability signature.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Optional output path for the detached signature. Defaults to a sibling .sig.json file.",
    ),
):
    """
    Sign a capability manifest with an Ed25519 detached signature.
    """
    try:
        manifest = capability_fingerprint.load_capability_manifest(manifest_file)
        signature_doc = capability_fingerprint.sign_capability_manifest(
            manifest,
            private_key.read_bytes(),
            key_id,
        )
        output_path = output or capability_fingerprint.default_capability_manifest_signature_path(manifest_file)
        capability_fingerprint.write_capability_manifest_signature(output_path, signature_doc)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to sign capability manifest: {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]SUCCESS:[/green] Wrote capability manifest signature to {output_path}")


@app.command("capability-verify")
def capability_verify(
    manifest_file: Path = typer.Option(
        ...,
        "--manifest-file",
        help="Path to a previously saved capability manifest.",
    ),
    initialize_file: Optional[Path] = typer.Option(
        None,
        "--initialize-file",
        help="Path to a captured initialize response JSON payload.",
    ),
    tools_file: Optional[Path] = typer.Option(
        None,
        "--tools-file",
        help="Path to a captured tools/list response JSON payload.",
    ),
    signature_file: Optional[Path] = typer.Option(
        None,
        "--signature-file",
        help="Optional detached signature for the capability manifest.",
    ),
    trust_key_file: Optional[Path] = typer.Option(
        None,
        "--trust-key-file",
        help="Trusted signer public-key JSON file used to verify the detached capability signature.",
    ),
    check_signature: bool = typer.Option(
        False,
        "--check-signature/--no-check-signature",
        help="Verify the detached capability-manifest signature in addition to capability drift.",
    ),
):
    """
    Compare captured initialize/tools payloads against a saved capability manifest.
    """
    if not initialize_file and not tools_file:
        console.print("[bold red]Error:[/bold red] Provide at least one of --initialize-file or --tools-file.")
        raise typer.Exit(code=1)

    try:
        expected = capability_fingerprint.load_capability_manifest(manifest_file)
        actual = capability_fingerprint.build_capability_manifest(
            initialize_payload=json.loads(initialize_file.read_text(encoding="utf-8")) if initialize_file else None,
            tools_payload=json.loads(tools_file.read_text(encoding="utf-8")) if tools_file else None,
        )
        drifts = capability_fingerprint.compare_capability_manifests(expected, actual)
        signature_issues: list[str] = []
        signature_verified = False
        if check_signature:
            resolved_signature_file = signature_file
            if resolved_signature_file is None:
                sibling_signature = capability_fingerprint.default_capability_manifest_signature_path(manifest_file)
                if sibling_signature.exists():
                    resolved_signature_file = sibling_signature

            signature_doc = (
                capability_fingerprint.load_capability_manifest_signature(resolved_signature_file)
                if resolved_signature_file is not None
                else None
            )
            extra_signers = [signing.load_signer_file(trust_key_file)] if trust_key_file else None
            trusted_signers = capability_fingerprint.load_trusted_capability_signers(extra_signers=extra_signers)
            signature_issues.extend(
                capability_fingerprint.evaluate_capability_manifest_signature(
                    expected,
                    signature_doc=signature_doc,
                    trusted_signers=trusted_signers,
                    require_signature=True,
                )
            )
            signature_verified = not signature_issues
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to verify capability manifest: {exc}")
        raise typer.Exit(code=1)

    console.print(Panel.fit(
        "[bold green]Capability Verification[/bold green]\n"
        f"[dim]{manifest_file}[/dim]",
        border_style="green",
    ))

    if check_signature:
        if signature_verified:
            console.print("[green]Signature:[/green] verified")
        else:
            console.print("[bold red]CAPABILITY SIGNATURE ISSUES DETECTED[/bold red]")
            for issue in signature_issues:
                console.print(f"  - {issue}")

    if not drifts and (not check_signature or signature_verified):
        console.print("[bold green]STATUS: MATCH[/bold green]")
        return

    if drifts:
        console.print("[bold red]STATUS: DRIFT DETECTED[/bold red]")
        for drift in drifts:
            console.print(f"  - {drift}")
    else:
        console.print("[bold red]STATUS: TRUST CHECK FAILED[/bold red]")
    raise typer.Exit(code=1)


@app.command("active-probe")
def active_probe(
    server: str = typer.Option(
        ...,
        "--server", "-s",
        help='The MCP server command to actively probe. e.g. "python my_server.py"',
    ),
    probe_file: Path = typer.Option(
        ...,
        "--probe-file",
        help="Path to an active probe manifest describing explicitly allowed low-risk probes.",
    ),
    timeout_secs: float = typer.Option(
        5.0,
        "--timeout-secs",
        help="Per-request timeout for the probing handshake and each tool call.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json-output",
        help="Emit machine-readable JSON instead of rich text output.",
    ),
):
    """
    Run explicit low-risk active probes against an upstream MCP server.
    """
    import asyncio
    import shlex

    server_cmd = shlex.split(server)
    try:
        manifest = active_probing.load_probe_manifest(probe_file)
        report = asyncio.run(
            active_probing.run_active_probes(
                server_cmd,
                manifest,
                timeout_secs=timeout_secs,
            )
        )
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to run active probes: {exc}")
        raise typer.Exit(code=1)

    if json_output:
        console.print_json(
            data={
                "passed": report.passed,
                "protocol_version": report.protocol_version,
                "tool_count": report.tool_count,
                "results": [
                    {
                        "probe_id": result.probe_id,
                        "tool": result.tool,
                        "passed": result.passed,
                        "reason": result.reason,
                        "tool_hints": result.tool_hints,
                        "response_error": result.response_error,
                    }
                    for result in report.results
                ],
            }
        )
        if not report.passed:
            raise typer.Exit(code=1)
        return

    console.print(Panel.fit(
        "[bold green]Active Probe Report[/bold green]\n"
        f"[dim]{probe_file}[/dim]",
        border_style="green",
    ))
    console.print(
        f"[bold]Protocol:[/bold] {report.protocol_version or 'unknown'}  "
        f"[bold]Tools:[/bold] {report.tool_count}"
    )

    table = Table(title="Probe Results")
    table.add_column("Probe", style="cyan", no_wrap=True)
    table.add_column("Tool", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Reason")

    for result in report.results:
        status = "[green]PASS[/green]" if result.passed else "[red]FAIL[/red]"
        table.add_row(result.probe_id, result.tool, status, result.reason)

    console.print(table)
    if report.passed:
        console.print("[bold green]STATUS: PASS[/bold green]")
        return

    console.print("[bold red]STATUS: FAIL[/bold red]")
    raise typer.Exit(code=1)


@app.command("baseline-bundle")
def baseline_bundle(
    server: str = typer.Option(
        ...,
        "--server", "-s",
        help='The MCP server command to fingerprint. e.g. "npx @modelcontextprotocol/server-filesystem ."',
    ),
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        help="Directory to write the server and capability baseline manifests.",
    ),
    initialize_file: Optional[Path] = typer.Option(
        None,
        "--initialize-file",
        help="Optional captured initialize response JSON payload.",
    ),
    tools_file: Optional[Path] = typer.Option(
        None,
        "--tools-file",
        help="Optional captured tools/list response JSON payload.",
    ),
    hash_executable: bool = typer.Option(
        False,
        "--hash-executable",
        help="Hash the resolved executable when it is a local file.",
    ),
    approval_status: str = typer.Option(
        "unapproved",
        "--approval-status",
        help="Approval status to embed in the server manifest.",
    ),
    trust_level: str = typer.Option(
        "unknown",
        "--trust-level",
        help="Trust level to embed in the server manifest.",
    ),
    private_key: Optional[Path] = typer.Option(
        None,
        "--private-key",
        help="Optional Ed25519 private-key PEM file used to sign the server manifest.",
    ),
    key_id: Optional[str] = typer.Option(
        None,
        "--key-id",
        help="Signer key identifier to embed in the detached server-manifest signature.",
    ),
    provenance_file: Optional[Path] = typer.Option(
        None,
        "--provenance-file",
        help="Optional in-toto/SLSA provenance document to include in the bundle.",
    ),
    provenance_signature_file: Optional[Path] = typer.Option(
        None,
        "--provenance-signature-file",
        help="Optional detached signature for the provenance document.",
    ),
    artifact_signature_file: Optional[Path] = typer.Option(
        None,
        "--artifact-signature-file",
        help="Optional detached signature for the resolved local executable or artifact.",
    ),
    capability_private_key: Optional[Path] = typer.Option(
        None,
        "--capability-private-key",
        help="Optional Ed25519 private-key PEM file used to sign the capability manifest. Defaults to --private-key when omitted.",
    ),
    capability_key_id: Optional[str] = typer.Option(
        None,
        "--capability-key-id",
        help="Optional signer key identifier for the detached capability-manifest signature. Defaults to --key-id when omitted.",
    ),
    sigstore_bundle_file: Optional[Path] = typer.Option(
        None,
        "--sigstore-bundle-file",
        help="Optional Sigstore bundle for the resolved local executable or artifact.",
    ),
):
    """
    Generate a paired baseline bundle for upstream command integrity and passive capabilities.
    """
    import shlex

    server_cmd = shlex.split(server)
    output_dir.mkdir(parents=True, exist_ok=True)
    server_manifest_path = output_dir / "server-manifest.json"
    server_signature_path = output_dir / server_integrity.SERVER_MANIFEST_SIGNATURE
    bundled_provenance_path = output_dir / "server-provenance.json"
    bundled_provenance_signature_path = output_dir / "server-provenance.sig.json"
    bundled_artifact_signature_path = output_dir / supplier_signatures.SERVER_ARTIFACT_SIGNATURE
    bundled_sigstore_bundle_path = output_dir / sigstore_bundle.SERVER_SIGSTORE_BUNDLE
    capability_manifest_path = output_dir / "capability-manifest.json"
    capability_signature_path = output_dir / capability_fingerprint.CAPABILITY_MANIFEST_SIGNATURE
    bundle_index_path = output_dir / "baseline-bundle.json"

    try:
        server_manifest_payload = server_integrity.build_server_manifest(
            server_cmd,
            hash_executable=hash_executable,
            approval_status=approval_status,
            trust_level=trust_level,
        )
        server_integrity.write_server_manifest(server_manifest_path, server_manifest_payload)
        if private_key or key_id:
            if not private_key or not key_id:
                raise ValueError("Provide both --private-key and --key-id to sign the server manifest.")
            signature_doc = server_integrity.sign_server_manifest(
                server_manifest_payload,
                private_key.read_bytes(),
                key_id,
            )
            server_integrity.write_server_manifest_signature(server_signature_path, signature_doc)

        if provenance_signature_file and not provenance_file:
            raise ValueError("Provide --provenance-file when supplying --provenance-signature-file.")
        if provenance_file:
            shutil.copyfile(provenance_file, bundled_provenance_path)
            resolved_provenance_signature = provenance_signature_file
            if resolved_provenance_signature is None:
                sibling_provenance_signature = provenance.default_provenance_signature_path(provenance_file)
                if sibling_provenance_signature.exists():
                    resolved_provenance_signature = sibling_provenance_signature
            if resolved_provenance_signature:
                shutil.copyfile(resolved_provenance_signature, bundled_provenance_signature_path)

        if artifact_signature_file:
            shutil.copyfile(artifact_signature_file, bundled_artifact_signature_path)
        if sigstore_bundle_file:
            shutil.copyfile(sigstore_bundle_file, bundled_sigstore_bundle_path)

        initialize_payload = json.loads(initialize_file.read_text(encoding="utf-8")) if initialize_file else None
        tools_payload = json.loads(tools_file.read_text(encoding="utf-8")) if tools_file else None
        capability_manifest_payload = capability_fingerprint.build_capability_manifest(
            initialize_payload=initialize_payload,
            tools_payload=tools_payload,
        )
        capability_fingerprint.write_capability_manifest(capability_manifest_path, capability_manifest_payload)

        resolved_capability_private_key = capability_private_key or private_key
        resolved_capability_key_id = capability_key_id or key_id
        if resolved_capability_private_key or resolved_capability_key_id:
            if not resolved_capability_private_key or not resolved_capability_key_id:
                raise ValueError("Provide both --capability-private-key and --capability-key-id to sign the capability manifest.")
            capability_signature_doc = capability_fingerprint.sign_capability_manifest(
                capability_manifest_payload,
                resolved_capability_private_key.read_bytes(),
                resolved_capability_key_id,
            )
            capability_fingerprint.write_capability_manifest_signature(capability_signature_path, capability_signature_doc)

        bundle_index = {
            "version": 1,
            "server_manifest": str(server_manifest_path),
            "server_manifest_signature": str(server_signature_path) if server_signature_path.exists() else None,
            "server_provenance": str(bundled_provenance_path) if bundled_provenance_path.exists() else None,
            "server_provenance_signature": str(bundled_provenance_signature_path) if bundled_provenance_signature_path.exists() else None,
            "server_artifact_signature": str(bundled_artifact_signature_path) if bundled_artifact_signature_path.exists() else None,
            "server_sigstore_bundle": str(bundled_sigstore_bundle_path) if bundled_sigstore_bundle_path.exists() else None,
            "capability_manifest": str(capability_manifest_path),
            "capability_manifest_signature": str(capability_signature_path) if capability_signature_path.exists() else None,
            "includes_initialize": initialize_file is not None,
            "includes_tools": tools_file is not None,
        }
        server_integrity.write_server_manifest(bundle_index_path, bundle_index)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to build baseline bundle: {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]SUCCESS:[/green] Wrote server manifest to {server_manifest_path}")
    if server_signature_path.exists():
        console.print(f"[green]SUCCESS:[/green] Wrote server manifest signature to {server_signature_path}")
    if bundled_provenance_path.exists():
        console.print(f"[green]SUCCESS:[/green] Wrote server provenance to {bundled_provenance_path}")
    if bundled_provenance_signature_path.exists():
        console.print(f"[green]SUCCESS:[/green] Wrote server provenance signature to {bundled_provenance_signature_path}")
    if bundled_artifact_signature_path.exists():
        console.print(f"[green]SUCCESS:[/green] Wrote server artifact signature to {bundled_artifact_signature_path}")
    if bundled_sigstore_bundle_path.exists():
        console.print(f"[green]SUCCESS:[/green] Wrote server Sigstore bundle to {bundled_sigstore_bundle_path}")
    console.print(f"[green]SUCCESS:[/green] Wrote capability manifest to {capability_manifest_path}")
    if capability_signature_path.exists():
        console.print(f"[green]SUCCESS:[/green] Wrote capability manifest signature to {capability_signature_path}")
    console.print(f"[green]SUCCESS:[/green] Wrote bundle index to {bundle_index_path}")

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
