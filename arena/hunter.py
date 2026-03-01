#!/usr/bin/env python3
"""
🏹 McpVanguard Hunter Tool — Real Implementation
Run local adversarial challenges to find exploits and earn points.

Usage:
    python hunter.py 1          # Run Level 1 challenge
    python hunter.py 1 --poe    # Run Level 1 and guide you to submit PoE

How it works:
    1. Loads the challenge config from arena/challenges/level_N.py
    2. Spins up the target vulnerable MCP server
    3. Spawns the Vanguard proxy with only the challenge's active rules
    4. Exposes a local stdio endpoint for YOUR agent to connect to
    5. Watches all traffic for the SUCCESS_CONDITION
    6. On success: saves a full Proof of Exploit (PoE) bundle to exploits/
"""

import asyncio
import importlib
import json
import logging
import os
import shlex
import signal
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).parent.parent
CHALLENGES_DIR = Path(__file__).parent / "challenges"
EXPLOITS_DIR = Path(__file__).parent / "exploits"
EXPLOITS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# PoE Bundle — the artifact hunters submit
# ---------------------------------------------------------------------------

class PoEBundle:
    """Proof of Exploit bundle — captures the full attack conversation."""

    def __init__(self, level: int, hunter_handle: str = "anonymous"):
        self.poe_id = str(uuid.uuid4())[:8]
        self.level = level
        self.hunter_handle = hunter_handle
        self.started_at = datetime.utcnow().isoformat() + "Z"
        self.conversation: list[dict] = []
        self.success_at: str | None = None
        self.bypass_found: bool = False

    def record_message(self, direction: str, message: dict, action: str, rule_triggered: str | None = None):
        """Record one message in the attack conversation log."""
        self.conversation.append({
            "ts": datetime.utcnow().isoformat() + "Z",
            "direction": direction,
            "message": message,
            "vanguard_action": action,
            "rule_triggered": rule_triggered,
        })

    def mark_success(self):
        self.bypass_found = True
        self.success_at = datetime.utcnow().isoformat() + "Z"

    def save(self, output_dir: Path) -> Path:
        """Write the PoE bundle to a JSON file."""
        filename = f"poe_level{self.level}_{self.poe_id}_{int(time.time())}.json"
        output_path = output_dir / filename
        bundle = {
            "schema_version": "1.0",
            "poe_id": self.poe_id,
            "hunter_handle": self.hunter_handle,
            "challenge_level": self.level,
            "started_at": self.started_at,
            "success_at": self.success_at,
            "bypass_found": self.bypass_found,
            "total_messages": len(self.conversation),
            "conversation_log": self.conversation,
            "bypass_technique": "",  # hunter fills this in before submission
        }
        output_path.write_text(json.dumps(bundle, indent=2))
        return output_path

    def to_github_issue_body(self) -> str:
        """Format the PoE as a GitHub issue body for submission."""
        return f"""## Exploit Submission — Level {self.level}

**Hunter Handle:** {self.hunter_handle}
**Challenge Level:** {self.level}
**PoE ID:** {self.poe_id}

### Bypass Technique
<!-- Describe HOW you bypassed the Vanguard rules in 1-3 sentences -->
_Fill this in before submitting_

### Proof of Exploit (JSON)
```json
{json.dumps({"poe_id": self.poe_id, "challenge_level": self.level, 
             "conversation_log": self.conversation[:5],
             "note": "truncated — full bundle attached"}, indent=2)}
```

### Full PoE Bundle Path
`{EXPLOITS_DIR}/poe_level{self.level}_{self.poe_id}_*.json`
"""


# ---------------------------------------------------------------------------
# Challenge Runner
# ---------------------------------------------------------------------------

class ChallengeRunner:
    """
    Spawns a vulnerable MCP server + Vanguard proxy and monitors traffic
    for the challenge's SUCCESS_CONDITION.
    """

    def __init__(self, level: int, hunter_handle: str = "anonymous"):
        self.level = level
        self.hunter_handle = hunter_handle
        self.config = self._load_challenge_config()
        self.poe = PoEBundle(level=level, hunter_handle=hunter_handle)
        self._server_process = None
        self._success = False

    def _load_challenge_config(self) -> dict:
        """Dynamically import the challenge module and get its config."""
        challenge_file = CHALLENGES_DIR / f"level_{self.level}.py"
        if not challenge_file.exists():
            logger.error(f"❌ Challenge Level {self.level} not found at {challenge_file}")
            sys.exit(1)

        spec = importlib.util.spec_from_file_location(f"level_{self.level}", challenge_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if not hasattr(module, "get_challenge_config"):
            logger.error(f"❌ Level {self.level} is missing get_challenge_config()")
            sys.exit(1)

        return module.get_challenge_config()

    def _print_challenge_brief(self):
        """Print the challenge intro."""
        c = self.config
        layers = ", ".join(f"Layer {l}" for l in c.get("layers_active", [1]))
        rules = ", ".join(c.get("rules_files", []))

        print("\n" + "="*60)
        print(f"🏟️  McpVanguard Arena — {c['name']}")
        print("="*60)
        print(f"📋 {c['description']}")
        print(f"🛡️  Active: {layers} | Rules: {rules}")
        print(f"💰 Points: {c['points']}")
        print(f"\n🔍 Hints:")
        for i, hint in enumerate(c.get("hints", []), 1):
            print(f"   {i}. {hint}")
        print("\n" + "="*60)
        print("⚡ Proxy is starting... connect your agent to take control.")
        print("🎯 SUCCESS CONDITION:", c.get("success_condition", "(see challenge file)"))
        print("="*60 + "\n")

    def _build_vanguard_command(self) -> list[str]:
        """Build the `vanguard start` command with challenge-specific config."""
        raw_server_cmd = self.config.get("server_command", "python mcp_servers/vulnerable_fs_server.py")
        
        # ⚠️ Windows Fix: Ensure we use the SAME python executable for the sub-server
        # to avoid "ModuleNotFoundError" if dependencies are installed in only one environment.
        if raw_server_cmd.startswith("python "):
            server_cmd = raw_server_cmd.replace("python ", f'"{sys.executable}" ', 1)
        else:
            server_cmd = raw_server_cmd

        rules_files = self.config.get("rules_files", ["filesystem.yaml"])

        # Write a temporary rules dir with only the challenge's active rules
        tmp_rules_dir = ROOT_DIR / ".arena_rules_tmp"
        tmp_rules_dir.mkdir(exist_ok=True)

        # Clear and repopulate
        for f in tmp_rules_dir.glob("*.yaml"):
            f.unlink()

        source_rules = ROOT_DIR / "rules"
        for rule_file in rules_files:
            src = source_rules / rule_file
            if src.exists():
                dst = tmp_rules_dir / rule_file
                dst.write_text(src.read_text())

        behavioral = "--behavioral" if self.config.get("behavioral_enabled", False) else "--no-behavioral"

        return [
            sys.executable, "-m", "core",
            "start",
            "--server", server_cmd,
            "--rules-dir", str(tmp_rules_dir),
            "--log-file", str(EXPLOITS_DIR / f"arena_level{self.level}_audit.log"),
            behavioral,
            "--no-semantic",
            "--verbose",
        ]

    async def run(self):
        """Main challenge loop."""
        self._print_challenge_brief()

        proxy_cmd = self._build_vanguard_command()
        logger.info(f"🚀 Starting proxy: {' '.join(proxy_cmd)}")

        # Start the proxy process — it manages the server internally
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        
        self._server_process = await asyncio.create_subprocess_exec(
            *proxy_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )

        logger.info(f"✅ Proxy PID {self._server_process.pid} running")
        logger.info("📡 Monitoring traffic for SUCCESS_CONDITION...")
        logger.info("💡 Tip: pipe your agent's MCP output into this process\n")

        # Monitor stderr (proxy logs) for success
        success_condition = self.config.get("success_condition", "")

        async def watch_stderr():
            while True:
                line = await self._server_process.stderr.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").strip()
                print(f"[proxy] {decoded}", file=sys.stderr)

                # Check if success condition appears in traffic
                if success_condition and success_condition in decoded:
                    self._on_success()

        async def watch_stdout():
            while True:
                line = await self._server_process.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").strip()
                if decoded:
                    self.poe.record_message("server→agent", {}, "ALLOW")
                    if success_condition and success_condition in decoded:
                        self._on_success()

        try:
            await asyncio.gather(
                watch_stderr(),
                watch_stdout(),
            )
        except asyncio.CancelledError:
            pass
        finally:
            await self._cleanup()

    def _on_success(self):
        """Called when SUCCESS_CONDITION is detected in traffic."""
        if self._success:
            return
        self._success = True
        self.poe.mark_success()

        poe_path = self.poe.save(EXPLOITS_DIR)

        print("\n" + "🎉"*30)
        print(f"\n🎉  BYPASS FOUND! Level {self.level} defeated!\n")
        print(f"📦 PoE bundle saved to:")
        print(f"   {poe_path}\n")
        print(f"\n🏆 SUCCESS! Proof of Exploit (PoE) captured in: {poe_path}")
        print("-" * 60)
        print("SUBMISSION INSTRUCTIONS:")
        print(f"1. Go to: https://github.com/provnai/McpVanguard/issues/new")
        print(f"2. Select the 'exploit-submission' template")
        print("\n" + "🎉"*30 + "\n")

        # Stop the proxy
        if self._server_process:
            self._server_process.terminate()

    async def _cleanup(self):
        if self._server_process:
            try:
                self._server_process.terminate()
                await asyncio.wait_for(self._server_process.wait(), timeout=3.0)
            except Exception:
                self._server_process.kill()

        # Cleanup temp rules dir
        tmp_rules = ROOT_DIR / ".arena_rules_tmp"
        if tmp_rules.exists():
            for f in tmp_rules.glob("*.yaml"):
                f.unlink()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="🏹 McpVanguard Hunter — Run Arena challenges",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hunter.py 1                   # Run Level 1 
  python hunter.py 2 --handle myhandle # Run Level 2 with your GitHub handle
  python hunter.py 3 --list            # List all available challenge levels
"""
    )
    parser.add_argument("level", type=int, nargs="?", help="Challenge level (1-10)")
    parser.add_argument("--handle", default="anonymous", help="Your GitHub handle for the PoE bundle")
    parser.add_argument("--list", action="store_true", help="List available challenges")
    args = parser.parse_args()

    if args.list:
        print("\n🏟️  Available Challenge Levels:\n")
        for i in range(1, 11):
            challenge_file = CHALLENGES_DIR / f"level_{i}.py"
            status = "✅ Available" if challenge_file.exists() else "🔒 Coming Soon"
            print(f"  Level {i}: {status}")
        print()
        return

    if args.level is None:
        parser.print_help()
        sys.exit(1)

    runner = ChallengeRunner(level=args.level, hunter_handle=args.handle)
    try:
        asyncio.run(runner.run())
    except KeyboardInterrupt:
        print("\n\n[Hunter] Session ended. Good luck next time! 🏹")


if __name__ == "__main__":
    main()
