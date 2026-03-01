"""
core/proxy.py
The McpVanguard transparent stdio proxy.

Sits between an AI agent and a real MCP server subprocess.
Intercepts every JSON-RPC message in both directions,
runs inspection layers, and blocks or forwards accordingly.

Architecture:
    Agent stdin  →  [proxy]  →  Server process stdin
    Server stdout →  [proxy]  →  Agent stdout

Latency target: <10ms overhead on the happy path (Layer 1 only).
"""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

if sys.platform != "win32":
    try:
        if os.getenv("VANGUARD_DISABLE_UVLOOP", "0") == "1" or os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("NIXPACKS"):
            raise ImportError("uvloop disabled by VANGUARD_DISABLE_UVLOOP or environment auto-detect (Railway/Nixpacks)")
        import uvloop
        HAS_UVLOOP = True
    except ImportError:
        HAS_UVLOOP = False
else:
    HAS_UVLOOP = False

from core.models import (
    AuditEvent,
    InspectionResult,
    JsonRpcRequest,
    make_block_response,
)
from core.rules_engine import RulesEngine
from core.session import SessionManager, SessionState
from core import semantic, behavioral
from core.vex_client import submit_blocked_call

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class ProxyConfig:
    """Runtime configuration for the proxy, loaded from env vars."""

    def __init__(self):
        self.log_level: str = os.getenv("VANGUARD_LOG_LEVEL", "INFO")
        self.log_file: str = os.getenv("VANGUARD_LOG_FILE", "audit.log")
        self.rules_dir: str = os.getenv("VANGUARD_RULES_DIR", "rules")
        self.semantic_enabled: bool = os.getenv("VANGUARD_SEMANTIC_ENABLED", "false").lower() == "true"
        self.behavioral_enabled: bool = os.getenv("VANGUARD_BEHAVIORAL_ENABLED", "true").lower() == "true"
        self.block_threshold: float = float(os.getenv("VANGUARD_BLOCK_THRESHOLD", "0.8"))
        self.warn_threshold: float = float(os.getenv("VANGUARD_WARN_THRESHOLD", "0.5"))


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

def setup_audit_logger(log_file: str) -> logging.Logger:
    """Set up a dedicated file logger for the audit trail."""
    audit = logging.getLogger("vanguard.audit")
    audit.setLevel(logging.DEBUG)
    audit.propagate = False

    # File handler (Rotating: 10MB max size, keep 5 backups)
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setFormatter(logging.Formatter("%(message)s"))

    # Console handler (stderr so it doesn't pollute stdout/stdin proxy)
    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(logging.Formatter("%(message)s"))

    audit.addHandler(fh)
    audit.addHandler(ch)
    return audit


# ---------------------------------------------------------------------------
# The Proxy
# ---------------------------------------------------------------------------

class VanguardProxy:
    """
    The core McpVanguard proxy.

    Spawns a real MCP server subprocess and transparently intercepts
    all JSON-RPC traffic between the agent and the server.
    """

    def __init__(
        self,
        server_command: list[str],
        config: Optional[ProxyConfig] = None,
        agent_reader: Optional[asyncio.StreamReader] = None,
        agent_writer: Optional[asyncio.StreamWriter] = None,
    ):
        self.server_command = server_command
        self.config = config or ProxyConfig()
        self.session_manager = SessionManager()
        self.rules_engine = RulesEngine(rules_dir=self.config.rules_dir)
        self.audit = setup_audit_logger(self.config.log_file)
        self._server_process: Optional[asyncio.subprocess.Process] = None
        self._session: Optional[SessionState] = None
        self._stats = {"allowed": 0, "blocked": 0, "warned": 0, "total": 0}

        # Transport Injection
        self.agent_reader = agent_reader
        self.agent_writer = agent_writer

        logger.info(
            f"[Vanguard] Loaded {self.rules_engine.rule_count} rules from '{self.config.rules_dir}'"
        )

    # -----------------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------------

    async def run(self):
        """
        Start the proxy. Spawns the server subprocess and begins
        bidirectional stdio interception.
        """
        self._session = self.session_manager.create()
        logger.info(f"[Vanguard] Session {self._session.session_id} started")
        logger.info(f"[Vanguard] Launching server: {' '.join(self.server_command)}")

        try:
            self._server_process = await asyncio.create_subprocess_exec(
                *self.server_command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.error(f"[Vanguard] Server command not found: {self.server_command[0]}")
            raise RuntimeError(f"MCP Server command not found: {self.server_command[0]}")

        logger.info(f"[Vanguard] Server PID {self._server_process.pid} — proxy active")

        # Run bidirectional pumps concurrently
        try:
            await asyncio.gather(
                self._pump_agent_to_server(),
                self._pump_server_to_agent(),
                self._pump_server_stderr(),
            )
        except asyncio.CancelledError:
            pass
        finally:
            await self._shutdown()

    # -----------------------------------------------------------------------
    # Agent → Server pump (inspection happens here)
    # -----------------------------------------------------------------------

    async def _pump_agent_to_server(self):
        """
        Read JSON-RPC messages from agent, inspect them, then forward or block.
        """
        loop = asyncio.get_event_loop()

        while True:
            try:
                if self.agent_reader:
                    # Generic reader (e.g. SSE)
                    line = await self.agent_reader.readline()
                else:
                    # Default: Stdio with EPERM fix
                    line = await loop.run_in_executor(None, sys.stdin.buffer.readline)
            except Exception as e:
                logger.error(f"[Vanguard] Error reading from agent: {e}")
                break

            if not line:
                break

            line = line.strip()
            if not line:
                continue

            t_start = time.monotonic()

            # Parse the JSON-RPC message
            try:
                raw_message = json.loads(line)
            except json.JSONDecodeError:
                logger.warning(f"[Vanguard] Invalid JSON from agent: {line[:100]}")
                continue

            # Inspect the message
            result = await self._inspect_message(raw_message)
            latency_ms = (time.monotonic() - t_start) * 1000

            # Parse for logging metadata
            method = raw_message.get("method", "")
            request_id = raw_message.get("id")
            tool_name = None
            if method == "tools/call":
                tool_name = raw_message.get("params", {}).get("name")

            # Record into session state
            self._session.record_call(
                tool_name=tool_name or method,
                method=method,
                params=raw_message.get("params", {}),
                action=result.action,
            )
            self._stats["total"] += 1

            # Build and write audit event
            event = AuditEvent(
                session_id=self._session.session_id,
                direction="agent→server",
                method=method,
                tool_name=tool_name,
                action=result.action,
                layer_triggered=result.layer_triggered,
                rule_id=result.rule_matches[0].rule_id if result.rule_matches else None,
                semantic_score=result.semantic_score,
                latency_ms=round(latency_ms, 2),
                blocked_reason=result.block_reason,
            )
            self.audit.info(event.to_log_line())

            if result.allowed:
                # Forward to server
                self._stats["allowed"] += 1
                if result.action == "WARN":
                    self._stats["warned"] += 1
                await self._write_to_server(line)
            else:
                # Block — send error response back to agent
                self._stats["blocked"] += 1
                rule_id = result.rule_matches[0].rule_id if result.rule_matches else "VANGUARD"

                # 🛡️ The VEX Flight Recorder Handoff
                # Transmit the blocked tool call to the VEX Rust Server asynchronously.
                # VEX will hash it, hit the CHORA Gate, and anchor the signature.
                submit_blocked_call(raw_message, session_id=self._session.session_id)

                block_response = make_block_response(
                    request_id=request_id,
                    reason=result.block_reason or "Security policy violation",
                    rule_id=rule_id,
                )
                await self._write_to_agent(json.dumps(block_response))

    # -----------------------------------------------------------------------
    # Server → Agent pump (response filtering)
    # -----------------------------------------------------------------------

    async def _pump_server_to_agent(self):
        """
        Read responses from the server and forward to the agent.
        (Response filtering can be added here in future layers.)
        """
        while True:
            try:
                line = await self._server_process.stdout.readline()
            except Exception:
                break

            if not line:
                break

            # Layer 3: Response inspection (large payloads)
            if self.config.behavioral_enabled:
                try:
                    line_str = line.decode("utf-8", errors="replace")
                    resp_result = await behavioral.inspect_response(
                        self._session.session_id, line_str
                    )
                    if resp_result and not resp_result.allowed:
                        logger.warning(f"[Vanguard] Blocking large response: {resp_result.block_reason}")
                        # for now just skip forwarding. 
                        # future: send back legitimate error to agent
                        continue
                except Exception as e:
                    logger.error(f"[Vanguard] Error in response inspection: {e}")

            # Forward response to agent
            await self._write_to_agent(line.decode("utf-8", errors="replace"))

    async def _pump_server_stderr(self):
        """Forward server's stderr to our stderr (for debugging)."""
        while True:
            try:
                line = await self._server_process.stderr.readline()
            except Exception:
                break
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    # -----------------------------------------------------------------------
    # Inspection pipeline
    # -----------------------------------------------------------------------

    async def _inspect_message(self, message: dict) -> InspectionResult:
        """
        Run a message through all enabled inspection layers.
        Returns the first BLOCK result or ALLOW if all layers pass.
        """
        # Layer 1: Static rules
        result = self.rules_engine.check(message)
        if not result.allowed:
            return result

        # Layer 3: Behavioral analysis (if enabled)
        if self.config.behavioral_enabled and self._session:
            beh_result = await behavioral.inspect_request(
                self._session.session_id, message
            )
            if beh_result:
                if not beh_result.allowed:
                    return beh_result
                # Accumulate warnings
                if beh_result.action == "WARN":
                    result.action = "WARN"
                    result.rule_matches.extend(beh_result.rule_matches)

        # Layer 2: Semantic scoring (if enabled)
        if self.config.semantic_enabled:
            sem_result = await semantic.score_intent(message)
            if sem_result:
                if not sem_result.allowed:
                    return sem_result
                # Accumulate warnings/score
                result.semantic_score = sem_result.semantic_score
                if sem_result.action == "WARN":
                    result.action = "WARN"
                    result.rule_matches.extend(sem_result.rule_matches)

        return result


    # -----------------------------------------------------------------------
    # I/O helpers
    # -----------------------------------------------------------------------

    async def _write_to_server(self, data: str):
        """Write a line to the server subprocess stdin."""
        if self._server_process and self._server_process.stdin:
            try:
                self._server_process.stdin.write((data + "\n").encode())
                await self._server_process.stdin.drain()
            except Exception as e:
                logger.error(f"[Vanguard] Failed to write to server: {e}")

    async def _write_to_agent(self, data: str):
        """Write a line back to the agent (stdout or network transport)."""
        if not data.endswith("\n"):
            data += "\n"

        try:
            if self.agent_writer:
                # Generic writer
                self.agent_writer.write(data.encode("utf-8"))
                await self.agent_writer.drain()
            else:
                # Default: Stdio
                sys.stdout.buffer.write(data.encode("utf-8"))
                sys.stdout.buffer.flush()
        except Exception as e:
            logger.error(f"[Vanguard] Failed to write to agent: {e}")

    # -----------------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------------

    async def _shutdown(self):
        """Clean up the server process on exit."""
        if self._server_process:
            try:
                # 🛡️ Robust Shutdown: Try termination, then kill if it hangs
                if sys.platform == "win32":
                    # On Windows, terminate() often fails for complex pipe structures
                    self._server_process.kill()
                else:
                    self._server_process.terminate()
                
                try:
                    await asyncio.wait_for(self._server_process.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    self._server_process.kill()
            except Exception as e:
                logger.debug(f"[Vanguard] Shutdown internal error (usually safe to ignore): {e}")

        if self._session:
            s = self._session.summary()
            logger.info(
                f"[Vanguard] Session {s['session_id']} ended — "
                f"{s['total_calls']} calls | {s['blocked']} blocked | {s['warnings']} warnings"
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_proxy(server_command: list[str], config: Optional[ProxyConfig] = None):
    """
    Public entry point. Call this from the CLI.
    Sets up uvloop if available and runs the proxy.
    """
    # 🛡️ Nixpacks/Docker Seccomp Fix:
    # If the container starts with stdin (fd 0) closed, os.pipe() inside
    # asyncio.create_subprocess_exec will allocate fd 0 for the pipe.
    # Some container environments block epoll_ctl unconditionally on fd 0/1/2 
    # via seccomp, causing PermissionError. We secure these slots with /dev/null.
    for fd in (0, 1, 2):
        try:
            os.fstat(fd)
        except OSError:
            os.open(os.devnull, os.O_RDWR)

    if HAS_UVLOOP:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        logger.debug("[Vanguard] Using uvloop event loop")

    proxy = VanguardProxy(server_command=server_command, config=config)

    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        logger.info("[Vanguard] Interrupted — shutting down")
