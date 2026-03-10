"""
core/proxy.py
The McpVanguard transparent stdio proxy.

Sits between an AI agent and a real MCP server subprocess.
Intercepts every JSON-RPC message in both directions,
runs inspection layers, and blocks or forwards accordingly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import sys
import time
import unicodedata
import urllib.parse
from typing import Optional, Any

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
    make_block_response,
)
from core.rules_engine import RulesEngine
from core.session import SessionManager, SessionState
from core import semantic, behavioral, telemetry
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
        # SSE auth key — also read by sse_server.py directly for early validation
        self.api_key: str = os.getenv("VANGUARD_API_KEY", "")
        # Off by default in production to avoid leaking rule internals.
        self.expose_block_reason: bool = os.getenv("VANGUARD_EXPOSE_BLOCK_REASON", "false").lower() == "true"
        # Maximum string length allowed in incoming tool calls (prevents memory exhaustion)
        self.max_string_len: int = int(os.getenv("VANGUARD_MAX_STRING_LEN", "65536")) # 64KB default


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

def setup_audit_logger(log_file: str) -> logging.Logger:
    """Set up a dedicated file logger for the audit trail."""
    audit = logging.getLogger("vanguard.audit")
    audit.setLevel(logging.INFO)
    audit.propagate = False

    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setFormatter(logging.Formatter("%(message)s"))

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

        self.agent_reader = agent_reader
        self.agent_writer = agent_writer

        logger.info(
            f"[Vanguard] Loaded {self.rules_engine.rule_count} rules from '{self.config.rules_dir}'"
        )

    # -----------------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------------

    async def run(self):
        """Start the proxy."""
        self._session = self.session_manager.create()
        logger.info(f"[Vanguard] Session {self._session.session_id} started")

        try:
            self._server_process = await asyncio.create_subprocess_exec(
                *self.server_command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as e:
            logger.error(f"[Vanguard] Failed to launch server: {e}")
            raise RuntimeError(f"MCP Server command failed: {e}")

        logger.info(f"[Vanguard] Server PID {self._server_process.pid} proxy active")

        try:
            # Run all pumps until the first one completes (usually agent_to_server closing)
            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(self._pump_agent_to_server()),
                    asyncio.create_task(self._pump_server_to_agent()),
                    asyncio.create_task(self._pump_server_stderr()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )
            # Cancel the remaining pumps
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        except Exception as e:
            logger.error(f"[Vanguard] Unexpected error in proxy loop: {e}")
        finally:
            await self._shutdown()

    # -----------------------------------------------------------------------
    # Agent → Server pump
    # -----------------------------------------------------------------------

    async def _pump_agent_to_server(self):
        loop = asyncio.get_event_loop()

        while True:
            try:
                if self.agent_reader:
                    line = await self.agent_reader.readline()
                else:
                    line = await loop.run_in_executor(None, sys.stdin.buffer.readline)
            except Exception:
                break

            if not line:
                break

            if isinstance(line, bytes):
                line = line.decode("utf-8", errors="replace")
            
            line = line.strip()
            if not line:
                continue

            t_start = time.monotonic()

            try:
                raw_message = json.loads(line)
            except json.JSONDecodeError:
                continue

            method = raw_message.get("method", "")
            request_id = raw_message.get("id")
            tool_name = None
            if method == "tools/call":
                tool_name = raw_message.get("params", {}).get("name")

            # Normalize the message before inspection to prevent encoding bypasses
            normalized_message = self._normalize_message(raw_message)

            # Inspect the message (with 5s Fail-Closed timeout)
            try:
                result = await asyncio.wait_for(
                    self._inspect_message(normalized_message), timeout=5.0
                )
            except asyncio.TimeoutError:
                logger.error(f"[Vanguard] Inspection TIMEOUT (Fail-Closed) for {method}")
                result = InspectionResult.block(
                    reason="Security inspection timeout (Fail-Closed policy).",
                    layer=2,
                )
            latency_ms = (time.monotonic() - t_start) * 1000
            telemetry.metrics.record_latency("TOTAL", latency_ms)

            # Record into session state
            self._stats["total"] += 1
            if self._session:
                self._session.record_call(
                    tool_name=tool_name or method,
                    method=method,
                    params=raw_message.get("params", {}),
                    action=result.action,
                )

            # Audit logging
            event = AuditEvent(
                session_id=self._session.session_id if self._session else "no-session",
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
                self._stats["allowed"] += 1
                telemetry.metrics.record_status("allowed")
                if result.action == "WARN":
                    self._stats["warned"] += 1
                    telemetry.metrics.record_status("warned")
                await self._write_to_server(line)
            else:
                self._stats["blocked"] += 1
                telemetry.metrics.record_status("blocked")
                rule_id = result.rule_matches[0].rule_id if result.rule_matches else "VANGUARD"

                if self._session:
                    submit_blocked_call(raw_message, session_id=self._session.session_id)

                # Sanitize response: only expose detail if explicitly opted-in
                if self.config.expose_block_reason:
                    agent_reason = result.block_reason or "Security policy violation"
                else:
                    agent_reason = "Request blocked by McpVanguard security policy."

                block_response = make_block_response(
                    request_id=request_id,
                    reason=agent_reason,
                    rule_id=rule_id,
                )
                logger.info(f"[Vanguard] BLOCKED {method} {tool_name or ''}")
                await self._write_to_agent(json.dumps(block_response))

    # -----------------------------------------------------------------------
    # Server → Agent pump
    # -----------------------------------------------------------------------

    async def _pump_server_to_agent(self):
        while True:
            try:
                line = await self._server_process.stdout.readline()
            except Exception:
                break

            if not line:
                break

            if self.config.behavioral_enabled and self._session:
                try:
                    line_str = line.decode("utf-8", errors="replace")
                    resp_result = await behavioral.inspect_response(
                        self._session.session_id, line_str
                    )
                    if resp_result and not resp_result.allowed:
                        logger.warning(f"[Vanguard] Blocking large response: {resp_result.block_reason}")
                        continue
                except Exception:
                    pass

            await self._write_to_agent(line)

    async def _pump_server_stderr(self):
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
        t_start = time.monotonic()
        result = self.rules_engine.check(message)
        telemetry.metrics.record_latency("L1", (time.monotonic() - t_start) * 1000)

        if not result.allowed:
            return result

        if self.config.behavioral_enabled and self._session:
            t_start = time.monotonic()
            beh_result = await behavioral.inspect_request(
                self._session.session_id, message
            )
            telemetry.metrics.record_latency("L3", (time.monotonic() - t_start) * 1000)
            if beh_result:
                if not beh_result.allowed:
                    return beh_result
                if beh_result.action == "WARN":
                    result.action = "WARN"
                    result.rule_matches.extend(beh_result.rule_matches)

        if self.config.semantic_enabled:
            t_start = time.monotonic()
            sem_result = await semantic.score_intent(message)
            telemetry.metrics.record_latency("L2", (time.monotonic() - t_start) * 1000)
            if sem_result:
                if not sem_result.allowed:
                    return sem_result
                result.semantic_score = sem_result.semantic_score
                if sem_result.action == "WARN":
                    result.action = "WARN"
                    result.rule_matches.extend(sem_result.rule_matches)

        return result

    def _normalize_message(self, message: Any) -> Any:
        """
        Recursively URL-decodes and Unicode-normalizes (NFKC) all string values
        in a message to prevent encoding-based rule bypasses.
        Loops URL decode until the value stabilizes to handle double/triple encoding.
        """
        if isinstance(message, dict):
            return {k: self._normalize_message(v) for k, v in message.items()}
        elif isinstance(message, list):
            return [self._normalize_message(v) for v in message]
        elif isinstance(message, str):
            # 1. Loop URL decode until stable (handles %252F triple encoding etc.)
            value = message
            for _ in range(20):  # max 20 passes prevents deep-nested exfiltration
                decoded = urllib.parse.unquote(value)
                decoded = decoded.replace("%5c", "\\").replace("%5C", "\\")
                if decoded == value:
                    break
                value = decoded
            # 2. Unicode NFKC (Handles lookalikes where possible)
            value = unicodedata.normalize("NFKC", value)
            # 3. Strip zero-width / invisible characters
            value = ''.join(
                ch for ch in value
                if unicodedata.category(ch) not in ('Cf',)
            )
            # 4. Length safeguard (prevents memory/CPU exhaustion)
            if len(value) > self.config.max_string_len:
                logger.warning(f"String exceeds max_string_len ({len(value)} > {self.config.max_string_len}). Truncating.")
                value = value[:self.config.max_string_len] + "...[TRUNCATED]"
            
            return value
        return message

    # -----------------------------------------------------------------------
    # I/O helpers
    # -----------------------------------------------------------------------

    async def _write_to_server(self, data: str | bytes):
        if not self._server_process or not self._server_process.stdin:
            return
        try:
            if isinstance(data, str):
                buf = (data.strip() + "\n").encode()
            else:
                buf = data.strip() + b"\n"
            
            self._server_process.stdin.write(buf)
            await self._server_process.stdin.drain()
        except Exception:
            pass

    async def _write_to_agent(self, data: str | bytes):
        try:
            if isinstance(data, str):
                buf = (data.strip() + "\n").encode("utf-8")
            else:
                buf = data.strip() + b"\n"

            if self.agent_writer:
                self.agent_writer.write(buf)
                await self.agent_writer.drain()
            else:
                sys.stdout.buffer.write(buf)
                sys.stdout.buffer.flush()
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------------

    async def _shutdown(self):
        if self._server_process:
            try:
                if sys.platform == "win32":
                    self._server_process.kill()
                else:
                    self._server_process.terminate()
                await asyncio.wait_for(self._server_process.wait(), timeout=2.0)
            except Exception:
                pass

    async def get_stats(self):
        return self._stats


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_proxy(server_command: list[str], config: Optional[ProxyConfig] = None):
    for fd in (0, 1, 2):
        try:
            os.fstat(fd)
        except OSError:
            os.open(os.devnull, os.O_RDWR)

    if HAS_UVLOOP:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    proxy = VanguardProxy(server_command=server_command, config=config)

    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        pass
