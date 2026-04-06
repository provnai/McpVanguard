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
from core import management

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
        self.management_tools_enabled: bool = os.getenv("VANGUARD_MANAGEMENT_TOOLS_ENABLED", "false").lower() == "true"
        self.block_threshold: float = float(os.getenv("VANGUARD_BLOCK_THRESHOLD", "0.8"))
        self.warn_threshold: float = float(os.getenv("VANGUARD_WARN_THRESHOLD", "0.5"))
        # Mode: "enforce" (default) or "audit" (log but don't block)
        self.mode: str = os.getenv("VANGUARD_MODE", "enforce").lower()
        # SSE auth key — also read by sse_server.py directly for early validation
        self.api_key: str = os.getenv("VANGUARD_API_KEY", "")
        # Off by default in production to avoid leaking rule internals.
        self.expose_block_reason: bool = os.getenv("VANGUARD_EXPOSE_BLOCK_REASON", "false").lower() == "true"
        # Maximum string length allowed in incoming tool calls (prevents memory exhaustion)
        self.max_string_len: int = int(os.getenv("VANGUARD_MAX_STRING_LEN", "65536")) # 64KB default
        # Audit format: "text" (human-readable) or "json" (SIEM ingest)
        self.audit_format: str = os.getenv("VANGUARD_AUDIT_FORMAT", "text").lower()


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

def setup_audit_logger(log_file: str) -> logging.Logger:
    """Set up a dedicated file logger for the audit trail."""
    audit = logging.getLogger("vanguard.audit")
    audit.setLevel(logging.INFO)
    audit.propagate = False
    desired_path = os.path.abspath(log_file)

    existing_file = False
    existing_stderr = False
    for handler in list(audit.handlers):
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            if os.path.abspath(handler.baseFilename) == desired_path:
                existing_file = True
            else:
                audit.removeHandler(handler)
                handler.close()
        elif isinstance(handler, logging.StreamHandler) and getattr(handler, "stream", None) is sys.stderr:
            existing_stderr = True

    if not existing_file:
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        fh.setFormatter(logging.Formatter("%(message)s"))
        audit.addHandler(fh)

    if not existing_stderr:
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(logging.Formatter("%(message)s"))
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
        self._pending_tool_lists: set[Any] = set()

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

            # 1. Handle native Vanguard tools
            if method == "tools/call" and tool_name and tool_name.startswith("vanguard_"):
                self._stats["total"] += 1
                if self._session:
                    self._session.record_call(
                        tool_name=tool_name,
                        method=method,
                        params=raw_message.get("params", {}),
                        action="ALLOW" if self.config.management_tools_enabled else "BLOCK",
                    )

                if not self.config.management_tools_enabled:
                    telemetry.metrics.record_status("blocked")
                    self._stats["blocked"] += 1
                    self.audit.info(
                        AuditEvent(
                            session_id=self._session.session_id if self._session else "N/A",
                            direction="agent→server",
                            method=method,
                            tool_name=tool_name,
                            action="BLOCK",
                            rule_id="VANGUARD-MGMT-DISABLED",
                            blocked_reason="Management tools are disabled on this McpVanguard instance.",
                        ).to_log_line(format=self.config.audit_format)
                    )
                    block_response = make_block_response(
                        request_id=request_id,
                        reason="Management tools are disabled on this McpVanguard instance.",
                        rule_id="VANGUARD-MGMT-DISABLED",
                    )
                    await self._write_to_agent(json.dumps(block_response))
                    continue

                telemetry.metrics.record_status("allowed")
                self._stats["allowed"] += 1
                self.audit.info(
                    AuditEvent(
                        session_id=self._session.session_id if self._session else "N/A",
                        direction="agent→server",
                        method=method,
                        tool_name=tool_name,
                        action="ALLOW",
                    ).to_log_line(format=self.config.audit_format)
                )
                args = raw_message.get("params", {}).get("arguments", {})
                vanguard_result = await management.handle_vanguard_tool(
                    tool_name,
                    args,
                    context=management.ManagementContext(
                        session_id=self._session.session_id if self._session else None,
                        log_file=self.config.log_file,
                        rules_engine=self.rules_engine,
                    ),
                )
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": vanguard_result
                }
                await self._write_to_agent(json.dumps(response))
                continue

            # 2. Track tool listing requests for enrichment
            if method == "tools/list" and request_id:
                self._pending_tool_lists.add(request_id)

            # Normalize the message before inspection to prevent encoding bypasses
            try:
                normalized_message = self._normalize_message(raw_message)
            except ValueError as e:
                # MED-2 Fix: Reject oversized messages instead of truncating and allowing bypass
                logger.warning(f"[Vanguard] REJECTED: Message contains oversized field: {e}")
                block_response = make_block_response(
                    request_id=request_id,
                    reason=f"Security Policy: Message contains a field exceeding the {self.config.max_string_len} byte limit.",
                    rule_id="VANGUARD-SIZE-001",
                )
                await self._write_to_agent(json.dumps(block_response))
                continue

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
            is_audit = (self.config.mode == "audit")
            effective_action = result.action
            if not result.allowed and is_audit:
                effective_action = "SHADOW-BLOCK"

            event = AuditEvent(
                session_id=self._session.session_id if self._session else "N/A",
                direction="agent→server",
                method=method,
                tool_name=tool_name,
                action=effective_action,
                layer_triggered=result.layer_triggered,
                rule_id=result.rule_matches[0].rule_id if result.rule_matches else None,
                semantic_score=result.semantic_score,
                latency_ms=round(latency_ms, 2),
                blocked_reason=result.block_reason,
            )
            self.audit.info(event.to_log_line(format=self.config.audit_format))

            is_audit = (self.config.mode == "audit")

            if result.allowed or is_audit:
                if not result.allowed:
                    logger.info(f"[Vanguard] [SHADOW-BLOCK] Audit mode allowing violation: {tool_name or method}")
                    self._stats["shadow_blocked"] = self._stats.get("shadow_blocked", 0) + 1

                self._stats["allowed"] += 1
                telemetry.metrics.record_status("allowed")
                if result.action == "WARN":
                    self._stats["warned"] += 1
                    telemetry.metrics.record_status("warned")
                # Forward the normalized message to ensure inspection/execution symmetry
                # This prevents truncation-based bypasses (P2 Audit Finding)
                forward_data = json.dumps(normalized_message)
                await self._write_to_server(forward_data)
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

            throttle_delay = 0.0
            if self.config.behavioral_enabled and self._session:
                try:
                    line_str = line.decode("utf-8", errors="replace")
                    resp_result = await behavioral.inspect_response(
                        self._session.session_id, line_str
                    )
                    
                    if resp_result and not resp_result.allowed:
                        logger.warning(f"[Vanguard] Blocking large response: {resp_result.block_reason}")
                        request_id = None
                        try:
                            request_id = json.loads(line_str).get("id")
                        except json.JSONDecodeError:
                            pass

                        if self.config.expose_block_reason:
                            agent_reason = resp_result.block_reason or "Response blocked by security policy."
                        else:
                            agent_reason = "Response blocked by McpVanguard security policy."

                        rule_id = resp_result.rule_matches[0].rule_id if resp_result.rule_matches else "VANGUARD-RESP"
                        block_response = make_block_response(
                            request_id=request_id,
                            reason=agent_reason,
                            rule_id=rule_id,
                        )
                        self._stats["blocked"] += 1
                        telemetry.metrics.record_status("blocked")
                        await self._write_to_agent(json.dumps(block_response))
                        continue
                        
                    # Requirement 3.1: Apply 1 byte/sec throttle if governor is empty
                    state = behavioral.get_state(self._session.session_id)
                    
                    # Periodic check: can we clear the throttle? (P2 Audit Finding)
                    state.update_throttle_status()

                    if state.is_throttled:
                        # Preserve JSON-RPC framing by delaying the full frame instead
                        # of fragmenting one message into multiple newline-delimited chunks.
                        total_len = len(line)
                        throttle_delay = max(0.0, (total_len - 1024) / 1024.0)
                except Exception as e:
                    logger.error(f"[Vanguard] Error in behavioral response inspection: {e}")

            # 3. Enrich tool listing responses with safety hints
            try:
                line_str = line.decode("utf-8", errors="replace")
                resp_json = json.loads(line_str)
                resp_id = resp_json.get("id")
                if resp_id in self._pending_tool_lists:
                    self._pending_tool_lists.remove(resp_id)
                    if "result" in resp_json and "tools" in resp_json["result"]:
                        enriched_tools = self._enrich_tool_list(resp_json["result"]["tools"])
                        resp_json["result"]["tools"] = enriched_tools
                        line = json.dumps(resp_json).encode("utf-8")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

            if throttle_delay > 0:
                await asyncio.sleep(throttle_delay)

            await self._write_to_agent(line)

    def _enrich_tool_list(self, tools: list[dict]) -> list[dict]:
        """Inject Vanguard management tools and apply safety hints/titles."""
        all_tools = list(tools)
        if self.config.management_tools_enabled:
            all_tools.extend(management.get_vanguard_tools())
        
        # Keywords for inference
        READ_PREFIXES = ("get_", "list_", "read_", "check_", "fetch_", "search_", "inspect_", "query_", "audit_")
        WRITE_PREFIXES = ("delete_", "remove_", "update_", "set_", "write_", "enforce_", "block_", "reset_", "clear_", "apply_", "push_", "exec_", "shell_")

        for t in all_tools:
            name = t.get("name", "")
            
            # Inject Title if missing
            if "title" not in t:
                t["title"] = name.replace("_", " ").title()

            # Inject Safety Hints
            if "readOnlyHint" not in t and "destructiveHint" not in t:
                if any(name.startswith(p) for p in READ_PREFIXES) or "status" in name:
                    t["readOnlyHint"] = True
                elif any(name.startswith(p) for p in WRITE_PREFIXES):
                    t["destructiveHint"] = True
                else:
                    # Default: label as conservative if ambiguous but mostly tool-like
                    t["readOnlyHint"] = True
            
        return all_tools

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
            sem_result = await semantic.score_intent(message, enabled=self.config.semantic_enabled)
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
            # MED-2 Fix: Raise error on oversize instead of truncating to prevent bypass
            if len(value) > self.config.max_string_len:
                raise ValueError(f"String length {len(value)} exceeds limit {self.config.max_string_len}")
            
            return value
        return message

    # -----------------------------------------------------------------------
    # I/O helpers
    # -----------------------------------------------------------------------

    async def _write_to_server(self, data: str | bytes):
        if not self._server_process or not self._server_process.stdin:
            return
        try:
            # Removed .strip() to prevent unintended payload mutation (P3 Audit Finding)
            if isinstance(data, str):
                buf = (data if data.endswith("\n") else data + "\n").encode()
            else:
                buf = data if data.endswith(b"\n") else data + b"\n"
            
            self._server_process.stdin.write(buf)
            await self._server_process.stdin.drain()
        except Exception as e:
            # MED-1 Fix: Log swallowed errors
            logger.error(f"[Vanguard] Error writing to server: {e}")

    async def _write_to_agent(self, data: str | bytes):
        try:
            # Preserve original whitespace for agent transport
            if isinstance(data, str):
                buf = (data if data.endswith("\n") else data + "\n").encode("utf-8")
            else:
                buf = data if data.endswith(b"\n") else data + b"\n"

            if self.agent_writer:
                self.agent_writer.write(buf)
                await self.agent_writer.drain()
            else:
                sys.stdout.buffer.write(buf)
                sys.stdout.buffer.flush()
        except Exception as e:
            # MED-1 Fix: Log swallowed errors
            logger.error(f"[Vanguard] Error writing to agent: {e}")

    # -----------------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------------

    async def _shutdown(self):
        if self._server_process:
            try:
                if self._server_process.stdin:
                    try:
                        self._server_process.stdin.close()
                        await asyncio.wait_for(self._server_process.stdin.wait_closed(), timeout=0.5)
                    except Exception:
                        pass

                if self._server_process.returncode is None:
                    if sys.platform == "win32":
                        self._server_process.kill()
                    else:
                        self._server_process.terminate()
                    await asyncio.wait_for(self._server_process.wait(), timeout=2.0)

                transport = getattr(self._server_process, "_transport", None)
                if transport is not None:
                    transport.close()
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
