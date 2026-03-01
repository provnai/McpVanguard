"""
core/behavioral.py — Layer 3: Behavioral Analysis

Detects attack patterns that look benign at the message level but are obvious
in aggregate — data scraping, enumeration, slow-burn exfiltration.

Uses sliding-window counters per (session_id, tool_name) stored in memory.
Events are optionally written to a shared Redis cluster.

Detectors:
    BEH-001  Data scraping:       >50 read_file calls in 10s → BLOCK
    BEH-002  Dir enumeration:     >20 list_dir calls in 5s   → WARN
    BEH-003  Priv esc sequence:   write after sensitive read  → BLOCK
    BEH-004  Large payload:       response body >10KB         → BLOCK (response side)
    BEH-005  Tool flood:          >200 any-tool calls in 60s  → BLOCK
"""

from __future__ import annotations

import collections
import logging
import os
import time
import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Deque, Optional, Any

from core.models import InspectionResult, RuleMatch

logger = logging.getLogger("vanguard.behavioral")

# ─── Config ──────────────────────────────────────────────────────────────────

ENABLED = os.getenv("VANGUARD_BEHAVIORAL_ENABLED", "true").lower() == "true"
MAX_READ_FILE_PER_10S = int(os.getenv("VANGUARD_BEH_READ_LIMIT", "50"))
MAX_LIST_DIR_PER_5S = int(os.getenv("VANGUARD_BEH_LIST_LIMIT", "20"))
MAX_ANY_TOOL_PER_60S = int(os.getenv("VANGUARD_BEH_FLOOD_LIMIT", "200"))
MAX_RESPONSE_BYTES = int(os.getenv("VANGUARD_BEH_PAYLOAD_LIMIT", str(10 * 1024)))

REDIS_URL = os.getenv("VANGUARD_REDIS_URL", "")

try:
    if REDIS_URL:
        import redis
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        _redis_client.ping()
        logger.info(f"Behavioral layer using Redis backend: {REDIS_URL}")
    else:
        _redis_client = None
except Exception as e:
    logger.warning(f"Failed to connect to Redis at {REDIS_URL}. Falling back to memory. Error: {e}")
    _redis_client = None

# Shared executor for making blocking Redis calls without halting the async proxy loop
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vanguard-beh")

# Paths that trigger the write-after-sensitive-read detector
_SENSITIVE_PATH_FRAGMENTS = (
    "/etc/", ".ssh/", ".env", "passwd", "shadow", "id_rsa", "authorized_keys",
)

# ─── Sliding window ───────────────────────────────────────────────────────────

class _RedisWindow:
    def __init__(self, key: str):
        self.key = key

    def record(self) -> None:
        if not _redis_client: return
        now = time.monotonic()
        _redis_client.zadd(self.key, {str(uuid.uuid4()): now})
        _redis_client.expire(self.key, 65)

    def count_in(self, window_secs: float) -> int:
        if not _redis_client: return 0
        now = time.monotonic()
        cutoff = now - window_secs
        _redis_client.zremrangebyscore(self.key, "-inf", cutoff - 0.1)
        return _redis_client.zcard(self.key)

@dataclass
class _Window:
    """A deque-based sliding window of event timestamps."""
    timestamps: Deque[float] = field(default_factory=lambda: collections.deque(maxlen=1000))

    def record(self) -> None:
        self.timestamps.append(time.monotonic())

    def count_in(self, window_secs: float) -> int:
        cutoff = time.monotonic() - window_secs
        # Trim from left
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()
        return len(self.timestamps)

# ─── Per-session state ────────────────────────────────────────────────────────

@dataclass
class BehavioralState:
    """Tracks behavioral counters for a single proxy session."""
    session_id: str
    # Per-tool sliding windows
    _windows: dict[str, Any] = field(default_factory=dict)
    # Paths that have been read (for priv-esc sequence detection)
    sensitive_reads: set[str] = field(default_factory=set)
    # Flag: has any write happened after a sensitive read?
    write_after_sensitive: bool = False
    # Total bytes seen in responses
    total_response_bytes: int = 0

    def window(self, tool: str):
        if tool not in self._windows:
            if _redis_client:
                self._windows[tool] = _RedisWindow(f"vguard:beh:{self.session_id}:win:{tool}")
            else:
                self._windows[tool] = _Window()
        return self._windows[tool]

    def record_call(self, tool_name: str, params: dict) -> None:
        self.window(tool_name).record()
        self.window("*").record()

        # Track sensitive reads for priv-esc detector
        path = (
            params.get("arguments", {}).get("path")
            or params.get("path", "")
            or ""
        )
        if any(frag in path for frag in _SENSITIVE_PATH_FRAGMENTS):
            if _redis_client:
                rkey = f"vguard:beh:{self.session_id}:reads"
                _redis_client.sadd(rkey, path)
                _redis_client.expire(rkey, 3600)
            else:
                self.sensitive_reads.add(path)
            logger.debug("Sensitive path recorded: %s", path)

    def record_write(self, tool_name: str) -> None:
        has_sensitive = False
        if _redis_client:
            rkey = f"vguard:beh:{self.session_id}:reads"
            has_sensitive = _redis_client.scard(rkey) > 0
        else:
            has_sensitive = len(self.sensitive_reads) > 0

        if has_sensitive:
            if _redis_client:
                wkey = f"vguard:beh:{self.session_id}:write_after"
                _redis_client.setex(wkey, 3600, "1")
            else:
                self.write_after_sensitive = True

            logger.warning(
                "Write-after-sensitive-read detected! tool=%s sensitive_reads=%s",
                tool_name,
                self.get_sensitive_reads(),
            )

    def get_sensitive_reads(self) -> set[str]:
        if _redis_client:
            rkey = f"vguard:beh:{self.session_id}:reads"
            return set(_redis_client.smembers(rkey))
        return self.sensitive_reads

    def has_write_after_sensitive(self) -> bool:
        if _redis_client:
            wkey = f"vguard:beh:{self.session_id}:write_after"
            return _redis_client.exists(wkey) > 0
        return self.write_after_sensitive

    def add_response_bytes(self, byte_len: int) -> int:
        if _redis_client:
            bkey = f"vguard:beh:{self.session_id}:bytes"
            val = _redis_client.incrby(bkey, byte_len)
            _redis_client.expire(bkey, 3600)
            return val
        else:
            self.total_response_bytes += byte_len
            return self.total_response_bytes


# ─── Global registry ─────────────────────────────────────────────────────────

_states: dict[str, BehavioralState] = {}


def get_state(session_id: str) -> BehavioralState:
    if session_id not in _states:
        _states[session_id] = BehavioralState(session_id=session_id)
    return _states[session_id]


def clear_state(session_id: str) -> None:
    _states.pop(session_id, None)


# ─── Write detection helpers ──────────────────────────────────────────────────

_WRITE_TOOLS = frozenset({"write_file", "create_file", "append_file", "edit_file",
                           "run_shell", "execute", "bash", "eval"})


def _is_write_tool(tool_name: str) -> bool:
    return tool_name.lower() in _WRITE_TOOLS


# ─── Public inspection API ────────────────────────────────────────────────────

async def inspect_request(session_id: str, message: dict) -> Optional[InspectionResult]:
    """Async wrapper that delegates to _inspect_request_sync using ThreadPoolExecutor."""
    if not ENABLED: return None
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, _inspect_request_sync, session_id, message)


def _inspect_request_sync(
    session_id: str,
    message: dict,
) -> Optional[InspectionResult]:
    """
    Inspect an incoming tool call using behavioral analysis.

    Args:
        session_id: Identifies the proxy session.
        message: Raw JSON-RPC message dict.

    Returns:
        InspectionResult to BLOCK or WARN, or None to pass through.
    """
    if not ENABLED:
        return None

    method = message.get("method", "")
    if method != "tools/call":
        return None

    params = message.get("params", {})
    tool_name = params.get("name", "unknown")
    state = get_state(session_id)

    # Record the call
    state.record_call(tool_name, params)

    # Track writes
    if _is_write_tool(tool_name):
        state.record_write(tool_name)

    # ── BEH-003: Write-after-sensitive-read (privilege escalation sequence) ──
    if state.has_write_after_sensitive():
        return InspectionResult(
            allowed=False,
            action="BLOCK",
            layer_triggered=3,
            rule_matches=[RuleMatch(
                rule_id="BEH-003",
                description=f"Write after reading sensitive path(s): {state.get_sensitive_reads()}",
                severity="CRITICAL",
            )],
            block_reason="Privilege escalation sequence: write following sensitive file read",
        )

    # ── BEH-001: Data scraping detector ──
    read_count = state.window("read_file").count_in(10.0)
    if read_count > MAX_READ_FILE_PER_10S:
        return InspectionResult(
            allowed=False,
            action="BLOCK",
            layer_triggered=3,
            rule_matches=[RuleMatch(
                rule_id="BEH-001",
                description=f"read_file called {read_count}× in 10s (limit {MAX_READ_FILE_PER_10S})",
                severity="HIGH",
            )],
            block_reason=f"Data scraping: {read_count} read_file calls in 10s",
        )

    # ── BEH-002: Directory enumeration detector ──
    list_count = state.window("list_directory").count_in(5.0)
    if list_count > MAX_LIST_DIR_PER_5S:
        return InspectionResult(
            allowed=True,  # Warn, don't block
            action="WARN",
            layer_triggered=3,
            rule_matches=[RuleMatch(
                rule_id="BEH-002",
                description=f"list_directory called {list_count}× in 5s (limit {MAX_LIST_DIR_PER_5S})",
                severity="MEDIUM",
            )],
        )

    # ── BEH-005: Tool flood detector ──
    total_count = state.window("*").count_in(60.0)
    if total_count > MAX_ANY_TOOL_PER_60S:
        return InspectionResult(
            allowed=False,
            action="BLOCK",
            layer_triggered=3,
            rule_matches=[RuleMatch(
                rule_id="BEH-005",
                description=f"Tool flood: {total_count} calls in 60s (limit {MAX_ANY_TOOL_PER_60S})",
                severity="HIGH",
            )],
            block_reason=f"Automated tool flood: {total_count} calls in 60s",
        )

    return None


async def inspect_response(session_id: str, response_body: str) -> Optional[InspectionResult]:
    """Async wrapper that delegates to _inspect_response_sync using ThreadPoolExecutor."""
    if not ENABLED: return None
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, _inspect_response_sync, session_id, response_body)


def _inspect_response_sync(
    session_id: str,
    response_body: str,
) -> Optional[InspectionResult]:
    """
    Inspect a server response for large payload exfiltration attempts.

    Args:
        session_id: Identifies the proxy session.
        response_body: Raw response string (JSON).

    Returns:
        InspectionResult to BLOCK, or None to pass through.
    """
    if not ENABLED:
        return None

    byte_len = len(response_body.encode("utf-8"))
    state = get_state(session_id)
    total_bytes = state.add_response_bytes(byte_len)

    if total_bytes > MAX_RESPONSE_BYTES:
        return InspectionResult(
            allowed=False,
            action="BLOCK",
            layer_triggered=3,
            rule_matches=[RuleMatch(
                rule_id="BEH-004",
                description=f"Large response: {byte_len} bytes (limit {MAX_RESPONSE_BYTES})",
                severity="HIGH",
            )],
            block_reason=f"Large payload blocked: {byte_len:,} bytes exceeds {MAX_RESPONSE_BYTES:,} byte limit",
        )

    return None
