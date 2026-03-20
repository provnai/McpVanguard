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
import math
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
VANGUARD_STRICT_REDIS = os.getenv("VANGUARD_STRICT_REDIS", "false").lower() == "true"
VANGUARD_BLOCK_ENUMERATION = os.getenv("VANGUARD_BLOCK_ENUMERATION", "false").lower() == "true"

# --- Task 3: Entropy Throttling config ---
ENTROPY_SCAN_BYTES = 8192          # Scan first 8KB only (performance limit)
ENTROPY_HIGH_THRESHOLD = float(os.getenv("VANGUARD_ENTROPY_HIGH", "6.0"))   # H > 6.0 = likely secret
ENTROPY_BLOCK_THRESHOLD = float(os.getenv("VANGUARD_ENTROPY_BLOCK", "7.5")) # H > 7.5 = almost certainly encrypted/key
ENTROPY_PENALTY_MULTIPLIER = float(os.getenv("VANGUARD_ENTROPY_PENALTY", "10.0"))  # virtual read cost multiplier

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
_SENSITIVE_PATH_FRAGMENTS = tuple(
    os.getenv("VANGUARD_SENSITIVE_PATHS", 
              "/etc/,.ssh/,.env,passwd,shadow,id_rsa,authorized_keys,"
              "System32/config/SAM,Microsoft/Credentials,NTDS.DIT").split(",")
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
class _TokenBucket:
    """Requirement 3.1: Entropy-aware Token Bucket governor."""
    capacity: float = 100.0
    tokens: float = 100.0
    last_update: float = field(default_factory=time.monotonic)
    refill_rate: float = 10.0  # tokens per second

    def consume(self, amount: float) -> bool:
        now = time.monotonic()
        delta = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_rate)
        self.last_update = now
        
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

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
    # Requirement 3.1: Entropy Governor
    entropy_bucket: _TokenBucket = field(default_factory=_TokenBucket)
    is_throttled: bool = False

    def update_throttle_status(self) -> bool:
        """
        Requirement 3.1: Check if the throttle should be cleared.
        Clears if bucket has refilled to >50% capacity (P2 Audit Finding).
        """
        if not self.is_throttled:
            return False
            
        # Trigger refill logic implicitly by calling tokens property/consumption
        # if tokens > 50% capacity, clear throttle
        now = time.monotonic()
        delta = now - self.entropy_bucket.last_update
        current_tokens = min(self.entropy_bucket.capacity, self.entropy_bucket.tokens + delta * self.entropy_bucket.refill_rate)
        
        if current_tokens > (self.entropy_bucket.capacity * 0.5):
            self.is_throttled = False
            logger.info("Entropy bucket refilled (>50%). Clearing session throttle for %s", self.session_id)
            return True
        return False

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
        if path:
            # Normalize to forward-slashes for consistent fragment matching
            path = path.replace("\\", "/")
            if any(frag.lower() in path.lower() for frag in _SENSITIVE_PATH_FRAGMENTS):
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


def clear_all_states() -> None:
    """Clear all session states for testing/isolation."""
    _states.clear()
    if _redis_client:
        try:
            # Dangerous in production, but we don't use it there for 'clear'
            # In tests, we use a dedicated Redis DB if possible
            keys = _redis_client.keys("vguard:beh:*")
            if keys:
                _redis_client.delete(*keys)
        except Exception:
            pass


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
        # print(f"[VANGUARD-DEBUG] behavioral Layer is DISABLED (ENABLED={ENABLED})")
        return None

    # Fail-closed if STRICT_REDIS is enabled but client failed to connect
    if VANGUARD_STRICT_REDIS and REDIS_URL and _redis_client is None:
        return InspectionResult.block(
            reason="High-security mode active: State synchronization (Redis) unavailable.",
            layer=3,
        )

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
            block_reason=f"Privilege escalation sequence: write following sensitive file read ({state.get_sensitive_reads()})",
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
            allowed=not VANGUARD_BLOCK_ENUMERATION,
            action="BLOCK" if VANGUARD_BLOCK_ENUMERATION else "WARN",
            layer_triggered=3,
            rule_matches=[RuleMatch(
                rule_id="BEH-002",
                description=f"list_directory called {list_count}× in 5s (limit {MAX_LIST_DIR_PER_5S})",
                severity="HIGH" if VANGUARD_BLOCK_ENUMERATION else "MEDIUM",
            )],
            block_reason=f"Directory enumeration detected: {list_count} calls in 5s" if VANGUARD_BLOCK_ENUMERATION else None,
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


# ─── Task 3: Shannon Entropy Scouter ─────────────────────────────────────────

def compute_shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon Entropy H(X) for a byte buffer.
    Samples up to ENTROPY_SCAN_BYTES (8KB) for performance.

    H(X) = -Σ p(x_i) * log2(p(x_i))

    Interpretation:
        H < 4.0  → plain text, logs, source code   (very low risk)
        H 4–6.0  → mixed content, structured data   (moderate)
        H > 6.0  → likely encrypted / compressed    (HIGH risk — potential secret)
        H > 7.5  → almost certainly binary / key    (BLOCK)
    Max theoretical = 8.0 (perfectly random byte distribution).
    """
    sample = data[:ENTROPY_SCAN_BYTES]
    if not sample:
        return 0.0

    freq = [0] * 256
    for byte in sample:
        freq[byte] += 1

    length = len(sample)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def entropy_risk_label(h: float) -> str:
    """Human-readable label for the entropy score."""
    if h >= ENTROPY_BLOCK_THRESHOLD:
        return "CRITICAL (encrypted/key material)"
    if h >= ENTROPY_HIGH_THRESHOLD:
        return "HIGH (likely binary or compressed)"
    return "LOW (plaintext)"


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
    Inspect a server response for large payload and high-entropy exfiltration attempts.
    Requirement 3.1: Throttles high-entropy output to 1 byte/sec if bucket empties.
    """
    if not ENABLED:
        return None

    byte_data = response_body.encode("utf-8")
    byte_len = len(byte_data)
    state = get_state(session_id)

    # ── Task 3: Entropy check (BEH-006) ──
    h = compute_shannon_entropy(byte_data)
    
    # Check if we should block immediately (critical keys)
    if h >= ENTROPY_BLOCK_THRESHOLD:
        logger.warning("High-entropy response blocked: H=%.4f session=%s", h, session_id)
        return InspectionResult.block(
            reason=f"Exfiltration Block: H={h:.4f} (Cryptographic Material Detected)",
            layer=3,
            rule_matches=[RuleMatch(rule_id="BEH-006", severity="CRITICAL")]
        )

    # Apply Token Bucket consumption
    cost = 1.0
    if h >= ENTROPY_HIGH_THRESHOLD:
        cost = ENTROPY_PENALTY_MULTIPLIER # 10x drain as per spec
    
    if not state.entropy_bucket.consume(cost):
        # Bucket empty: Apply 1 byte/sec throttle as per spec
        logger.warning("Entropy bucket EMPTY. Throttling session %s to 1 byte/sec.", session_id)
        state.is_throttled = True
        return InspectionResult(
            allowed=True,
            action="WARN",
            layer_triggered=3,
            rule_matches=[RuleMatch(
                rule_id="BEH-007",
                description="Entropy bucket exhausted. Throttling active (1 byte/sec).",
                severity="HIGH",
            )],
            block_reason="Automatic throttling engaged due to high-entropy extraction pattern.",
        )

    # ── BEH-004: Large payload ──
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

async def check_redis_health() -> bool:
    """Returns True if Redis is reachable (or not configured)."""
    if not REDIS_URL or not _redis_client:
        return True
    
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(_executor, _redis_client.ping)
        return True
    except Exception:
        return False
