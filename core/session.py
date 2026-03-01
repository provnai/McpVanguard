"""
core/session.py
Session state machine — tracks multi-turn context per session ID.
Detects patterns that only become dangerous across multiple turns.
"""

from __future__ import annotations
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ToolCallRecord:
    """A single tool call record within a session."""
    timestamp: float
    tool_name: str
    method: str
    params: dict
    action: str  # ALLOW | BLOCK | WARN
    session_id: str


@dataclass
class SessionState:
    """
    Tracks the full state of one proxy session.
    A session is one continuous agent ↔ server connection.
    """
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    started_at: float = field(default_factory=time.time)
    call_history: deque = field(default_factory=lambda: deque(maxlen=500))
    blocked_count: int = 0
    warn_count: int = 0
    total_calls: int = 0
    is_terminated: bool = False
    termination_reason: Optional[str] = None

    # --- Per-tool call counters (for behavioral analysis) ---
    tool_call_counts: dict = field(default_factory=lambda: defaultdict(int))

    # Sliding windows: {tool_name: deque of timestamps}
    tool_call_windows: dict = field(default_factory=lambda: defaultdict(lambda: deque(maxlen=200)))

    # Track what paths have been read (for privilege escalation detection)
    read_paths: list = field(default_factory=list)

    def record_call(self, tool_name: str, method: str, params: dict, action: str):
        """Record a tool call into this session's history."""
        now = time.time()
        record = ToolCallRecord(
            timestamp=now,
            tool_name=tool_name,
            method=method,
            params=params,
            action=action,
            session_id=self.session_id,
        )
        self.call_history.append(record)
        self.total_calls += 1

        if tool_name:
            self.tool_call_counts[tool_name] += 1
            self.tool_call_windows[tool_name].append(now)

        if action == "BLOCK":
            self.blocked_count += 1
        elif action == "WARN":
            self.warn_count += 1

        # Track read paths for privilege escalation detection
        if tool_name in ("read_file", "get_file") and params:
            path = params.get("path") or params.get("arguments", {}).get("path")
            if path:
                self.read_paths.append(path)

    def calls_in_window(self, tool_name: str, window_seconds: float) -> int:
        """Count how many calls to a tool happened in the last N seconds."""
        now = time.time()
        cutoff = now - window_seconds
        window = self.tool_call_windows.get(tool_name, deque())
        return sum(1 for ts in window if ts >= cutoff)

    def terminate(self, reason: str):
        """Mark this session as terminated (agent will receive no more responses)."""
        self.is_terminated = True
        self.termination_reason = reason

    @property
    def age_seconds(self) -> float:
        return time.time() - self.started_at

    def summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "age_seconds": round(self.age_seconds, 1),
            "total_calls": self.total_calls,
            "blocked": self.blocked_count,
            "warnings": self.warn_count,
            "terminated": self.is_terminated,
        }


class SessionManager:
    """
    Manages all active proxy sessions.
    One session per agent connection.
    """

    def __init__(self, max_sessions: int = 1000):
        self._sessions: dict[str, SessionState] = {}
        self._max_sessions = max_sessions

    def create(self) -> SessionState:
        """Create and register a new session."""
        session = SessionState()
        self._sessions[session.session_id] = session
        # Evict oldest if at capacity
        if len(self._sessions) > self._max_sessions:
            oldest_id = next(iter(self._sessions))
            del self._sessions[oldest_id]
        return session

    def get(self, session_id: str) -> Optional[SessionState]:
        return self._sessions.get(session_id)

    def remove(self, session_id: str):
        self._sessions.pop(session_id, None)

    def active_count(self) -> int:
        return len(self._sessions)
