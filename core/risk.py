"""
core/risk.py
Vanguard Risk Engine: Dynamic trust-score modeling and enforcement governors.
Calculates real-time risk scores for sessions based on multi-layer signals.
"""

import enum
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("vanguard.risk")


class EnforcementLevel(enum.IntEnum):
    """Enforcement actions based on trust levels."""
    NONE = 0      # No enforcement beyond baseline policy
    AUDIT = 1     # Increase telemetry detail and audit logging
    DEGRADE = 2   # Forced Layer 2 Semantic inspection and 1 byte/sec throttling
    BLOCK = 3     # Immediate session termination


@dataclass
class SessionRiskState:
    """Tracks the risk profile of a single proxy session."""
    session_id: str
    server_id: str
    score: float = 100.0
    last_event_time: float = field(default_factory=time.monotonic)
    events: List[dict] = field(default_factory=list)
    enforcement: EnforcementLevel = EnforcementLevel.NONE
    tool_call_timestamps: List[float] = field(default_factory=list)
    risky_call_count: int = 0
    blocked_attempt_count: int = 0

    def decay(self, recovery_rate_per_hour: float = 5.0):
        """Recover trust score over time (good behavior)."""
        now = time.monotonic()
        elapsed_hours = (now - self.last_event_time) / 3600.0
        # Ignore sub-millisecond elapsed time so read-after-write callers do not
        # see floating-point drift immediately after recording an event.
        if elapsed_hours > (0.001 / 3600.0):
            recovery = elapsed_hours * recovery_rate_per_hour
            self.score = min(100.0, self.score + recovery)
            self.last_event_time = now


class RiskEngine:
    """
    Singleton engine for tracking and enforcing dynamic security risk.
    """
    _instance: Optional['RiskEngine'] = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(RiskEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._states: Dict[Tuple[str, str], SessionRiskState] = {}
        self._state_lock = threading.Lock()
        
        # Enforcement thresholds
        self.audit_threshold = 80.0
        self.degrade_threshold = 40.0
        self.block_threshold = 10.0
        
        # Event weights (negative impact)
        self.weights = {
            "RULE_WARN": 5.0,
            "RULE_BLOCK": 20.0,
            "SEMANTIC_WARN": 10.0,
            "SEMANTIC_BLOCK": 20.0,
            "ENTROPY_HIGH": 15.0,
            "ENTROPY_CRITICAL": 50.0,
            "BEHAVIORAL_WARN": 10.0,
            "BEHAVIORAL_BLOCK": 30.0,
            "MANAGEMENT_DENIED": 20.0,
            "MANAGEMENT_MUTATION": 5.0,
            "ATTESTATION_DRIFT": 25.0,
            "SBOM_MISMATCH": 15.0
        }
        
        self._initialized = True

    @classmethod
    def get_instance(cls) -> 'RiskEngine':
        if cls._instance is None:
            return cls()
        return cls._instance

    def get_state(self, session_id: str, server_id: str) -> SessionRiskState:
        key = (session_id, server_id)
        with self._state_lock:
            if key not in self._states:
                self._states[key] = SessionRiskState(session_id, server_id)
            state = self._states[key]
            state.decay()
            return state

    def record_event(self, session_id: str, server_id: str, event_type: str, metadata: dict = None):
        """Record a security event and adjust the trust score."""
        state = self.get_state(session_id, server_id)
        impact = self.weights.get(event_type, 0.0)
        
        with self._state_lock:
            state.score = max(0.0, state.score - impact)
            state.last_event_time = time.monotonic()
            state.events.append({
                "ts": time.time(),
                "type": event_type,
                "impact": impact,
                "metadata": metadata or {}
            })
            # Keep history manageable
            if len(state.events) > 50:
                state.events.pop(0)

            # Recalculate enforcement level
            old_level = state.enforcement
            if state.score <= self.block_threshold:
                state.enforcement = EnforcementLevel.BLOCK
            elif state.score <= self.degrade_threshold:
                state.enforcement = EnforcementLevel.DEGRADE
            elif state.score <= self.audit_threshold:
                state.enforcement = EnforcementLevel.AUDIT
            else:
                state.enforcement = EnforcementLevel.NONE
            
            if state.enforcement != old_level:
                logger.warning(
                    f"RiskEngine: Session {session_id} trust score {state.score:.2f} "
                    f"transitioned {old_level.name} -> {state.enforcement.name}"
                )

    def get_enforcement(self, session_id: str, server_id: str) -> EnforcementLevel:
        return self.get_state(session_id, server_id).enforcement

    def get_score(self, session_id: str, server_id: str) -> float:
        return self.get_state(session_id, server_id).score

    def record_policy_budget(
        self,
        session_id: str,
        server_id: str,
        *,
        effective_action: str,
        max_calls_per_minute: int = 0,
        max_risky_calls_per_session: int = 0,
        max_blocked_attempts_per_session: int = 0,
        now: Optional[float] = None,
    ) -> Optional[dict[str, Any]]:
        """
        Record the final policy decision for per-session budget accounting.

        Limits are opt-in: zero or negative values disable that budget. The
        method returns a violation dictionary when the current request should
        be blocked by a configured budget, otherwise None.
        """
        state = self.get_state(session_id, server_id)
        ts = time.monotonic() if now is None else now
        normalized_action = (effective_action or "ALLOW").upper()

        with self._state_lock:
            if max_calls_per_minute > 0:
                cutoff = ts - 60.0
                state.tool_call_timestamps = [
                    item for item in state.tool_call_timestamps if item >= cutoff
                ]
                state.tool_call_timestamps.append(ts)
                if len(state.tool_call_timestamps) > max_calls_per_minute:
                    return {
                        "rule_id": "VANGUARD-BUDGET-001",
                        "budget": "max_tool_calls_per_minute",
                        "limit": max_calls_per_minute,
                        "observed": len(state.tool_call_timestamps),
                        "reason": (
                            "Per-session tool-call budget exceeded "
                            f"({len(state.tool_call_timestamps)}/{max_calls_per_minute} in 60s)."
                        ),
                    }

            if normalized_action in {"WARN", "REVIEW", "SHADOW-BLOCK", "BLOCK"}:
                state.risky_call_count += 1
                if (
                    max_risky_calls_per_session > 0
                    and state.risky_call_count > max_risky_calls_per_session
                ):
                    return {
                        "rule_id": "VANGUARD-BUDGET-002",
                        "budget": "max_risky_calls_per_session",
                        "limit": max_risky_calls_per_session,
                        "observed": state.risky_call_count,
                        "reason": (
                            "Per-session risky-call budget exceeded "
                            f"({state.risky_call_count}/{max_risky_calls_per_session})."
                        ),
                    }

            if (
                max_blocked_attempts_per_session > 0
                and state.blocked_attempt_count >= max_blocked_attempts_per_session
                and normalized_action not in {"SHADOW-BLOCK", "BLOCK"}
            ):
                return {
                    "rule_id": "VANGUARD-BUDGET-003",
                    "budget": "max_blocked_attempts_per_session",
                    "limit": max_blocked_attempts_per_session,
                    "observed": state.blocked_attempt_count,
                    "reason": (
                        "Per-session blocked-attempt budget already exhausted "
                        f"({state.blocked_attempt_count}/{max_blocked_attempts_per_session})."
                    ),
                }

            if normalized_action in {"SHADOW-BLOCK", "BLOCK"}:
                state.blocked_attempt_count += 1
                if (
                    max_blocked_attempts_per_session > 0
                    and state.blocked_attempt_count > max_blocked_attempts_per_session
                ):
                    return {
                        "rule_id": "VANGUARD-BUDGET-003",
                        "budget": "max_blocked_attempts_per_session",
                        "limit": max_blocked_attempts_per_session,
                        "observed": state.blocked_attempt_count,
                        "reason": (
                            "Per-session blocked-attempt budget exceeded "
                            f"({state.blocked_attempt_count}/{max_blocked_attempts_per_session})."
                        ),
                    }

        return None
