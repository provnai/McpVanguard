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
from typing import Dict, List, Optional, Tuple

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
            "ENTROPY_HIGH": 15.0,
            "ENTROPY_CRITICAL": 50.0,
            "BEHAVIORAL_WARN": 10.0,
            "BEHAVIORAL_BLOCK": 30.0,
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
