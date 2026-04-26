"""
tests/test_phase7_assurance.py
Verification suite for McpVanguard Phase 7 High-Assurance track.
Tests Risk Modeling, Active Attestation, and SBOM Integrity.
"""

import pytest
import time
from core.risk import RiskEngine, EnforcementLevel
from core import capability_fingerprint
from core import server_integrity

@pytest.fixture
def risk_engine():
    engine = RiskEngine.get_instance()
    # Reset states for testing
    engine._states.clear()
    return engine

def test_risk_score_calculation(risk_engine):
    sid, srv = "sess-1", "srv-1"
    
    # Baseline
    assert risk_engine.get_score(sid, srv) == 100.0
    assert risk_engine.get_enforcement(sid, srv) == EnforcementLevel.NONE
    
    # Penalty: Rule block (-20)
    risk_engine.record_event(sid, srv, "RULE_BLOCK")
    assert risk_engine.get_score(sid, srv) == 80.0
    assert risk_engine.get_enforcement(sid, srv) == EnforcementLevel.AUDIT
    
    # Penalty: Attestation drift (-25) -> Score 55
    risk_engine.record_event(sid, srv, "ATTESTATION_DRIFT")
    assert risk_engine.get_score(sid, srv) == 55.0
    assert risk_engine.get_enforcement(sid, srv) == EnforcementLevel.AUDIT
    
    # Penalty: Behavioral block (-30) -> Score 25
    risk_engine.record_event(sid, srv, "BEHAVIORAL_BLOCK")
    assert risk_engine.get_score(sid, srv) == 25.0
    assert risk_engine.get_enforcement(sid, srv) == EnforcementLevel.DEGRADE

    # Penalty: SBOM mismatch (-15) -> Score 10 (triggers BLOCK as score <= 10.0)
    risk_engine.record_event(sid, srv, "SBOM_MISMATCH")
    assert risk_engine.get_score(sid, srv) == 10.0
    assert risk_engine.get_enforcement(sid, srv) == EnforcementLevel.BLOCK

    # One more hit to confirm deep block
    risk_engine.record_event(sid, srv, "RULE_WARN")
    assert risk_engine.get_score(sid, srv) < 10.0
    assert risk_engine.get_enforcement(sid, srv) == EnforcementLevel.BLOCK

def test_capability_attestation_drift():
    pinned = {
        "version": 1,
        "tools": {
            "version": 1,
            "tools": [
                {"name": "read_file", "inputSchema_sha256": "hash-1"},
                {"name": "list_dir", "inputSchema_sha256": "hash-2"}
            ]
        }
    }
    
    # 1. Valid match
    res = capability_fingerprint.verify_attestation(pinned, pinned)
    assert res.is_valid is True
    assert len(res.drifts) == 0
    
    # 2. Unexpected tool (Critical)
    actual_rogue = {
        "version": 1,
        "tools": {
            "version": 1,
            "tools": [
                {"name": "read_file", "inputSchema_sha256": "hash-1"},
                {"name": "list_dir", "inputSchema_sha256": "hash-2"},
                {"name": "run_shell", "inputSchema_sha256": "rogue-hash"}
            ]
        }
    }
    res = capability_fingerprint.verify_attestation(actual_rogue, pinned)
    assert res.is_valid is False
    assert any(d.drift_type == "unexpected" and d.feature == "run_shell" for d in res.drifts)
    assert res.risk_impact >= 50.0

    # 3. Missing tool
    actual_missing = {
        "version": 1,
        "tools": {
            "version": 1,
            "tools": [{"name": "read_file", "inputSchema_sha256": "hash-1"}]
        }
    }
    res = capability_fingerprint.verify_attestation(actual_missing, pinned)
    assert res.is_valid is False
    assert any(d.drift_type == "missing" and d.feature == "list_dir" for d in res.drifts)

def test_sbom_integrity_verify():
    baseline = {
        "executable": {"sha256": "original-hash"},
        "command": {"argv": ["python", "server.py"]}
    }
    
    # 1. Valid
    valid, impact, labels = server_integrity.verify_server_sbom(baseline, baseline)
    assert valid is True
    
    # 2. Executable mismatch
    malicious = {
        "executable": {"sha256": "poisoned-hash"},
        "command": {"argv": ["python", "server.py"]}
    }
    valid, impact, labels = server_integrity.verify_server_sbom(malicious, baseline)
    assert valid is False
    assert "executable.sha256" in labels
    assert impact >= 40.0
