import os
import pytest
import time
from pathlib import Path
from core.rules_engine import RulesEngine
from core.models import SafeZone, RuleAction
from core import behavioral
from core.proxy import ProxyConfig, VanguardProxy

@pytest.fixture
def clean_behavioral():
    behavioral._states.clear()
    yield
    behavioral._states.clear()

def test_crit_1_format_bypass_blocked():
    """Verify that safe zones trigger even on non-standard MCP formats."""
    # Use a temp directory for rules to avoid side effects
    engine = RulesEngine(rules_dir="rules")
    engine.safe_zones = [SafeZone(tool="read_file", allowed_prefixes=["/safe/"], recursive=True)]
    
    # 1. Standard format (blocked)
    msg_standard = {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}
    }
    assert engine.check(msg_standard).action == "BLOCK"
    
    # 2. Bypassed format (used to bypass, now MUST block)
    msg_non_standard = {
        "method": "not_tools_call", 
        "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}
    }
    assert engine.check(msg_non_standard).action == "BLOCK"

def test_crit_2_default_deny_enforced():
    """Verify that VANGUARD_DEFAULT_POLICY=DENY works for unknown tools."""
    os.environ["VANGUARD_DEFAULT_POLICY"] = "DENY"
    try:
        engine = RulesEngine(rules_dir="rules")
        engine.rules = []
        engine.safe_zones = []
        
        msg = {
            "method": "tools/call",
            "params": {"name": "unknown_tool", "arguments": {}}
        }
        res = engine.check(msg)
        assert res.action == "BLOCK"
        assert "default" in res.block_reason.lower()
    finally:
        os.environ["VANGUARD_DEFAULT_POLICY"] = "ALLOW"

def test_crit_3_behavioral_state_pruning(clean_behavioral):
    """Verify that behavioral states don't leak memory and prune correctly."""
    # Insert over the limit
    for i in range(1005):
        behavioral.get_state(f"session_{i}")
    
    assert len(behavioral._states) == 1005
    
    # Age some states
    now = time.monotonic()
    for sid in list(behavioral._states.keys())[:500]:
        behavioral._states[sid].last_accessed = now - 5000 
        
    # Pruning should happen next time we get a NEW state or call prune
    behavioral.get_state("session_trigger")
    
    # Pruned states should be gone (500 aged + 1 trigger logic)
    # The count should be back below ~1000
    assert len(behavioral._states) <= 1000

def test_med_2_oversized_payload_rejection():
    """Verify that oversized payloads are REJECTED instead of truncated."""
    config = ProxyConfig()
    config.max_string_len = 100
    proxy = VanguardProxy(server_command=["python", "-c", "pass"], config=config)
    
    long_cmd = ("A" * 150)
    msg_long = {"method": "tools/call", "params": {"name": "exec", "arguments": {"cmd": long_cmd}}}
    
    with pytest.raises(ValueError) as excinfo:
        proxy._normalize_message(msg_long)
    
    assert "exceeds limit" in str(excinfo.value)
