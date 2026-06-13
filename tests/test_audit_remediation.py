import os
import pytest
import time
import os
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


def test_safe_zone_blocks_nonstandard_target_argument():
    engine = RulesEngine(rules_dir="rules")
    engine.safe_zones = [SafeZone(tool="read_file", allowed_prefixes=["/safe/"], recursive=True)]

    msg = {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"target": "/etc/passwd"}}
    }

    result = engine.check(msg)
    assert result.action == "BLOCK"
    assert "SAFEZONE" in result.rule_matches[0].rule_id
    assert result.rule_matches[0].matched_field == "target"
    assert result.rule_matches[0].matched_value == "/etc/passwd"
    assert "/safe/" in result.rule_matches[0].description


@pytest.mark.parametrize("arg_name", ["file", "input", "output", "filepath", "target"])
def test_safe_zone_blocks_recursive_nonstandard_path_arguments(arg_name):
    engine = RulesEngine(rules_dir="rules")
    engine.safe_zones = [SafeZone(tool="read_file", allowed_prefixes=["/safe/"], recursive=True)]

    msg = {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"nested": {arg_name: "/etc/passwd"}}},
    }

    result = engine.check(msg)
    assert result.action == "BLOCK"
    assert result.rule_matches[0].rule_id == "VANGUARD-SAFEZONE-001"


@pytest.mark.parametrize(
    ("arguments", "expected_rule"),
    [
        ({"file": "/etc/passwd"}, "FS-001"),
        ({"nested": {"file": "/etc/passwd"}}, "FS-001"),
        ({"cmd": "rm -rf /"}, "CMD-001"),
        ({"command": ["rm", "-rf", "/"]}, "CMD-001"),
        ({"nested": {"argv": ["rm", "-rf", "/"]}}, "CMD-001"),
    ],
)
def test_l1_recursively_blocks_nonstandard_argument_names(arguments, expected_rule):
    engine = RulesEngine(rules_dir="rules")
    engine.safe_zones = []

    msg = {
        "method": "tools/call",
        "params": {"name": "custom_tool", "arguments": arguments},
    }

    result = engine.check(msg)
    assert result.action == "BLOCK"
    assert result.rule_matches[0].rule_id == expected_rule

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


def test_clear_all_states_uses_scan_iter_when_available(clean_behavioral):
    class FakeRedis:
        def __init__(self):
            self.deleted_batches = []
            self.keys_called = False

        def scan_iter(self, match=None, count=None):
            assert match == "vguard:beh:*"
            assert count == 100
            for key in ("vguard:beh:1", "vguard:beh:2"):
                yield key

        def delete(self, *keys):
            self.deleted_batches.append(keys)

        def keys(self, pattern):
            self.keys_called = True
            raise AssertionError("keys() should not be used when scan_iter is available")

    fake = FakeRedis()
    original = behavioral._redis_client
    behavioral._redis_client = fake
    try:
        behavioral.clear_all_states()
    finally:
        behavioral._redis_client = original

    assert fake.deleted_batches == [("vguard:beh:1", "vguard:beh:2")]
    assert fake.keys_called is False


def test_redis_window_uses_epoch_time_for_shared_process_counts(monkeypatch):
    class FakeRedis:
        def __init__(self):
            self.scores = []
            self.removed_cutoff = None

        def zadd(self, key, mapping):
            self.scores.extend(mapping.values())

        def expire(self, key, ttl):
            pass

        def zremrangebyscore(self, key, start, stop):
            self.removed_cutoff = stop

        def zcard(self, key):
            return len(self.scores)

    fake = FakeRedis()
    original = behavioral._redis_client
    behavioral._redis_client = fake
    monkeypatch.setattr(behavioral.time, "time", lambda: 1_700_000_000.0)
    monkeypatch.setattr(behavioral.time, "monotonic", lambda: 12.0)
    try:
        window = behavioral._RedisWindow("vguard:beh:test")
        window.record()
        assert fake.scores == [1_700_000_000.0]

        assert window.count_in(60) == 1
        assert fake.removed_cutoff == pytest.approx(1_699_999_939.9)
    finally:
        behavioral._redis_client = original

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
