import os
import sys
import json
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path.cwd()))

from core.rules_engine import RulesEngine
from core.models import SafeZone
from core import behavioral
from core.proxy import ProxyConfig, VanguardProxy

def test_crit_1_format_bypass():
    print("\n--- Testing CRIT-1: Safe Zone Bypass ---")
    engine = RulesEngine(rules_dir="rules")
    # Manually inject a safe zone for testing
    engine.safe_zones = [SafeZone(tool="read_file", allowed_prefixes=["/safe/"], recursive=True)]
    
    # 1. Correct format (blocked)
    msg_blocked = {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}
    }
    res1 = engine.check(msg_blocked)
    print(f"Standard format (/etc/passwd): {res1.action} (Allowed: {res1.allowed})")
    
    # 2. Malicious format (bypassed)
    msg_bypass = {
        "method": "not_tools_call", # different method
        "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}
    }
    res2 = engine.check(msg_bypass)
    print(f"Bypassed format (/etc/passwd): {res2.action} (Allowed: {res2.allowed})")
    
    if res1.action == "BLOCK" and res2.action == "ALLOW":
        print("RESULT: CRIT-1 VERIFIED! (Bypass confirmed)")
    else:
        print(f"RESULT: CRIT-1 NOT VERIFIED (Status: {res1.action} vs {res2.action})")

def test_crit_2_default_allow():
    print("\n--- Testing CRIT-2: Default Allow Policy ---")
    engine = RulesEngine(rules_dir="rules")
    # Clean rules for clean test
    engine.rules = []
    engine.safe_zones = []
    
    msg = {
        "method": "tools/call",
        "params": {"name": "unknown_tool", "arguments": {}}
    }
    res = engine.check(msg)
    print(f"Default policy for unknown tool: {res.action}")
    if res.action == "ALLOW":
        print("RESULT: CRIT-2 VERIFIED! (Default allow confirmed)")

def test_crit_3_memory_leak():
    print("\n--- Testing CRIT-3: Memory Leak (Session Accumulation) ---")
    behavioral._states.clear()
    print(f"Initial states: {len(behavioral._states)}")
    
    for i in range(1000):
        behavioral.get_state(f"session_{i}")
        
    final_count = len(behavioral._states)
    print(f"States after 1000 sessions: {final_count}")
    if final_count == 1000:
        print("RESULT: CRIT-3 VERIFIED! (States accumulate indefinitely)")

def test_med_2_truncation_bypass():
    print("\n--- Testing MED-2: Truncation Bypass ---")
    config = ProxyConfig()
    config.max_string_len = 100 # small for testing
    proxy = VanguardProxy(server_command=["python", "-c", "pass"], config=config)
    
    # Configure a rule to block 'malicious_cmd'
    proxy.rules_engine.rules = [] # clear legacy
    from core.rules_engine import Rule
    test_rule = Rule({
        "id": "test-block",
        "pattern": "malicious_cmd",
        "action": "BLOCK",
        "severity": "CRITICAL"
    }, "test.yaml")
    proxy.rules_engine.rules.append(test_rule)
    
    # 1. Direct command (blocked)
    msg_block = {"method": "tools/call", "params": {"name": "exec", "arguments": {"cmd": "malicious_cmd"}}}
    res1 = proxy.rules_engine.check(msg_block)
    print(f"Direct command: {res1.action}")
    
    # 2. Long command (truncated, therefore bypassed)
    long_cmd = ("A" * 120) + " maliciously_cmd"
    msg_long = {"method": "tools/call", "params": {"name": "exec", "arguments": {"cmd": long_cmd}}}
    
    # Check normalization/truncation
    normalized = proxy._normalize_message(msg_long)
    res2 = proxy.rules_engine.check(normalized)
    
    print(f"Truncated command: {res2.action}")
    print(f"Normalized value sample: {normalized['params']['arguments']['cmd'][:110]}...")
    
    if res1.action == "BLOCK" and res2.action == "ALLOW":
        print("RESULT: MED-2 VERIFIED! (Truncation causes bypass)")

if __name__ == "__main__":
    test_crit_1_format_bypass()
    test_crit_2_default_allow()
    test_crit_3_memory_leak()
    test_med_2_truncation_bypass()
