import os
import sys
import json
import time
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path.cwd()))

from core.rules_engine import RulesEngine
from core.models import SafeZone, RuleAction
from core import behavioral
from core.proxy import ProxyConfig, VanguardProxy

def test_crit_1_format_bypass_FIXED():
    print("\n--- Verifying FIX for CRIT-1: Safe Zone Bypass ---")
    engine = RulesEngine(rules_dir="rules")
    engine.safe_zones = [SafeZone(tool="read_file", allowed_prefixes=["/safe/"], recursive=True)]
    
    # 1. Standard format (blocked)
    msg_blocked = {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}
    }
    res1 = engine.check(msg_blocked)
    print(f"Standard format (/etc/passwd): {res1.action}")
    
    # 2. Bypassed format (NOW BLOCKED!)
    msg_bypass = {
        "method": "not_tools_call", 
        "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}
    }
    res2 = engine.check(msg_bypass)
    print(f"Non-standard format (/etc/passwd): {res2.action}")
    
    if res1.action == "BLOCK" and res2.action == "BLOCK":
        print("RESULT: CRIT-1 FIX VERIFIED! (Bypassed format now caught)")
    else:
        print(f"RESULT: CRIT-1 FIX FAILED (Status: {res1.action} vs {res2.action})")

def test_crit_2_default_deny_FIXED():
    print("\n--- Verifying FIX for CRIT-2: Default Deny Policy ---")
    os.environ["VANGUARD_DEFAULT_POLICY"] = "DENY"
    engine = RulesEngine(rules_dir="rules")
    engine.rules = []
    engine.safe_zones = []
    
    msg = {
        "method": "tools/call",
        "params": {"name": "unknown_tool", "arguments": {}}
    }
    res = engine.check(msg)
    print(f"Default policy (DENY) for unknown tool: {res.action}")
    if res.action == "BLOCK":
        print("RESULT: CRIT-2 FIX VERIFIED! (Default deny works)")
    os.environ["VANGUARD_DEFAULT_POLICY"] = "ALLOW" # reset

def test_crit_3_memory_leak_FIXED():
    print("\n--- Verifying FIX for CRIT-3: Memory Leak (Pruning) ---")
    behavioral._states.clear()
    
    # Fill up to 1001 states to trigger pruning
    for i in range(1005):
        behavioral.get_state(f"session_{i}")
    
    count_before = len(behavioral._states)
    print(f"States after 1005 insertions: {count_before}")
    
    # Simulate age and prune
    now = time.monotonic()
    for sid in list(behavioral._states.keys())[:500]:
        behavioral._states[sid].last_accessed = now - 5000 # old
        
    pruned = behavioral.prune_inactive_states(max_age_secs=3600)
    print(f"Pruned: {pruned} states")
    count_after = len(behavioral._states)
    print(f"States after pruning: {count_after}")
    
    if count_before > 1000 and count_after < 1000:
        print("RESULT: CRIT-3 FIX VERIFIED! (Pruning works)")

def test_med_2_truncation_bypass_FIXED():
    print("\n--- Verifying FIX for MED-2: Truncation Bypass (Rejection) ---")
    config = ProxyConfig()
    config.max_string_len = 100
    proxy = VanguardProxy(server_command=["python", "-c", "pass"], config=config)
    
    long_cmd = ("A" * 120) + " malicious_cmd"
    msg_long = {"method": "tools/call", "params": {"name": "exec", "arguments": {"cmd": long_cmd}}}
    
    failed = False
    try:
        proxy._normalize_message(msg_long)
    except ValueError as e:
        print(f"Caught expected ValueError: {e}")
        failed = True
    
    if failed:
        print("RESULT: MED-2 FIX VERIFIED! (Oversized message rejected)")
    else:
        print("RESULT: MED-2 FIX FAILED (No exception raised)")

if __name__ == "__main__":
    test_crit_1_format_bypass_FIXED()
    test_crit_2_default_deny_FIXED()
    test_crit_3_memory_leak_FIXED()
    test_med_2_truncation_bypass_FIXED()
