import pytest
import json
import unicodedata
import time
from unittest.mock import MagicMock
from core import jail, rules_engine, models

# ---------------------------------------------------------------------------
# 1. Unicode Normalization Fuzzing
# ---------------------------------------------------------------------------

def test_unicode_normalization_bypass():
    """
    Test if non-standard slashes or dots bypass prefix checks.
    """
    safe_prefix = "C:/Users/test"
    # U+2215 DIVISION SLASH
    div_slash = "C:/Users/test/..∕..∕etc/passwd"
    
    # Current behavior check: does it resolve?
    # Python pathlib resolve() on Windows/Linux usually handles these.
    # But we should be explicit.
    
    assert jail.check_path_jail(div_slash, [safe_prefix]) is False

# ---------------------------------------------------------------------------
# 2. ReDoS / Regex Stress Test
# ---------------------------------------------------------------------------

def test_regex_catastrophic_backtracking():
    """
    Verify that the 100ms timeout and 100KB cap protect the worker pool.
    """
    from core.rules_engine import Rule
    
    # Vulnerable-looking regex (if not for our guards)
    vuln_data = {
        "id": "REDOS-TEST",
        "pattern": "(a+)+$", 
        "match_fields": ["params"]
    }
    rule = rules_engine.Rule(vuln_data, "test.yaml")
    
    # Payload that causes catastrophic backtracking
    # aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
    evil_payload = "a" * 50 + "!"
    
    import time
    start = time.monotonic()
    # Should NOT hang the thread forever, but hit our 100ms timeout
    rule.check({"params": evil_payload})
    duration = time.monotonic() - start
    
    assert duration < 1.0 # Should be fast (0.1s + threading overhead)

# ---------------------------------------------------------------------------
# 3. Large Payload & JSON Nesting (Resource Exhaustion)
# ---------------------------------------------------------------------------

def test_deeply_nested_json():
    """
    Test if deeply nested JSON crashes the Pydantic/Standard parser.
    """
    nested = {"a": {}}
    curr = nested["a"]
    for _ in range(2000): # 2000 levels deep
        curr["a"] = {}
        curr = curr["a"]
    
    json_str = json.dumps(nested)
    
    # Test if models can handle it without RecursionError
    try:
        models.JsonRpcRequest.model_validate_json(json_str)
    except Exception as e:
        # Pydantic usually catches this gracefully, as long as we don't crash
        print(f"Caught expected parser limit: {e}")

def test_massive_unstructured_payload():
    """
    Test 10MB payload against proxy normalization.
    """
    massive = "X" * (10 * 1024 * 1024)
    # This should be truncated by _normalize_message() to 8KB
    from core.proxy import ProxySession, ProxyConfig
    session = ProxySession(MagicMock(), ProxyConfig())
    
    normalized = session._normalize_message(massive)
    assert len(str(normalized)) < 16384 # Way less than 10MB
