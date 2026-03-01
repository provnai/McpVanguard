"""
tests/test_behavioral.py — Tests for Layer 3 behavioral analysis.
"""

import pytest
from core import behavioral
from core.models import InspectionResult

@pytest.fixture(autouse=True)
def clean_behavioral_state():
    """Ensure a clean state for each test."""
    behavioral._states.clear()
    yield
    behavioral._states.clear()

@pytest.mark.asyncio
async def test_data_scraping_detection():
    session_id = "test-session-1"
    
    # 1. Send many read_file calls (below limit)
    for _ in range(behavioral.MAX_READ_FILE_PER_10S):
        res = await behavioral.inspect_request(session_id, {
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/foo/bar"}}
        })
        assert res is None
        
    # 2. Exceed limit
    res = await behavioral.inspect_request(session_id, {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/foo/baz"}}
    })
    
    assert res is not None
    assert res.action == "BLOCK"
    assert res.layer_triggered == 3
    assert "BEH-001" in res.rule_matches[0].rule_id

@pytest.mark.asyncio
async def test_directory_enumeration_warning():
    session_id = "test-session-2"
    
    # Send many list_directory calls
    for _ in range(behavioral.MAX_LIST_DIR_PER_5S):
        res = await behavioral.inspect_request(session_id, {
            "method": "tools/call",
            "params": {"name": "list_directory", "arguments": {"path": "/"}}
        })
        assert res is None
        
    # Exceed limit
    res = await behavioral.inspect_request(session_id, {
        "method": "tools/call",
        "params": {"name": "list_directory", "arguments": {"path": "/var"}}
    })
    
    assert res is not None
    assert res.action == "WARN"
    assert res.layer_triggered == 3
    assert "BEH-002" in res.rule_matches[0].rule_id

@pytest.mark.asyncio
async def test_write_after_sensitive_read():
    session_id = "test-session-3"
    
    # 1. Read a sensitive file
    await behavioral.inspect_request(session_id, {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}
    })
    
    # 2. Run a "write" tool (e.g., write_file)
    res = await behavioral.inspect_request(session_id, {
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "/tmp/evil", "content": "foo"}}
    })
    
    assert res is not None
    assert res.action == "BLOCK"
    assert res.layer_triggered == 3
    assert "BEH-003" in res.rule_matches[0].rule_id

@pytest.mark.asyncio
async def test_large_response_detection():
    session_id = "test-session-4"
    
    # Moderate response
    res = await behavioral.inspect_response(session_id, "{\"result\": \"ok\"}")
    assert res is None
    
    # Huge response
    huge_body = "A" * (behavioral.MAX_RESPONSE_BYTES + 100)
    res = await behavioral.inspect_response(session_id, huge_body)
    
    assert res is not None
    assert res.action == "BLOCK"
    assert res.layer_triggered == 3
    assert "BEH-004" in res.rule_matches[0].rule_id

@pytest.mark.asyncio
async def test_tool_flood_detection():
    session_id = "test-session-5"
    
    # Flood any tools
    for _ in range(behavioral.MAX_ANY_TOOL_PER_60S):
        res = await behavioral.inspect_request(session_id, {
            "method": "tools/call",
            "params": {"name": "get_weather", "arguments": {"city": "Berlin"}}
        })
        assert res is None
        
    # Exceed limit
    res = await behavioral.inspect_request(session_id, {
        "method": "tools/call",
        "params": {"name": "get_weather", "arguments": {"city": "London"}}
    })
    
    assert res is not None
    assert res.action == "BLOCK"
    assert res.layer_triggered == 3
    assert "BEH-005" in res.rule_matches[0].rule_id
