import pytest
import asyncio
import os
import httpx
from unittest.mock import MagicMock, patch, AsyncMock
from core import sse_server, semantic, jail

# ---------------------------------------------------------------------------
# 1. Test: Global Connection Ceiling (DoS Protection)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_v172_global_connection_limit():
    """
    Verify that VANGUARD_MAX_GLOBAL_CONNECTIONS is strictly enforced.
    """
    from core.sse_server import ServerContext, handle_sse
    
    # Mock config
    cfg = {
        "API_KEY": "",
        "ALLOWED_IPS": [],
        "MAX_CONCURRENCY": 5,
        "MAX_GLOBAL_CONNECTIONS": 2, # Tiny limit for testing
        "RATE_LIMIT_PER_SEC": 10.0
    }
    
    # Mock context
    ctx = ServerContext(
        server_command=["python", "-c", "print('hello')"],
        config=None,
        sse_transport=MagicMock(),
        cfg=cfg
    )
    
    # Reset global state for clean test
    sse_server._total_active_connections = 0
    sse_server._active_connections.clear()
    
    async def mock_send(data): pass
    async def mock_receive(): return {"type": "http.request"}
    
    scope = {
        "type": "http",
        "client": ["1.1.1.1", 1234],
        "headers": []
    }
    
    # Simulate 2 existing global connections
    sse_server._total_active_connections = 2
    
    # Third connection attempt should trigger the error
    with patch("core.sse_server._send_error", new_callable=AsyncMock) as mock_err:
        await handle_sse(scope, mock_receive, mock_send, ctx)
        mock_err.assert_called_once()
        assert mock_err.call_args[0][1] == 503
        assert "Global connection limit reached" in mock_err.call_args[0][2]

# ---------------------------------------------------------------------------
# 2. Test: Semantic Scorer Fail-Closed (Reliability)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_v172_semantic_fail_closed():
    """
    Verify that if Ollama is down and VANGUARD_SEMANTIC_FAIL_CLOSED=true, 
    the tool call is BLOCKED.
    """
    with patch.dict(os.environ, {
        "VANGUARD_SEMANTIC_ENABLED": "true",
        "VANGUARD_SEMANTIC_FAIL_CLOSED": "true"
    }):
        # Reload constants in semantic module or patch them
        with patch("core.semantic.ENABLED", True), \
             patch("core.semantic.ENABLE_FAIL_CLOSED", True):
            
            # Mock _score_sync to simulate total failure after retries
            with patch("core.semantic._score_sync") as mock_score:
                mock_score.return_value = (1.0, "FAIL-CLOSED: All 3 semantic attempts failed")
                
                message = {"method": "tools/call", "params": {"name": "read_file"}}
                result = await semantic.score_intent(message)
                
                assert result is not None
                assert result.allowed is False
                assert "FAIL-CLOSED" in result.block_reason

# ---------------------------------------------------------------------------
# 3. Test: Hermetic Gate (Unicode + Traversal)
# ---------------------------------------------------------------------------

def test_v172_hermetic_gate_traversal():
    """
    Verify that dot-dot is blocked even with lookalike characters.
    """
    # U+2215 DIVISION SLASH
    evil_path = "C:/Users/test/..∕..∕etc/passwd"
    prefix = "C:/Users/test"
    
    # Logic in jail.py now normalizes and then blocks ..
    assert jail.check_path_jail(evil_path, [prefix]) is False
    
    # Standard traversal should also be blocked immediately
    assert jail.check_path_jail("C:/Users/test/../../windows/system32", [prefix]) is False
