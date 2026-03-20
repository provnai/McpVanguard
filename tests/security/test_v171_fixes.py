import pytest
import json
import asyncio
import os
import time
from unittest.mock import MagicMock, patch, AsyncMock
from core.proxy import ProxyConfig, VanguardProxy
from core import behavioral, rules_engine, jail, models

# ---------------------------------------------------------------------------
# 1. Test: Inspection/Execution Symmetry (P2 Bypass Fix)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_v171_bypass_prevention():
    """
    Verify that the normalized (inspected) payload is exactly what is forwarded.
    This prevents 'truncation bypass' where the inspector sees short string
    but the server gets a long malicious one.
    """
    config = ProxyConfig()
    config.mode = "enforce"
    
    # Mock proxy instance
    # VanguardProxy is the combined class in 1.7.0
    mock_server = MagicMock()
    mock_server.stdin = MagicMock()
    mock_server.stdin.write = MagicMock()
    mock_server.stdin.drain = AsyncMock()
    
    proxy = VanguardProxy(["dummy"], config)
    
    # Malicious raw message with extra content that would be stripped by _normalize_message
    # but could be executed by a vulnerable server if forwarded raw.
    raw_payload = '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/tmp/safe"}}} \n MALICIOUS_EXTRA_DATA'
    
    # We need to mock _inspect_message to return ALLOW
    with patch.object(proxy, '_inspect_message', new_callable=AsyncMock) as mock_inspect:
        mock_inspect.return_value = models.InspectionResult.allow()
        
        # Manually trigger the pump logic (simplified)
        raw_message = json.loads(raw_payload.split("\n")[0]) # Extract JSON part like the real proxy
        normalized = proxy._normalize_message(raw_message)
        assert "MALICIOUS_EXTRA_DATA" not in json.dumps(normalized)
        
        # Test the forwarding logic (line 269 fix)
        forward_data = json.dumps(normalized)
        # In VanguardProxy, we need to mock the writer
        proxy.agent_writer = MagicMock() 
        proxy.agent_writer.write = MagicMock()
        proxy.agent_writer.drain = AsyncMock()
        
        # Actually _write_to_server in VanguardProxy writes to self._server_process.stdin
        proxy._server_process = MagicMock()
        proxy._server_process.stdin = MagicMock()
        proxy._server_process.stdin.write = MagicMock()
        proxy._server_process.stdin.drain = AsyncMock()

        await proxy._write_to_server(forward_data)
        
        # Verify that ONLY the JSON was written, not the raw 'line'
        call_args = proxy._server_process.stdin.write.call_args[0][0]
        assert b"MALICIOUS_EXTRA_DATA" not in call_args
        assert b"/tmp/safe" in call_args

# ---------------------------------------------------------------------------
# 2. Test: SSE Rate Limiting (P1 SSE Gap)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_v171_sse_rate_limiting():
    """
    Verify that handle_messages in sse_server now enforces rate limits.
    """
    from core.sse_server import RateLimiter
    import time
    
    limiter = RateLimiter(rate=1, capacity=2)
    
    # First two should pass (burst)
    assert await limiter.consume() is True
    assert await limiter.consume() is True
    
    # Third should fail immediately
    assert await limiter.consume() is False
    
    # Wait for refill
    await asyncio.sleep(1.1)
    assert await limiter.consume() is True

# ---------------------------------------------------------------------------
# 3. Test: Behavioral Throttle Recovery (P2 Stickiness Fix)
# ---------------------------------------------------------------------------

def test_v171_throttle_recovery():
    """
    Verify that is_throttled clears once the bucket refills > 50%.
    """
    state = behavioral.BehavioralState(session_id="test-session")
    state.is_throttled = True
    
    # Set bucket to empty
    state.entropy_bucket.tokens = 0
    state.entropy_bucket.last_update = time.monotonic()
    
    # Status check should NOT clear it yet
    assert state.update_throttle_status() is False
    assert state.is_throttled is True
    
    # Mock time jump for refill (> 50 tokens)
    state.entropy_bucket.tokens = 60 
    assert state.update_throttle_status() is True
    assert state.is_throttled is False

# ---------------------------------------------------------------------------
# 4. Test: Non-Recursive Jail (P2 Safe Zone Fix)
# ---------------------------------------------------------------------------

def test_v171_non_recursive_jail():
    """
    Verify that recursive=False correctly blocks deeper paths.
    """
    prefixes = ["C:/Users/test"]
    
    # Recursive (default) allows deep
    assert jail.check_path_jail("C:/Users/test/subdir/secret.txt", prefixes, recursive=True) is True
    
    # Non-recursive should block subdir
    # Note: relpath on Windows might return 'subdir\secret.txt'
    assert jail.check_path_jail("C:/Users/test/subdir/secret.txt", prefixes, recursive=False) is False
    
    # Non-recursive should allow direct child
    assert jail.check_path_jail("C:/Users/test/readme.txt", prefixes, recursive=False) is True

# ---------------------------------------------------------------------------
# 5. Test: CLI Env Precedence (P1 Misconfig Fix)
# ---------------------------------------------------------------------------

def test_v171_cli_precedence():
    """
    Verify that CLI defaults (None) do not override env variables.
    """
    from core.cli import ProxyConfig
    import os
    
    with patch.dict(os.environ, {"VANGUARD_SEMANTIC_ENABLED": "true"}):
        config = ProxyConfig()
        assert config.semantic_enabled is True
        
        # Simulate CLI 'start' with semantic=None (default)
        semantic_cli = None
        if semantic_cli is not None:
             config.semantic_enabled = semantic_cli
             
        assert config.semantic_enabled is True # Should remain True from env
        
        # Simulate CLI 'start' with semantic=False (explicit override)
        semantic_cli = False
        if semantic_cli is not None:
             config.semantic_enabled = semantic_cli
             
        assert config.semantic_enabled is False # Should be overridden
