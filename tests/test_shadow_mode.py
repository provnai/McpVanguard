"""
tests/test_shadow_mode.py
Verify that Shadow Mode correctly allows blocks to pass while logging them.
"""

import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from core.proxy import ProxyConfig, VanguardProxy
import asyncio

@pytest.mark.asyncio
async def test_shadow_mode_allows_violation():
    """Verify that VANGUARD_MODE=audit allows forbidden calls but logs them."""
    config = ProxyConfig()
    config.mode = "audit"
    # Mock reader and writer
    mock_reader = AsyncMock()
    mock_writer = AsyncMock()
    
    # Mock reading one line which is a restricted file access
    mock_reader.readline.side_effect = [
        json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/etc/shadow"}},
            "id": 1
        }).encode("utf-8"),
        None # Stop session
    ]
    
    # Mock proxy methods
    proxy = VanguardProxy(
        server_command=["mock-server"],
        config=config,
        agent_reader=mock_reader,
        agent_writer=mock_writer
    )
    proxy._setup_subprocess = AsyncMock()
    proxy._write_to_server = AsyncMock()
    proxy._write_to_agent = AsyncMock()
    
    # Mock inspection to return a BLOCK
    with patch.object(proxy, "_inspect_message") as mock_inspect:
        from core.models import InspectionResult
        mock_inspect.return_value = InspectionResult.block(
            reason="Path traversal unauthorized",
            layer=1
        )
        
        # Run pump
        await proxy._pump_agent_to_server()
        
    # VERIFY: 
    # 1. _write_to_server was called (meaning it was allowed through)
    assert proxy._write_to_server.called
    # 2. _write_to_agent was NOT called with an error response (block response)
    # The current logic writes the tool call to server, but NEVER sends an error to agent.
    for call in proxy._write_to_agent.call_args_list:
        data = json.loads(call.args[0])
        assert "error" not in data
        
    # 3. Stats reflect shadow block
    assert proxy._stats.get("shadow_blocked", 0) == 1
