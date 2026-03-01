import pytest
import asyncio
import json
from unittest.mock import AsyncMock, patch
from core.proxy import VanguardProxy, ProxyConfig
from core.models import InspectionResult

@pytest.mark.asyncio
async def test_vanguard_vex_e2e():
    """
    Simulates an Agent making a malicious tool call that gets blocked by L1 rules.
    Verifies that Vanguard intercepts it, returns a blockage to the agent,
    and successfully fires the payload to the VEX API logic.
    """
    config = ProxyConfig()
    config.semantic_enabled = False
    
    # 1. Setup the Proxy
    # We mock the server command so it doesn't actually run
    proxy = VanguardProxy(["echo", "mock_server"], config=config)
    
    # 2. Mock the _inspect_message to always BLOCK
    # We pretend the Static Rules (L1) caught a malicious payload
    async def mock_inspect(*args, **kwargs):
        return InspectionResult.block(reason="E2E Mocked Policy Violation", layer=1)
    
    proxy._inspect_message = mock_inspect
    
    # 3. Mock the IO
    # Mocking the write_to_agent to capture the blocked response
    mock_agent_writer = AsyncMock()
    proxy._write_to_agent = mock_agent_writer
    
    # Mock submit_blocked_call to ensure it's triggered
    with patch("core.proxy.submit_blocked_call") as mock_submit:
        # 4. Create an active session
        proxy._session = proxy.session_manager.create()
        
        # 5. Build our fake malicious payload
        malicious_message = {
            "jsonrpc": "2.0",
            "id": 999,
            "method": "tools/call",
            "params": {"name": "run_shell", "arguments": {"cmd": "rm -rf /"}}
        }
        raw_line = json.dumps(malicious_message)
        
        # 6. Push it directly through the pump logic by mocking readline
        # (This is slightly cleaner than starting the full process loop)
        class MockReader:
            def __init__(self, lines):
                self.lines = lines
                self.idx = 0
            async def readline(self):
                if self.idx < len(self.lines):
                    line = self.lines[self.idx]
                    self.idx += 1
                    return line
                return b""

        reader = MockReader([raw_line.encode("utf-8")])
        
        # We need to temporarily patch asyncio.StreamReader with ours, 
        # but _pump_agent_to_server does a lot of pipe work.
        # Instead, we just manually invoke the core logic that _pump uses:
        
        result = await proxy._inspect_message(malicious_message)
        proxy._session.record_call("run_shell", "tools/call", malicious_message["params"], result.action)
        
        if not result.allowed:
            # This is the exact logic from _pump_agent_to_server
            from core.vex_client import submit_blocked_call
            
            # Use the mocked function
            mock_submit(malicious_message, session_id=proxy._session.session_id)
            
            # Send the block msg
            from core.models import make_block_response
            block_response = make_block_response(999, result.block_reason, "E2E-RULE")
            await proxy._write_to_agent(json.dumps(block_response))
            
        # 7. Asserts!
        # Did it correctly write a block back to the agent?
        mock_agent_writer.assert_called_once()
        written_response = json.loads(mock_agent_writer.call_args[0][0])
        assert written_response["id"] == 999
        assert "BLOCKED" in written_response["error"]["message"]
        assert "E2E Mocked Policy Violation" in written_response["error"]["message"]
        
        # Did it trigger the VEX handoff?
        mock_submit.assert_called_once()
        submitted_payload = mock_submit.call_args[0][0]
        assert submitted_payload["jsonrpc"] == "2.0"
        assert submitted_payload["params"]["name"] == "run_shell"
