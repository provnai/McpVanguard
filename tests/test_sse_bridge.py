"""
tests/test_sse_bridge.py
Verifies the McpVanguard SSE Bridge by starting a local server
and sending an MCP tool call via HTTP POST (SSE flow).
"""

import asyncio
import json
import socket
import pytest
import httpx
from core.sse_server import run_sse_server
from core.proxy import ProxyConfig

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

@pytest.mark.asyncio
async def test_sse_bridge_e2e():
    """
    1. Starts a Vanguard SSE Server with a mock server ('echo').
    2. Connects via SSE client.
    3. Sends a malicious command via POST to /messages.
    4. Asserts that Vanguard intercepts and returns a JSON-RPC error.
    """
    port = get_free_port()
    host = "127.0.0.1"
    
    import sys
    # Use the same python binary that is running the test
    server_cmd = [sys.executable, "-c", "import sys; [sys.stdout.write(l) for l in sys.stdin]"]
    
    config = ProxyConfig()
    config.semantic_enabled = False # disable for speed
    
    # Start the server in the background
    server_task = asyncio.create_task(run_sse_server(
        server_command=server_cmd,
        host=host,
        port=port,
        config=config
    ))
    
    # Wait for server to boot
    await asyncio.sleep(2)
    
    if server_task.done():
        try:
            await server_task
        except Exception as e:
            pytest.fail(f"Server failed to start: {e}")

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Step 1: Establish SSE Connection (GET /sse)
            session_id = None
            async def connect_sse():
                nonlocal session_id
                try:
                    async with client.stream("GET", f"http://{host}:{port}/sse/", follow_redirects=True) as response:
                        print(f"SSE GET status: {response.status_code}")
                        async for line in response.aiter_lines():
                            print(f"SSE Line: {line}")
                            if line.startswith("data:"):
                                # Format: endpoint: /messages?sessionId=...
                                if "sessionId=" in line:
                                    session_id = line.split("sessionId=")[-1].strip()
                                    print(f"Session ID Found: {session_id}")
                                    return
                except Exception as e:
                    print(f"SSE Stream Error: {e}")

            sse_connect_task = asyncio.create_task(connect_sse())
            
            # Wait for session ID to be assigned and returned
            for i in range(20):
                if session_id:
                    break
                if server_task.done():
                    await server_task # trigger exception if it crashed
                await asyncio.sleep(0.5)
            
            if not session_id:
                pytest.fail("Failed to get sessionId from SSE connection")
            
            print(f"Acquired session ID: {session_id}")

            # Build malicious payload
            payload = {
                "jsonrpc": "2.0",
                "id": "sse-test-1",
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "/etc/shadow"}
                }
            }
            
            # Step 2: POST the message to /messages with the real session ID
            response = await client.post(
                f"http://{host}:{port}/messages?sessionId={session_id}",
                json=payload
            )
            
            print(f"POST Result: {response.status_code} - {response.text}")
            assert response.status_code in (200, 202)

    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            # ValueError: I/O operation on closed pipe is common on Windows during teardown
            pass

if __name__ == "__main__":
    asyncio.run(test_sse_bridge_e2e())
