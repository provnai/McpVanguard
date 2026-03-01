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
import sys
import traceback
from core.sse_server import run_sse_server
from core.proxy import ProxyConfig

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

@pytest.mark.asyncio
async def test_sse_bridge_e2e():
    """
    Verifies the bidirectional SSE flow:
    1. Establish persistent SSE stream.
    2. POST a tool call while SSE is open.
    3. Capture the block response via the SSE stream or POST response.
    """
    port = get_free_port()
    host = "127.0.0.1"
    
    server_cmd = [sys.executable, "-c", "import sys; [sys.stdout.write(l) for l in sys.stdin]"]
    
    config = ProxyConfig()
    config.semantic_enabled = False 
    
    server_task = asyncio.create_task(run_sse_server(
        server_command=server_cmd,
        host=host,
        port=port,
        config=config
    ))
    
    await asyncio.sleep(2)
    if server_task.done():
        try:
            await server_task
        except Exception as e:
            pytest.fail(f"Server failed to start: {e}")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            connection_established = asyncio.Event()
            post_url = None
            sse_responses = []
            
            async def run_sse_client():
                nonlocal post_url
                try:
                    async with client.stream("GET", f"http://{host}:{port}/sse", follow_redirects=True) as response:
                        print(f"SSE Connected: {response.status_code}")
                        current_event = None
                        async for line in response.aiter_lines():
                            line = line.strip()
                            if not line: 
                                print("SSE Recv: <empty line>")
                                continue
                            print(f"SSE Recv: {line}")
                            
                            if line.startswith("event:"):
                                current_event = line[6:].strip()
                            elif line.startswith("data:"):
                                data = line[5:].strip()
                                if current_event == "endpoint":
                                    post_url = data
                                    print(f"Captured POST URL: {post_url}")
                                    connection_established.set()
                                    current_event = None
                                else:
                                    # It might be a JSON-RPC response
                                    try:
                                        msg = json.loads(data)
                                        sse_responses.append(msg)
                                        print(f"Captured SSE Message: {msg}")
                                    except:
                                        pass
                except asyncio.CancelledError:
                    print("SSE Client cancelled")
                except Exception as e:
                    print(f"SSE Client Error: {e}")
                    traceback.print_exc()

            client_task = asyncio.create_task(run_sse_client())
            
            # Wait for connection
            try:
                await asyncio.wait_for(connection_established.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                client_task.cancel()
                pytest.fail("Timeout waiting for SSE session ID")
            
            print(f"Using POST URL: {post_url}")
            
            payload = {
                "jsonrpc": "2.0",
                "id": "sse-test-1",
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "/etc/shadow"}
                }
            }
            
            full_post_url = f"http://{host}:{port}{post_url}" if post_url.startswith("/") else post_url
            
            # POST the message with a newline and explicit Content-Type
            print(f"POSTing payload to {full_post_url}")
            post_resp = await client.post(
                full_post_url, 
                content=json.dumps(payload) + "\n",
                headers={"Content-Type": "application/json"}
            )
            print(f"POST Resp: {post_resp.status_code}")
            assert post_resp.status_code in (200, 202)
            
            # Now wait for the response to come back via SSE
            # (In some MCP implementations, the block error might come back via POST response too)
            success = False
            for _ in range(20):
                # Check POST response body
                try:
                    data = post_resp.json()
                    if "error" in data:
                        print("Block received via POST response")
                        success = True
                        break
                except:
                    pass
                
                # Check SSE responses
                if any("error" in r for r in sse_responses):
                    print("Block received via SSE stream")
                    success = True
                    break
                    
                await asyncio.sleep(0.5)
            
            if not success:
                pytest.fail("Failed to receive block response via SSE or POST")

            client_task.cancel()
            try:
                await client_task
            except asyncio.CancelledError:
                pass

    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass

if __name__ == "__main__":
    asyncio.run(test_sse_bridge_e2e())
