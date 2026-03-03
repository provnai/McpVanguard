import asyncio
import httpx
import json
import sys

async def test_remote_vanguard(base_url: str):
    base_url = base_url.rstrip("/")
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"
        
    sse_url = f"{base_url}/sse"
    print(f"🌍 Connecting to Vanguard SSE interface at: {sse_url}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            async with client.stream("GET", sse_url, follow_redirects=True) as response:
                print(f"✅ Connected! Status: {response.status_code}\n")
                
                post_endpoint = None
                current_event = None

                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    
                    if line.startswith("event:"):
                        current_event = line[6:].strip()
                        continue
                        
                    if line.startswith("data:"):
                        data = line[5:].strip()
                        
                        if current_event == "endpoint":
                            post_endpoint = data
                            print(f"🔗 Received session endpoint: {post_endpoint}")
                            
                            full_post_url = f"{base_url}{post_endpoint}"
                            payload = {
                                "jsonrpc": "2.0",
                                "id": "val-test-post-fix",
                                "method": "tools/call",
                                "params": {
                                    "name": "read_file",
                                    "arguments": {"path": "/etc/shadow"}
                                }
                            }
                            
                            async def send_malicious_request():
                                await asyncio.sleep(1)
                                print(f"\n🕵️‍♂️ Attempting Path Traversal Attack -> {payload['params']['name']} {payload['params']['arguments']['path']}")
                                post_resp = await client.post(
                                    full_post_url,
                                    content=json.dumps(payload) + "\n",
                                    headers={"Content-Type": "application/json"}
                                )
                                print(f"📩 POST Request Sent. Status: {post_resp.status_code}")
                            
                            asyncio.create_task(send_malicious_request())
                            current_event = None
                            
                        elif data.startswith("{"):
                            try:
                                msg = json.loads(data)
                                print("\n🛡️ Vanguard Response Received:")
                                print(json.dumps(msg, indent=2))
                                
                                if "error" in msg:
                                    print("\n🟢 SUCCESS: Attack was successfully blocked and response streamed back!")
                                    # Wait a tiny bit for any potential back-end errors to appear in logs
                                    await asyncio.sleep(2)
                                    break 
                            except Exception:
                                print(f"Raw data: {data}")
                                
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://mcpvanguard-production.up.railway.app"
    try:
        asyncio.run(test_remote_vanguard(url))
    except KeyboardInterrupt:
        pass
