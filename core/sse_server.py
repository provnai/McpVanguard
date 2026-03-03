"""
core/sse_server.py
The SSE bridge for McpVanguard.
"""

from __future__ import annotations

import asyncio
import logging
import json
import sys
from typing import Optional

from mcp.server.sse import SseServerTransport, SessionMessage
from core.proxy import VanguardProxy, ProxyConfig

logger = logging.getLogger("vanguard.sse")

class StreamWrapper:
    def __init__(self, read_stream, write_stream):
        self.read_stream = read_stream
        self.write_stream = write_stream
        self._buffer = b""

    async def readline(self) -> bytes:
        while True:
            if b"\n" in self._buffer:
                idx = self._buffer.find(b"\n")
                line = self._buffer[:idx+1]
                self._buffer = self._buffer[idx+1:]
                return line

            try:
                msg = await self.read_stream.receive()
                if not msg:
                    return b""
                
                # SseServerTransport yields SessionMessage(message=...)
                if hasattr(msg, "message"):
                    msg = msg.message
                
                chunk = b""
                if hasattr(msg, "model_dump_json"):
                    chunk = msg.model_dump_json().encode("utf-8")
                elif hasattr(msg, "json"):
                    chunk = msg.json().encode("utf-8")
                elif isinstance(msg, dict):
                    chunk = json.dumps(msg).encode("utf-8")
                elif isinstance(msg, bytes):
                    chunk = msg
                else:
                    try:
                        chunk = json.dumps(msg, default=str).encode("utf-8")
                    except Exception:
                        chunk = str(msg).encode("utf-8")
                
                self._buffer += chunk
                
                # Check for balanced JSON object
                stripped = self._buffer.strip()
                if stripped.startswith(b"{") and stripped.endswith(b"}"):
                    line = self._buffer
                    if not line.endswith(b"\n"):
                        line += b"\n"
                    self._buffer = b""
                    return line
            except Exception as e:
                logger.debug(f"StreamWrapper read error: {e}")
                return b""

    def write(self, data: bytes):
        self._pending_write = data

    async def drain(self):
        if hasattr(self, "_pending_write"):
            try:
                raw_str = self._pending_write.decode("utf-8", errors="replace").strip()
                try:
                    obj = json.loads(raw_str)
                    from mcp.types import JSONRPCMessage
                    # Proper MCP SDK serialization
                    msg_obj = SessionMessage(message=JSONRPCMessage.model_validate(obj))
                    await self.write_stream.send(msg_obj)
                except Exception:
                    # Fallback for non-JSON or other errors
                    await self.write_stream.send(raw_str)
            except Exception as e:
                logger.error(f"StreamWrapper drain error: {e}")
            finally:
                if hasattr(self, "_pending_write"):
                    del self._pending_write

async def run_sse_server(
    server_command: list[str],
    host: str = "0.0.0.0",
    port: int = 8080,
    config: Optional[ProxyConfig] = None
):
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.responses import Response

    print(f"Starting Vanguard SSE Bridge on {host}:{port}")
    sse_transport = SseServerTransport("/messages")

    async def handle_sse(scope, receive, send):
        assert scope["type"] == "http"
        async with sse_transport.connect_sse(scope, receive, send) as (read_stream, write_stream):
            bridge = StreamWrapper(read_stream, write_stream)
            proxy = VanguardProxy(
                server_command=server_command,
                config=config,
                agent_reader=bridge,
                agent_writer=bridge
            )
            await proxy.run()

    async def handle_messages(scope, receive, send):
        assert scope["type"] == "http"
        await sse_transport.handle_post_message(scope, receive, send)

    class AsgiAppWrapper:
        def __init__(self, func):
            self.func = func
        async def __call__(self, scope, receive, send):
            await self.func(scope, receive, send)

    app = Starlette(
        debug=False,
        routes=[
            Route("/sse", endpoint=AsgiAppWrapper(handle_sse), methods=["GET"]),
            Route("/messages", endpoint=AsgiAppWrapper(handle_messages), methods=["POST"]),
        ]
    )


    import uvicorn
    config_uv = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config_uv)
    await server.serve()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        asyncio.run(run_sse_server(sys.argv[1:]))
    else:
        asyncio.run(run_sse_server([sys.executable, "-c", "import sys; [sys.stdout.write(l) for l in sys.stdin]"]))
