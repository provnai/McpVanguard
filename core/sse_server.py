"""
core/sse_server.py
The SSE bridge for McpVanguard.
Allows the proxy to receive tool calls over the internet (Railway/Docker).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from mcp.server.sse import SseServerTransport
from core.proxy import VanguardProxy, ProxyConfig

logger = logging.getLogger("vanguard.sse")

class StreamWrapper:
    """Helper to bridge SseServerTransport streams to VanguardProxy expectations."""
    def __init__(self, read_stream, write_stream):
        self.read_stream = read_stream
        self.write_stream = write_stream
        self._buffer = b""

    async def readline(self) -> bytes:
        """Read a line from the transport stream."""
        while b"\n" not in self._buffer:
            try:
                chunk = await self.read_stream.receive()
                if not chunk:
                    return b""
                self._buffer += chunk
            except Exception:
                return b""
        
        idx = self._buffer.find(b"\n")
        line = self._buffer[:idx+1]
        self._buffer = self._buffer[idx+1:]
        return line

    def write(self, data: bytes):
        """Write to the transport stream."""
        self._pending_write = data

    async def drain(self):
        """Send the data over the transport."""
        if hasattr(self, "_pending_write"):
            try:
                # SseServerTransport manages its own SSE framing 
                # for the underlying ByteSendStream.
                await self.write_stream.send(self._pending_write)
            except Exception as e:
                logger.error(f"SSE Write Error: {e}")
            finally:
                del self._pending_write

async def run_sse_server(
    server_command: list[str],
    host: str = "0.0.0.0",
    port: int = 8080,
    config: Optional[ProxyConfig] = None
):
    """
    Run a raw ASGI server that hosts the MCP SSE transport.
    """
    logger.info(f"🚀 Starting Vanguard SSE Bridge on {host}:{port}")
    
    # Critical: The endpoint URL must match the path used in the POST handler
    sse_transport = SseServerTransport("/messages")

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        
        if scope["type"] != "http":
            return

        # Normalize path
        path = scope["path"].rstrip("/")
        if not path:
            path = "/"

        if path == "/sse" and scope["method"] == "GET":
            try:
                async with sse_transport.connect_sse(scope, receive, send) as (read_stream, write_stream):
                    bridge = StreamWrapper(read_stream, write_stream)
                    proxy = VanguardProxy(
                        server_command=server_command,
                        config=config,
                        agent_reader=bridge,
                        agent_writer=bridge
                    )
                    logger.info("New agent connected via SSE")
                    await proxy.run()
                    logger.info("Agent disconnected")
            except Exception as e:
                logger.error(f"SSE Error: {e}", exc_info=True)
        
        elif path == "/messages" and scope["method"] == "POST":
            try:
                await sse_transport.handle_post_message(scope, receive, send)
            except Exception as e:
                logger.error(f"POST Error: {e}", exc_info=True)
        
        else:
            await send({
                "type": "http.response.start",
                "status": 404,
                "headers": [(b"content-type", b"text/plain")],
            })
            await send({"type": "http.response.body", "body": b"Not Found"})

    import uvicorn
    # Use raw app without Starlette wrapper for maximum protocol fidelity
    config_uv = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config_uv)
    await server.serve()
if __name__ == "__main__":
    import sys
    asyncio.run(run_sse_server([sys.executable, "-c", "import sys; [sys.stdout.write(l) for l in sys.stdin]"]))
