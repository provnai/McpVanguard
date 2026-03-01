"""
core/sse_server.py
The SSE bridge for McpVanguard.
Allows the proxy to receive tool calls over the internet (Railway/Docker).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse
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
        """Write to the transport stream (async handled by drain)."""
        self._pending_write = data

    async def drain(self):
        """Send the data over the transport."""
        if hasattr(self, "_pending_write"):
            await self.write_stream.send(self._pending_write)
            del self._pending_write

async def run_sse_server(
    server_command: list[str],
    host: str = "0.0.0.0",
    port: int = 8080,
    config: Optional[ProxyConfig] = None
):
    """
    Run an ASGI server (Starlette) that hosts the MCP SSE transport.
    Incoming RPC calls are piped through the VanguardProxy.
    """
    logger.info(f"🚀 Starting Vanguard SSE Bridge on {host}:{port}")
    
    # We create a single shared logic instance, but each SSE connection
    # might need its own pump? 
    # For simplicity in MVP: 1 connection = 1 proxy session.
    
    sse_transport = SseServerTransport("/messages")

    async def handle_sse(scope, receive, send):
        """Raw ASGI handler for SSE."""
        try:
            async with sse_transport.connect_sse(
                scope, receive, send
            ) as (read_stream, write_stream):
                # Wrap the streams for our Proxy
                bridge = StreamWrapper(read_stream, write_stream)
                
                # Start the Vanguard Proxy with this transport
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
            # Don't raise here for ASGI to avoid double logging
            # but we could send a 500 if we haven't started sending SSE

    async def handle_messages(request: Request):
        try:
            await sse_transport.handle_post_message(request.scope, request.receive, request.send)
        except Exception as e:
            logger.error(f"Post Message Error: {e}", exc_info=True)
            raise

    app = Starlette(
        debug=True,
        routes=[
            Mount("/sse", app=handle_sse),
            Route("/messages", endpoint=handle_messages, methods=["POST"]),
        ]
    )

    import uvicorn
    # Use uvicorn to run the Starlette app
    # uvicorn.run(app, host=host, port=port)
    config_uv = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config_uv)
    await server.serve()
