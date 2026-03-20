"""
core/sse_server.py
The SSE bridge for McpVanguard.
"""

from __future__ import annotations

import asyncio
import logging
import json
import sys
import hmac
import collections
import os
import time
from typing import Optional, Any

from mcp.server.sse import SseServerTransport, SessionMessage
from core.proxy import VanguardProxy, ProxyConfig

logger = logging.getLogger("vanguard.sse")

class RateLimiter:
    """Simple token-bucket rate limiter."""
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, amount: float = 1.0) -> bool:
        async with self._lock:
            now = time.monotonic()
            passed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + passed * self.rate)
            self.last_update = now
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

_rate_limiters: dict[str, RateLimiter] = {}
_active_connections: dict[str, int] = collections.defaultdict(int)
_total_active_connections: int = 0
_registry_lock = asyncio.Lock()

def _get_sse_config():
    return {
        "API_KEY": os.getenv("VANGUARD_API_KEY", ""),
        "ALLOWED_IPS": os.getenv("VANGUARD_ALLOWED_IPS", "").split(",") if os.getenv("VANGUARD_ALLOWED_IPS") else [],
        "MAX_CONCURRENCY": int(os.getenv("VANGUARD_MAX_CONCURRENT_SSE", "5")),
        "MAX_GLOBAL_CONNECTIONS": int(os.getenv("VANGUARD_MAX_GLOBAL_CONNECTIONS", "50")),
        "RATE_LIMIT_PER_SEC": float(os.getenv("VANGUARD_SSE_RATE_LIMIT", "1.0")),
    }

def _check_auth(scope) -> tuple[bool, str]:
    """Returns (is_authed, error_message). Module-level for testing."""
    cfg = _get_sse_config()
    client_ip = scope.get("client", ["unknown"])[0]
    
    if cfg["ALLOWED_IPS"] and client_ip not in cfg["ALLOWED_IPS"]:
        return False, f"IP {client_ip} not in allowlist."

    if not cfg["API_KEY"]:
        return True, ""

    headers = dict(scope.get("headers", []))
    try:
        api_key = headers.get(b"x-api-key", b"").decode("utf-8")
        bearer = headers.get(b"authorization", b"").decode("utf-8")
    except UnicodeDecodeError:
        return False, "Invalid encoding in authentication headers."

    if bearer.lower().startswith("bearer "):
        bearer = bearer[7:].strip()
    
    ok = hmac.compare_digest(api_key, cfg["API_KEY"]) or hmac.compare_digest(bearer, cfg["API_KEY"])
    return ok, "Unauthorized. Provide valid VANGUARD_API_KEY."

async def _send_error(send, status: int, message: str):
    await send({"type": "http.response.start", "status": status, "headers": [[b"content-type", b"application/json"]]})
    await send({"type": "http.response.body", "body": json.dumps({"error": message}).encode("utf-8")})

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

from dataclasses import dataclass

@dataclass
class ServerContext:
    server_command: list[str]
    config: Optional[ProxyConfig]
    sse_transport: SseServerTransport
    cfg: dict[str, Any]

async def handle_sse(scope, receive, send, ctx: ServerContext):
    global _total_active_connections
    assert scope["type"] == "http"
    authed, err = _check_auth(scope)
    if not authed:
        await _send_error(send, 401 if "Unauthorized" in err else 403, err)
        return

    client_ip = scope.get("client", ["unknown"])[0]

    # Registry operations (Rate Limiter and Concurrency Guard)
    async with _registry_lock:
        if client_ip not in _rate_limiters:
            _rate_limiters[client_ip] = RateLimiter(ctx.cfg["RATE_LIMIT_PER_SEC"], ctx.cfg["MAX_CONCURRENCY"] * 2)
        
        limiter = _rate_limiters[client_ip]
        
        # Concurrency Guard (Global)
        if _total_active_connections >= ctx.cfg["MAX_GLOBAL_CONNECTIONS"]:
            logger.warning("Global connection limit (%d) reached.", ctx.cfg["MAX_GLOBAL_CONNECTIONS"])
            await _send_error(send, 503, "Server too busy. Global connection limit reached.")
            return

        # Concurrency Guard (Per IP)
        if _active_connections[client_ip] >= ctx.cfg["MAX_CONCURRENCY"]:
            await _send_error(send, 429, f"Concurrent connection limit ({ctx.cfg['MAX_CONCURRENCY']}) reached.")
            return

        _active_connections[client_ip] += 1
        _total_active_connections += 1

    # Rate Limiting (consume outside the registry lock to avoid blocking other IPs)
    if not await limiter.consume():
        async with _registry_lock:
            _active_connections[client_ip] -= 1
            _total_active_connections -= 1
        await _send_error(send, 429, "Too Many Requests. Rate limit exceeded.")
        return

    try:
        async with ctx.sse_transport.connect_sse(scope, receive, send) as (read_stream, write_stream):
            bridge = StreamWrapper(read_stream, write_stream)
            proxy = VanguardProxy(
                server_command=ctx.server_command,
                config=ctx.config,
                agent_reader=bridge,
                agent_writer=bridge
            )
            await proxy.run()
    finally:
        async with _registry_lock:
            _active_connections[client_ip] -= 1
            _total_active_connections -= 1

async def handle_messages(scope, receive, send, ctx: ServerContext):
    assert scope["type"] == "http"
    authed, err = _check_auth(scope)
    if not authed:
        await _send_error(send, 401 if "Unauthorized" in err else 403, err)
        return

    client_ip = scope.get("client", ["unknown"])[0]
    
    # Apply the same rate-limiting and concurrency bucket as handle_sse
    async with _registry_lock:
        if client_ip not in _rate_limiters:
            _rate_limiters[client_ip] = RateLimiter(ctx.cfg["RATE_LIMIT_PER_SEC"], ctx.cfg["MAX_CONCURRENCY"] * 2)
        limiter = _rate_limiters[client_ip]
    
    if not await limiter.consume():
        await _send_error(send, 429, "Too Many Requests. Message rate limit exceeded.")
        return

    await ctx.sse_transport.handle_post_message(scope, receive, send)

async def health_check_handler(scope, receive, send):
    """Deep health check for Railway/Cloud readiness."""
    assert scope["type"] == "http"
    
    from core.behavioral import check_redis_health
    from core.semantic import check_semantic_health
    from core import __version__
    import starlette.responses
    
    redis_ok = await check_redis_health()
    semantic_ok = await check_semantic_health()
    
    status = "ok" if redis_ok and semantic_ok else "degraded"
    
    health_data = {
        "status": status,
        "version": __version__,
        "layers": {
            "l1_rules": "ok", 
            "l2_semantic": "ok" if semantic_ok else "unreachable",
            "l3_behavioral": "ok" if redis_ok else "redis_disconnected"
        },
        "timestamp": time.time()
    }
    
    response = starlette.responses.Response(
        json.dumps(health_data), 
        status_code=200 if status == "ok" else 503,
        media_type="application/json"
    )
    await response(scope, receive, send)

async def run_sse_server(
    server_command: list[str],
    host: str = "0.0.0.0",
    port: int = 8080,
    config: Optional[ProxyConfig] = None
):
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.responses import Response

    cfg = _get_sse_config()
    if cfg["API_KEY"]:
        print(f"[Vanguard] SSE authentication ENABLED (VANGUARD_API_KEY is set)")
    else:
        print(f"[Vanguard] WARNING: VANGUARD_API_KEY not set. SSE endpoints are open.")

    print(f"Starting Vanguard SSE Bridge on {host}:{port}")
    sse_transport = SseServerTransport("/messages")
    
    ctx = ServerContext(
        server_command=server_command,
        config=config,
        sse_transport=sse_transport,
        cfg=cfg
    )

    class AsgiAppWrapper:
        def __init__(self, func, ctx=None):
            self.func = func
            self.ctx = ctx
        async def __call__(self, scope, receive, send):
            if self.ctx:
                await self.func(scope, receive, send, self.ctx)
            else:
                await self.func(scope, receive, send)

    app = Starlette(
        debug=False,
        routes=[
            Route("/sse", endpoint=AsgiAppWrapper(handle_sse, ctx), methods=["GET"]),
            Route("/messages", endpoint=AsgiAppWrapper(handle_messages, ctx), methods=["POST"]),
            Route("/health", endpoint=health_check_handler, methods=["GET"]),
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
