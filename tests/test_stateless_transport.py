"""Isolated tests for the opt-in stateless transport migration seam."""

from __future__ import annotations

import asyncio
import json
import sys
import textwrap
from importlib.metadata import version

import httpx
import pytest
from core.proxy import ProxyConfig
from core.sse_server import VanguardStreamableSessionManager, run_sse_server


def _sdk_protocol_version() -> str:
    return "2026-07-28" if int(version("mcp").split(".", 1)[0]) >= 2 else "2025-11-25"


def _modern_sdk_available() -> bool:
    return int(version("mcp").split(".", 1)[0]) >= 2


def _server_command() -> list[str]:
    script = textwrap.dedent(
        """
        import json
        import sys

        for line in sys.stdin:
            message = json.loads(line)
            if message.get("method") == "tools/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {"tools": []},
                }
                sys.stdout.write(json.dumps(response) + "\\n")
                sys.stdout.flush()
        """
    )
    return [sys.executable, "-u", "-c", script]


@pytest.mark.asyncio
async def test_stateless_manager_processes_one_request_without_session_state():
    config = ProxyConfig()
    config.semantic_enabled = False
    manager = VanguardStreamableSessionManager(
        server_command=_server_command(),
        config=config,
        stateless=True,
        request_config={},
    )
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "stateless-1",
            "method": "tools/list",
        }
    ).encode("utf-8")
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [
            (b"accept", b"application/json, text/event-stream"),
            (b"content-type", b"application/json"),
            (b"mcp-protocol-version", _sdk_protocol_version().encode("ascii")),
            (b"mcp-method", b"tools/list"),
        ],
    }
    messages: list[dict] = []
    received = False

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    try:
        await manager.handle_request(scope, receive, send)
    finally:
        await manager.shutdown()

    assert messages[0]["type"] == "http.response.start"
    assert messages[0]["status"] == 200, messages
    response_body = b"".join(message.get("body", b"") for message in messages)
    assert "stateless-1" in response_body.decode("utf-8")
    assert manager._stateless_tasks == set()


@pytest.mark.asyncio
async def test_stateless_manager_terminates_upstream_when_request_fails():
    config = ProxyConfig()
    config.semantic_enabled = False
    manager = VanguardStreamableSessionManager(
        server_command=[sys.executable, "-c", "raise SystemExit(2)"],
        config=config,
        stateless=True,
        request_config={},
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [
            (b"accept", b"application/json, text/event-stream"),
            (b"content-type", b"application/json"),
            (b"mcp-protocol-version", _sdk_protocol_version().encode("ascii")),
            (b"mcp-method", b"tools/list"),
        ],
    }
    body = json.dumps({"jsonrpc": "2.0", "id": "stateless-fail", "method": "tools/list"}).encode()
    received = False

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(_message):
        return None

    try:
        await manager.handle_request(scope, receive, send)
    finally:
        await manager.shutdown()

    assert manager._stateless_tasks == set()


@pytest.mark.asyncio
async def test_stateless_profile_serves_server_discover_without_upstream(monkeypatch):
    monkeypatch.setenv("VANGUARD_MCP_PROTOCOL_PROFILE", "mcp_2026_07_28_stateless")
    config = ProxyConfig()
    config.protocol_profile = "mcp_2026_07_28_stateless"
    ctx_messages: list[dict] = []

    from core.sse_server import ServerContext
    from unittest.mock import MagicMock

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "client": ["127.0.0.1", 1234],
        "headers": [
            (b"accept", b"application/json"),
            (b"content-type", b"application/json"),
            (b"mcp-protocol-version", b"2026-07-28"),
            (b"mcp-method", b"server/discover"),
        ],
    }
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": "discover-1",
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }).encode()
    received = False

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        ctx_messages.append(message)

    cfg = {
        "AUTH_MODE": "none",
        "API_KEY": "",
        "ALLOWED_IPS": [],
        "ALLOWED_ORIGINS": [],
        "REQUIRE_ORIGIN": False,
        "MAX_CONCURRENCY": 5,
        "MAX_GLOBAL_CONNECTIONS": 10,
        "RATE_LIMIT_PER_SEC": 100.0,
        "MAX_BODY_BYTES": 1024 * 1024,
    }
    ctx = ServerContext(
        server_command=_server_command(),
        config=config,
        sse_transport=MagicMock(),
        streamable_manager=MagicMock(),
        cfg=cfg,
    )

    from core.sse_server import handle_mcp

    await handle_mcp(scope, receive, send, ctx)

    assert ctx_messages[0]["status"] == 200
    response = b"".join(item.get("body", b"") for item in ctx_messages)
    decoded = json.loads(response)
    assert decoded["result"]["resultType"] == "complete"
    assert decoded["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "McpVanguard"


@pytest.mark.asyncio
@pytest.mark.skipif(not _modern_sdk_available(), reason="requires MCP SDK v2")
async def test_stateless_profile_works_through_http_with_sdk_v2():
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    config = ProxyConfig()
    config.semantic_enabled = False
    config.protocol_profile = "mcp_2026_07_28_stateless"
    server_task = asyncio.create_task(
        run_sse_server(
            server_command=_server_command(),
            host="127.0.0.1",
            port=port,
            config=config,
        )
    )
    await asyncio.sleep(1.5)
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"http://127.0.0.1:{port}/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": "sdk-v2-stateless",
                    "method": "tools/list",
                    "params": {
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        }
                    },
                },
                headers={
                    "Accept": "application/json",
                    "Mcp-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "tools/list",
                },
            )
        assert response.status_code == 200
        assert response.json()["id"] == "sdk-v2-stateless"
    finally:
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
