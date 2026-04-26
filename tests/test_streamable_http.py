import asyncio
import json
import socket
import sys
import textwrap

import httpx
import pytest

from core.proxy import ProxyConfig
from core.sse_server import run_sse_server


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
def _reset_streamable_http_env(monkeypatch):
    for key in (
        "VANGUARD_DEFAULT_POLICY",
        "VANGUARD_BIND_STREAMABLE_SESSIONS",
        "VANGUARD_TRUST_PROXY_HEADERS",
        "VANGUARD_TRUSTED_PROXY_IPS",
    ):
        monkeypatch.delenv(key, raising=False)


@pytest.mark.asyncio
async def test_streamable_http_mcp_endpoint_blocks_and_issues_session_id():
    port = get_free_port()
    host = "127.0.0.1"
    server_script = textwrap.dedent(
        """
        import json
        import sys

        for line in sys.stdin:
            msg = json.loads(line)
            method = msg.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "test-server", "version": "1.0.0"},
                }
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}) + "\\n")
                sys.stdout.flush()
            elif method == "tools/call":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"content": [{"type": "text", "text": "ok"}]}}) + "\\n")
                sys.stdout.flush()
        """
    )
    server_cmd = [sys.executable, "-u", "-c", server_script]

    config = ProxyConfig()
    config.semantic_enabled = False

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=config,
        )
    )

    await asyncio.sleep(2)
    if server_task.done():
        try:
            await server_task
        except Exception as exc:
            pytest.fail(f"Server failed to start: {exc}")

    initialize_payload = {
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"},
        },
    }

    blocked_payload = {
        "jsonrpc": "2.0",
        "id": "streamable-test-1",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/etc/shadow"},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream(
                "POST",
                f"http://{host}:{port}/mcp",
                content=json.dumps(initialize_payload),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            ) as response:
                assert response.status_code == 200
                session_id = response.headers.get("mcp-session-id")
                assert session_id

                init_body_chunks = []
                async for chunk in response.aiter_text():
                    init_body_chunks.append(chunk)
                    if "init-1" in chunk and "result" in chunk:
                        break

                init_body = "".join(init_body_chunks)
                assert "init-1" in init_body
                assert "result" in init_body

            async with client.stream(
                "POST",
                f"http://{host}:{port}/mcp",
                content=json.dumps(blocked_payload),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": session_id,
                    "Mcp-Protocol-Version": "2025-03-26",
                },
            ) as response:
                assert response.status_code == 200

                body_chunks = []
                async for chunk in response.aiter_text():
                    body_chunks.append(chunk)
                    if "streamable-test-1" in chunk and "error" in chunk:
                        break

                body = "".join(body_chunks)
                assert "error" in body
                assert "streamable-test-1" in body
                assert "McpVanguard Blocked" in body
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass


@pytest.mark.asyncio
async def test_streamable_http_rejects_malformed_session_id():
    port = get_free_port()
    host = "127.0.0.1"
    server_cmd = [sys.executable, "-u", "-c", "import sys; [sys.stdout.write(l) for l in sys.stdin]"]

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=ProxyConfig(),
        )
    )

    await asyncio.sleep(2)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"http://{host}:{port}/mcp",
                    content=json.dumps({"jsonrpc": "2.0", "id": "bad-session", "method": "tools/list"}),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                        "Mcp-Session-Id": "bad session",
                        "Mcp-Protocol-Version": "2025-03-26",
                    },
                )

        assert response.status_code == 400
        payload = response.json()
        assert payload["error"]["message"] == "Invalid session ID format"
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass


@pytest.mark.asyncio
async def test_streamable_http_returns_not_found_for_unknown_session_id():
    port = get_free_port()
    host = "127.0.0.1"
    server_cmd = [sys.executable, "-u", "-c", "import sys; [sys.stdout.write(l) for l in sys.stdin]"]

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=ProxyConfig(),
        )
    )

    await asyncio.sleep(2)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"http://{host}:{port}/mcp",
                content=json.dumps({"jsonrpc": "2.0", "id": "missing-session", "method": "tools/list"}),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": "abcdef1234567890abcdef1234567890",
                    "Mcp-Protocol-Version": "2025-03-26",
                },
            )

        assert response.status_code == 404
        payload = response.json()
        assert payload["error"]["message"] == "Session not found"
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass


@pytest.mark.asyncio
async def test_streamable_http_delete_terminates_session_and_reuse_fails():
    port = get_free_port()
    host = "127.0.0.1"
    server_script = textwrap.dedent(
        """
        import json
        import sys

        for line in sys.stdin:
            msg = json.loads(line)
            method = msg.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "test-server", "version": "1.0.0"},
                }
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}) + "\\n")
                sys.stdout.flush()
            elif method == "tools/list":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}}) + "\\n")
                sys.stdout.flush()
        """
    )
    server_cmd = [sys.executable, "-u", "-c", server_script]

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=ProxyConfig(),
        )
    )

    await asyncio.sleep(2)

    initialize_payload = {
        "jsonrpc": "2.0",
        "id": "init-delete-1",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream(
                "POST",
                f"http://{host}:{port}/mcp",
                content=json.dumps(initialize_payload),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            ) as response:
                assert response.status_code == 200
                session_id = response.headers.get("mcp-session-id")
                assert session_id
                async for chunk in response.aiter_text():
                    if "init-delete-1" in chunk and "result" in chunk:
                        break

            delete_response = await client.request(
                "DELETE",
                f"http://{host}:{port}/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": session_id,
                    "Mcp-Protocol-Version": "2025-03-26",
                },
            )
            assert delete_response.status_code == 200

            reuse_response = await client.post(
                f"http://{host}:{port}/mcp",
                content=json.dumps({"jsonrpc": "2.0", "id": "after-delete", "method": "tools/list"}),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": session_id,
                    "Mcp-Protocol-Version": "2025-03-26",
                },
            )
            assert reuse_response.status_code == 404
            payload = reuse_response.json()
            assert payload["error"]["message"] == "Session not found"
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass


@pytest.mark.asyncio
async def test_streamable_http_delete_requires_known_session():
    port = get_free_port()
    host = "127.0.0.1"
    server_cmd = [sys.executable, "-u", "-c", "import sys; [sys.stdout.write(l) for l in sys.stdin]"]

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=ProxyConfig(),
        )
    )

    await asyncio.sleep(2)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                "DELETE",
                f"http://{host}:{port}/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": "abcdef1234567890abcdef1234567890",
                    "Mcp-Protocol-Version": "2025-03-26",
                },
            )

        assert response.status_code == 404
        payload = response.json()
        assert payload["error"]["message"] == "Session not found"
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass


@pytest.mark.asyncio
async def test_streamable_http_rejects_session_reuse_with_different_user_agent():
    port = get_free_port()
    host = "127.0.0.1"
    server_script = textwrap.dedent(
        """
        import json
        import sys

        for line in sys.stdin:
            msg = json.loads(line)
            method = msg.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "test-server", "version": "1.0.0"},
                }
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}) + "\\n")
                sys.stdout.flush()
            elif method == "tools/list":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}}) + "\\n")
                sys.stdout.flush()
        """
    )
    server_cmd = [sys.executable, "-u", "-c", server_script]

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=ProxyConfig(),
        )
    )

    await asyncio.sleep(2)

    initialize_payload = {
        "jsonrpc": "2.0",
        "id": "init-bind-ua",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream(
                "POST",
                f"http://{host}:{port}/mcp",
                content=json.dumps(initialize_payload),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "User-Agent": "pytest-client-a",
                },
            ) as response:
                assert response.status_code == 200
                session_id = response.headers.get("mcp-session-id")
                assert session_id
                async for chunk in response.aiter_text():
                    if "init-bind-ua" in chunk and "result" in chunk:
                        break

            reuse_response = await client.post(
                f"http://{host}:{port}/mcp",
                content=json.dumps({"jsonrpc": "2.0", "id": "bind-ua-reuse", "method": "tools/list"}),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": session_id,
                    "Mcp-Protocol-Version": "2025-03-26",
                    "User-Agent": "pytest-client-b",
                },
            )

        assert reuse_response.status_code == 403
        payload = reuse_response.json()
        assert payload["error"]["message"] == "Session binding mismatch"
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass


@pytest.mark.asyncio
async def test_streamable_http_rejects_session_reuse_with_different_origin():
    port = get_free_port()
    host = "127.0.0.1"
    server_script = textwrap.dedent(
        """
        import json
        import sys

        for line in sys.stdin:
            msg = json.loads(line)
            method = msg.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "test-server", "version": "1.0.0"},
                }
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}) + "\\n")
                sys.stdout.flush()
            elif method == "tools/list":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}}) + "\\n")
                sys.stdout.flush()
        """
    )
    server_cmd = [sys.executable, "-u", "-c", server_script]

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=ProxyConfig(),
        )
    )

    await asyncio.sleep(2)

    initialize_payload = {
        "jsonrpc": "2.0",
        "id": "init-bind-origin",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream(
                "POST",
                f"http://{host}:{port}/mcp",
                content=json.dumps(initialize_payload),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Origin": "https://client-a.example",
                },
            ) as response:
                assert response.status_code == 200
                session_id = response.headers.get("mcp-session-id")
                assert session_id
                async for chunk in response.aiter_text():
                    if "init-bind-origin" in chunk and "result" in chunk:
                        break

            reuse_response = await client.post(
                f"http://{host}:{port}/mcp",
                content=json.dumps({"jsonrpc": "2.0", "id": "bind-origin-reuse", "method": "tools/list"}),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": session_id,
                    "Mcp-Protocol-Version": "2025-03-26",
                    "Origin": "https://client-b.example",
                },
            )

        assert reuse_response.status_code == 403
        payload = reuse_response.json()
        assert payload["error"]["message"] == "Session binding mismatch"
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass


@pytest.mark.asyncio
async def test_streamable_http_can_disable_session_binding_with_env(monkeypatch):
    monkeypatch.setenv("VANGUARD_BIND_STREAMABLE_SESSIONS", "false")
    port = get_free_port()
    host = "127.0.0.1"
    server_script = textwrap.dedent(
        """
        import json
        import sys

        for line in sys.stdin:
            msg = json.loads(line)
            method = msg.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "test-server", "version": "1.0.0"},
                }
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}) + "\\n")
                sys.stdout.flush()
            elif method == "tools/list":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}}) + "\\n")
                sys.stdout.flush()
        """
    )
    server_cmd = [sys.executable, "-u", "-c", server_script]

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=ProxyConfig(),
        )
    )

    await asyncio.sleep(2)

    initialize_payload = {
        "jsonrpc": "2.0",
        "id": "init-bind-disabled",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream(
                "POST",
                f"http://{host}:{port}/mcp",
                content=json.dumps(initialize_payload),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "User-Agent": "pytest-client-a",
                },
            ) as response:
                assert response.status_code == 200
                session_id = response.headers.get("mcp-session-id")
                assert session_id
                async for chunk in response.aiter_text():
                    if "init-bind-disabled" in chunk and "result" in chunk:
                        break

            reuse_response = await client.post(
                f"http://{host}:{port}/mcp",
                content=json.dumps({"jsonrpc": "2.0", "id": "bind-disabled-reuse", "method": "tools/list"}),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": session_id,
                    "Mcp-Protocol-Version": "2025-03-26",
                    "User-Agent": "pytest-client-b",
                },
            )

        assert reuse_response.status_code == 200
        assert "bind-disabled-reuse" in reuse_response.text
        assert "result" in reuse_response.text
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass


@pytest.mark.asyncio
async def test_streamable_http_ignores_forwarded_headers_by_default(monkeypatch):
    monkeypatch.delenv("VANGUARD_TRUST_PROXY_HEADERS", raising=False)
    monkeypatch.delenv("VANGUARD_TRUSTED_PROXY_IPS", raising=False)
    port = get_free_port()
    host = "127.0.0.1"
    server_script = textwrap.dedent(
        """
        import json
        import sys

        for line in sys.stdin:
            msg = json.loads(line)
            method = msg.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "test-server", "version": "1.0.0"},
                }
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}) + "\\n")
                sys.stdout.flush()
            elif method == "tools/list":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}}) + "\\n")
                sys.stdout.flush()
        """
    )
    server_cmd = [sys.executable, "-u", "-c", server_script]

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=ProxyConfig(),
        )
    )

    await asyncio.sleep(2)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream(
                "POST",
                f"http://{host}:{port}/mcp",
                content=json.dumps({
                    "jsonrpc": "2.0",
                    "id": "init-forwarded-default",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "pytest", "version": "1.0"},
                    },
                }),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "X-Forwarded-For": "198.51.100.10",
                },
            ) as response:
                assert response.status_code == 200
                session_id = response.headers.get("mcp-session-id")
                assert session_id
                async for chunk in response.aiter_text():
                    if "init-forwarded-default" in chunk and "result" in chunk:
                        break

            reuse_response = await client.post(
                f"http://{host}:{port}/mcp",
                content=json.dumps({"jsonrpc": "2.0", "id": "forwarded-default-reuse", "method": "tools/list"}),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": session_id,
                    "Mcp-Protocol-Version": "2025-03-26",
                    "X-Forwarded-For": "203.0.113.20",
                },
            )

        assert reuse_response.status_code == 200
        assert "forwarded-default-reuse" in reuse_response.text
        assert "result" in reuse_response.text
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass


@pytest.mark.asyncio
async def test_streamable_http_rejects_reuse_when_trusted_proxy_forwarded_identity_changes(monkeypatch):
    monkeypatch.setenv("VANGUARD_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("VANGUARD_TRUSTED_PROXY_IPS", "127.0.0.1")
    port = get_free_port()
    host = "127.0.0.1"
    server_script = textwrap.dedent(
        """
        import json
        import sys

        for line in sys.stdin:
            msg = json.loads(line)
            method = msg.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "test-server", "version": "1.0.0"},
                }
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}) + "\\n")
                sys.stdout.flush()
            elif method == "tools/list":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}}) + "\\n")
                sys.stdout.flush()
        """
    )
    server_cmd = [sys.executable, "-u", "-c", server_script]

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=ProxyConfig(),
        )
    )

    await asyncio.sleep(2)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream(
                "POST",
                f"http://{host}:{port}/mcp",
                content=json.dumps({
                    "jsonrpc": "2.0",
                    "id": "init-forwarded-trusted",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "pytest", "version": "1.0"},
                    },
                }),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "X-Forwarded-For": "198.51.100.10",
                },
            ) as response:
                assert response.status_code == 200
                session_id = response.headers.get("mcp-session-id")
                assert session_id
                async for chunk in response.aiter_text():
                    if "init-forwarded-trusted" in chunk and "result" in chunk:
                        break

            reuse_response = await client.post(
                f"http://{host}:{port}/mcp",
                content=json.dumps({"jsonrpc": "2.0", "id": "forwarded-trusted-reuse", "method": "tools/list"}),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": session_id,
                    "Mcp-Protocol-Version": "2025-03-26",
                    "X-Forwarded-For": "203.0.113.20",
                },
            )

        assert reuse_response.status_code == 403
        payload = reuse_response.json()
        assert payload["error"]["message"] == "Session binding mismatch"
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass


@pytest.mark.asyncio
async def test_streamable_http_ignores_forwarded_identity_from_untrusted_proxy(monkeypatch):
    monkeypatch.setenv("VANGUARD_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("VANGUARD_TRUSTED_PROXY_IPS", "10.0.0.5")
    port = get_free_port()
    host = "127.0.0.1"
    server_script = textwrap.dedent(
        """
        import json
        import sys

        for line in sys.stdin:
            msg = json.loads(line)
            method = msg.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-03-26"),
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "test-server", "version": "1.0.0"},
                }
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}) + "\\n")
                sys.stdout.flush()
            elif method == "tools/list":
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": []}}) + "\\n")
                sys.stdout.flush()
        """
    )
    server_cmd = [sys.executable, "-u", "-c", server_script]

    server_task = asyncio.create_task(
        run_sse_server(
            server_command=server_cmd,
            host=host,
            port=port,
            config=ProxyConfig(),
        )
    )

    await asyncio.sleep(2)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream(
                "POST",
                f"http://{host}:{port}/mcp",
                content=json.dumps({
                    "jsonrpc": "2.0",
                    "id": "init-forwarded-untrusted",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "pytest", "version": "1.0"},
                    },
                }),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "X-Forwarded-For": "198.51.100.10",
                },
            ) as response:
                assert response.status_code == 200
                session_id = response.headers.get("mcp-session-id")
                assert session_id
                async for chunk in response.aiter_text():
                    if "init-forwarded-untrusted" in chunk and "result" in chunk:
                        break

            reuse_response = await client.post(
                f"http://{host}:{port}/mcp",
                content=json.dumps({"jsonrpc": "2.0", "id": "forwarded-untrusted-reuse", "method": "tools/list"}),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": session_id,
                    "Mcp-Protocol-Version": "2025-03-26",
                    "X-Forwarded-For": "203.0.113.20",
                },
            )

        assert reuse_response.status_code == 200
        assert "forwarded-untrusted-reuse" in reuse_response.text
        assert "result" in reuse_response.text
    finally:
        server_task.cancel()
        try:
            await server_task
        except (asyncio.CancelledError, ValueError):
            pass
