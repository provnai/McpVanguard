"""The bundled synthetic upstream must run with the declared MCP SDK v2."""

import asyncio
import subprocess
import sys

import mcp.types as types

from core.demo_mcp import create_demo_server, create_sse_demo_app
from core.demo_verify import verify_demo


def test_demo_registers_sdk_v2_handlers_and_tools():
    server = create_demo_server()
    entry = server.get_request_handler("tools/list")
    assert entry is not None
    result = asyncio.run(entry.handler(None, None))
    assert {tool.name for tool in result.tools} >= {"read_file", "fetch_url"}
    for tool in result.tools:
        assert tool.input_schema["type"] == "object"


def test_demo_safe_read_and_unknown_tool_error():
    handler = create_demo_server().get_request_handler("tools/call").handler
    result = asyncio.run(handler(None, types.CallToolRequestParams(
        name="read_file", arguments={"path": "/docs/readme.txt"},
    )))
    assert not result.is_error
    assert "secure MCP demo" in result.content[0].text
    unknown = asyncio.run(handler(None, types.CallToolRequestParams(name="unknown", arguments={})))
    assert unknown.is_error
    invalid = asyncio.run(handler(None, types.CallToolRequestParams(name="read_file", arguments={})))
    assert invalid.is_error


def test_demo_sse_application_constructs_with_sdk_v2():
    app = create_sse_demo_app()
    assert {route.path for route in app.routes} >= {"/sse", "/health"}


def test_demo_stdio_raw_and_guarded_end_to_end():
    result = verify_demo()
    assert result["scope"] == "synthetic-only"
    assert all(session["passed"] for session in result["sessions"])


def test_verifier_rejects_failed_condition_with_python_optimization():
    result = subprocess.run(
        [sys.executable, "-O", "-c",
         "from core.demo_verify import _require; _require(False, 'invalid demo result')"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "invalid demo result" in result.stderr
