import asyncio
import json
import sys
from pathlib import Path

from core import active_probing


SERVER_SCRIPT = """
import json
import sys

TOOLS = [
    {
        "name": "get_status",
        "description": "Return a static status payload.",
        "annotations": {
            "readOnlyHint": True,
            "idempotentHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
        "inputSchema": {"type": "object"},
    },
    {
        "name": "mutate_state",
        "description": "Pretend to mutate internal state.",
        "annotations": {
            "readOnlyHint": False,
            "idempotentHint": False,
            "destructiveHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {"type": "object"},
    },
]

for raw in sys.stdin:
    if not raw.strip():
        continue
    msg = json.loads(raw)
    method = msg.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "protocolVersion": msg["params"]["protocolVersion"],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mock-probe-server", "version": "1.0.0"},
            }
        }), flush=True)
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"tools": TOOLS},
        }), flush=True)
    elif method == "tools/call":
        name = msg["params"]["name"]
        if name == "get_status":
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {"content": [{"type": "text", "text": "ok"}]},
            }), flush=True)
        elif name == "mutate_state":
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {"content": [{"type": "text", "text": "mutated"}]},
            }), flush=True)
        else:
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "error": {"code": -32601, "message": "Tool not found"},
            }), flush=True)
"""


def _write_mock_server(tmp_path: Path) -> Path:
    script_path = tmp_path / "mock_probe_server.py"
    script_path.write_text(SERVER_SCRIPT, encoding="utf-8")
    return script_path


def test_run_active_probes_passes_for_explicit_read_only_probe(tmp_path):
    script_path = _write_mock_server(tmp_path)
    probe_manifest = {
        "version": 1,
        "protocolVersion": "2025-11-25",
        "probes": [
            {
                "probe_id": "status-probe",
                "tool": "get_status",
                "arguments": {},
                "safety_class": "read_only_idempotent",
                "expect_success": True,
            }
        ],
    }

    report = asyncio.run(
        active_probing.run_active_probes(
            [sys.executable, str(script_path)],
            probe_manifest,
            timeout_secs=5.0,
        )
    )

    assert report.passed is True
    assert report.tool_count == 2
    assert report.results[0].probe_id == "status-probe"
    assert report.results[0].passed is True


def test_run_active_probes_rejects_unsafe_probe_before_calling_tool(tmp_path):
    script_path = _write_mock_server(tmp_path)
    probe_manifest = {
        "version": 1,
        "protocolVersion": "2025-11-25",
        "probes": [
            {
                "probe_id": "mutate-probe",
                "tool": "mutate_state",
                "arguments": {},
                "safety_class": "read_only_idempotent",
                "expect_success": True,
            }
        ],
    }

    report = asyncio.run(
        active_probing.run_active_probes(
            [sys.executable, str(script_path)],
            probe_manifest,
            timeout_secs=5.0,
        )
    )

    assert report.passed is False
    assert report.results[0].passed is False
    assert "readOnlyHint=true" in report.results[0].reason
