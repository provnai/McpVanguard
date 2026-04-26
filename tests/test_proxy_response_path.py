import asyncio
import json
import logging
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.behavioral import clear_state, get_state
from core.models import InspectionResult, RuleMatch
from core.proxy import ProxyConfig, VanguardProxy
from core.session import SessionState
from core.session_isolation import derive_server_id


class _CapturingWriter:
    def __init__(self):
        self.chunks = []

    def write(self, data: bytes):
        self.chunks.append(data)

    async def drain(self):
        return None


@pytest.fixture(autouse=True)
def clean_audit_logger():
    audit = logging.getLogger("vanguard.audit")
    for handler in list(audit.handlers):
        audit.removeHandler(handler)
        handler.close()
    yield
    for handler in list(audit.handlers):
        audit.removeHandler(handler)
        handler.close()


@pytest.mark.asyncio
async def test_blocked_response_returns_jsonrpc_error():
    config = ProxyConfig()
    config.behavioral_enabled = True
    config.expose_block_reason = True

    proxy = VanguardProxy(server_command=["dummy"], config=config)
    proxy._session = SessionState(session_id="resp-block")
    proxy._write_to_agent = AsyncMock()

    stdout = MagicMock()
    stdout.readline = AsyncMock(side_effect=[
        b'{"jsonrpc":"2.0","id":1,"result":{"content":"secret"}}\n',
        b'',
    ])
    proxy._server_process = MagicMock()
    proxy._server_process.stdout = stdout

    resp_result = InspectionResult.block(
        reason="response blocked",
        layer=3,
        rule_matches=[RuleMatch(rule_id="BEH-006", severity="CRITICAL")],
    )

    with patch("core.behavioral.inspect_response", new=AsyncMock(return_value=resp_result)):
        await proxy._pump_server_to_agent()

    proxy._write_to_agent.assert_awaited_once()
    payload = json.loads(proxy._write_to_agent.await_args.args[0])
    assert payload["id"] == 1
    assert payload["error"]["data"]["rule"] == "BEH-006"
    assert "response blocked" in payload["error"]["message"].lower()


@pytest.mark.asyncio
async def test_throttled_response_preserves_single_frame():
    config = ProxyConfig()
    config.behavioral_enabled = True

    proxy = VanguardProxy(server_command=["dummy"], config=config)
    proxy._session = SessionState(session_id="resp-throttle")
    writer = _CapturingWriter()
    proxy.agent_writer = writer

    line = b'{"jsonrpc":"2.0","id":1,"result":{"content":"' + (b"x" * 2500) + b'"}}\n'
    stdout = MagicMock()
    stdout.readline = AsyncMock(side_effect=[line, b""])
    proxy._server_process = MagicMock()
    proxy._server_process.stdout = stdout

    # Phase 6: proxy derives server_id from its command; we must use the same key
    _server_id = derive_server_id(["dummy"])
    state = get_state("resp-throttle", _server_id)
    state.is_throttled = True
    state.entropy_bucket.tokens = 0
    state.entropy_bucket.last_update = time.monotonic()

    with patch("core.behavioral.inspect_response", new=AsyncMock(return_value=None)), \
         patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
        await proxy._pump_server_to_agent()

    clear_state("resp-throttle", _server_id)

    assert mock_sleep.await_count == 1
    assert len(writer.chunks) == 1
    assert writer.chunks[0] == line


@pytest.mark.asyncio
async def test_capability_drift_warns_on_tools_list_response(tmp_path):
    config = ProxyConfig()
    config.capability_manifest_policy = "warn"
    config.capability_manifest_file = str(tmp_path / "capability-manifest.json")

    expected_manifest = {
        "version": 1,
        "initialize": None,
        "tools": {
            "count": 1,
            "tools": [
                {
                    "name": "read_file",
                    "title": None,
                    "description_sha256": "old",
                    "annotations": {},
                    "inputSchema": {},
                    "inputSchema_sha256": "old-schema",
                }
            ],
            "tools_sha256": "old-tools",
        },
    }
    Path(config.capability_manifest_file).write_text(json.dumps(expected_manifest), encoding="utf-8")

    proxy = VanguardProxy(server_command=["dummy"], config=config)
    proxy._session = SessionState(session_id="cap-warn")
    proxy.audit.info = MagicMock()
    proxy._pending_tool_lists.add(1)
    proxy._expected_capability_manifest = expected_manifest

    stdout = MagicMock()
    stdout.readline = AsyncMock(side_effect=[
        b'{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"write_file","description":"Write a file."}]}}\n',
        b'',
    ])
    proxy._server_process = MagicMock()
    proxy._server_process.stdout = stdout
    proxy._write_to_agent = AsyncMock()

    with patch("core.behavioral.inspect_response", new=AsyncMock(return_value=None)):
        await proxy._pump_server_to_agent()

    proxy._write_to_agent.assert_awaited_once()
    forwarded = json.loads(proxy._write_to_agent.await_args.args[0])
    assert forwarded["result"]["tools"][0]["name"] == "write_file"
    assert proxy.audit.info.call_count >= 1
    assert any("Upstream capability drift detected in tools" in call.args[0] for call in proxy.audit.info.call_args_list)


@pytest.mark.asyncio
async def test_capability_drift_blocks_initialize_response(tmp_path):
    config = ProxyConfig()
    config.capability_manifest_policy = "block"
    config.capability_manifest_file = str(tmp_path / "capability-manifest.json")

    expected_manifest = {
        "version": 1,
        "initialize": {
            "protocolVersion": "2025-03-26",
            "serverInfo": {"name": "demo", "version": "1.0.0"},
            "capabilities": {"tools": {"listChanged": True}},
            "capabilities_sha256": "expected-capabilities",
            "instructions_sha256": None,
        },
        "tools": None,
    }
    Path(config.capability_manifest_file).write_text(json.dumps(expected_manifest), encoding="utf-8")

    proxy = VanguardProxy(server_command=["dummy"], config=config)
    proxy._session = SessionState(session_id="cap-block")
    proxy._expected_capability_manifest = expected_manifest
    proxy._pending_initializations.add("init-1")
    proxy._write_to_agent = AsyncMock()

    stdout = MagicMock()
    stdout.readline = AsyncMock(side_effect=[
        b'{"jsonrpc":"2.0","id":"init-1","result":{"protocolVersion":"2025-03-26","capabilities":{"resources":{}},"serverInfo":{"name":"demo","version":"1.0.0"}}}\n',
        b'',
    ])
    proxy._server_process = MagicMock()
    proxy._server_process.stdout = stdout

    with patch("core.behavioral.inspect_response", new=AsyncMock(return_value=None)):
        await proxy._pump_server_to_agent()

    proxy._write_to_agent.assert_awaited_once()
    payload = json.loads(proxy._write_to_agent.await_args.args[0])
    assert payload["id"] == "init-1"
    assert payload["error"]["data"]["rule"] == "VANGUARD-CAPABILITY-DRIFT"
