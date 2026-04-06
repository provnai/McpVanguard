import asyncio
import json
import logging
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.behavioral import clear_state, get_state
from core.models import InspectionResult, RuleMatch
from core.proxy import ProxyConfig, VanguardProxy
from core.session import SessionState


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

    state = get_state("resp-throttle")
    state.is_throttled = True
    state.entropy_bucket.tokens = 0
    state.entropy_bucket.last_update = time.monotonic()

    with patch("core.behavioral.inspect_response", new=AsyncMock(return_value=None)), \
         patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
        await proxy._pump_server_to_agent()

    clear_state("resp-throttle")

    assert mock_sleep.await_count == 1
    assert len(writer.chunks) == 1
    assert writer.chunks[0] == line

