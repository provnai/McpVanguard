import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch

from core.proxy import VanguardProxy, ProxyConfig
from core.session import SessionState

@pytest.mark.asyncio
async def test_enrich_tool_list_hides_management_tools_by_default():
    """Management tools should stay hidden unless the operator explicitly enables them."""
    proxy = VanguardProxy(server_command=["python", "-c", "pass"])

    mock_tools = [
        {"name": "read_file", "description": "Read a file"},
        {"name": "write_to_disk", "description": "Write something"},
        {"name": "unknown_tool", "description": "No prefix"}
    ]

    enriched = proxy._enrich_tool_list(mock_tools)

    assert all(not t["name"].startswith("vanguard_") for t in enriched)

    # Check Hints
    for t in enriched:
        name = t["name"]
        if name == "read_file":
            assert t["readOnlyHint"] is True
            assert t["title"] == "Read File"
        elif name == "write_to_disk":
            assert t["destructiveHint"] is True
            assert t["title"] == "Write To Disk"
        elif name == "unknown_tool":
            assert t["readOnlyHint"] is True # Default
            assert t["title"] == "Unknown Tool"


@pytest.mark.asyncio
async def test_enrich_tool_list_includes_management_tools_when_enabled():
    config = ProxyConfig()
    config.management_tools_enabled = True
    proxy = VanguardProxy(server_command=["python", "-c", "pass"], config=config)

    enriched = proxy._enrich_tool_list([{"name": "read_file", "description": "Read a file"}])

    vanguard_names = [t["name"] for t in enriched if t["name"].startswith("vanguard_") or t["name"].startswith("get_vanguard_")]
    assert "get_vanguard_status" in [t["name"] for t in enriched]
    assert "vanguard_apply_rule" in vanguard_names
    apply_rule = next(t for t in enriched if t["name"] == "vanguard_apply_rule")
    assert apply_rule["destructiveHint"] is True
    assert apply_rule["title"] == "Vanguard: Hot-Patch Rule"

@pytest.mark.asyncio
async def test_proxy_intercepts_vanguard_tools():
    """Check if the logic would call management handler for vanguard_ tools."""
    config = ProxyConfig()
    config.management_tools_enabled = True

    request = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "vanguard_reset_session", "arguments": {}}
    }).encode("utf-8")

    class Reader:
        def __init__(self):
            self.lines = [request, b""]

        async def readline(self):
            return self.lines.pop(0)

    proxy = VanguardProxy(server_command=["python", "-c", "pass"], config=config, agent_reader=Reader(), agent_writer=AsyncMock())
    proxy._session = SessionState(session_id="proxy-mgmt")
    proxy._write_to_agent = AsyncMock()

    with patch("core.management.handle_vanguard_tool", new=AsyncMock(return_value={"content": [{"type": "text", "text": "ok"}]})) as mock_handle:
        await proxy._pump_agent_to_server()

    mock_handle.assert_awaited_once()
    context = mock_handle.await_args.kwargs["context"]
    assert context.session_id == "proxy-mgmt"
    assert context.log_file == config.log_file
    proxy._write_to_agent.assert_awaited_once()


@pytest.mark.asyncio
async def test_proxy_blocks_management_tools_when_disabled():
    config = ProxyConfig()
    config.management_tools_enabled = False

    request = json.dumps({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "vanguard_reset_session", "arguments": {}}
    }).encode("utf-8")

    class Reader:
        def __init__(self):
            self.lines = [request, b""]

        async def readline(self):
            return self.lines.pop(0)

    proxy = VanguardProxy(server_command=["python", "-c", "pass"], config=config, agent_reader=Reader(), agent_writer=AsyncMock())
    proxy._session = SessionState(session_id="proxy-mgmt")
    proxy._write_to_agent = AsyncMock()
    proxy.audit.info = MagicMock()

    with patch("core.management.handle_vanguard_tool", new=AsyncMock()) as mock_handle:
        await proxy._pump_agent_to_server()

    mock_handle.assert_not_awaited()
    proxy._write_to_agent.assert_awaited_once()
    response = json.loads(proxy._write_to_agent.await_args.args[0])
    assert response["id"] == 7
    assert response["error"]["data"]["rule"] == "VANGUARD-MGMT-DISABLED"
    proxy.audit.info.assert_called_once()
    assert "Management tools are disabled" in proxy.audit.info.call_args.args[0]
