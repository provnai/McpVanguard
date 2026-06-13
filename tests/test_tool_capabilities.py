import pytest

from core import behavioral
from core.risk import RiskEngine
from core.tool_capabilities import (
    ToolCapability,
    capabilities_from_manifest,
    capability_values,
    infer_tool_capabilities,
    infer_tool_definition_capabilities,
)


def test_infer_capabilities_from_renamed_file_reader():
    msg = {
        "method": "tools/call",
        "params": {"name": "fetch_document", "arguments": {"target": "/workspace/report.md"}},
    }

    caps = infer_tool_capabilities(msg)

    assert ToolCapability.FILESYSTEM_READ in caps
    assert capability_values(caps) == ["filesystem_read"]


def test_operator_override_can_classify_custom_tool(monkeypatch):
    monkeypatch.setenv("VANGUARD_TOOL_CAPABILITIES_JSON", '{"company_tool": ["network_request"]}')
    msg = {"method": "tools/call", "params": {"name": "company_tool", "arguments": {}}}

    caps = infer_tool_capabilities(msg)

    assert caps == {ToolCapability.NETWORK_REQUEST}


def test_infer_capabilities_from_tool_definition_schema_fields():
    tool = {
        "name": "internal_request",
        "description": "Call an internal service.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Target URL."},
                "headers": {"type": "object"},
            },
        },
    }

    caps = infer_tool_definition_capabilities(tool)

    assert ToolCapability.NETWORK_REQUEST in caps


def test_read_capabilities_from_capability_manifest():
    manifest = {
        "tools": {
            "tools": [
                {
                    "name": "fetch_document",
                    "tool_capabilities": ["filesystem_read", "credential_adjacent"],
                }
            ]
        }
    }

    caps = capabilities_from_manifest(manifest, "fetch_document")

    assert caps == {ToolCapability.FILESYSTEM_READ, ToolCapability.CREDENTIAL_ADJACENT}


def test_missing_manifest_capability_is_unknown():
    assert capabilities_from_manifest({"tools": {"tools": []}}, "missing") == {ToolCapability.UNKNOWN}


@pytest.mark.asyncio
async def test_l3_renamed_read_tool_contributes_to_scraping_detector(monkeypatch):
    behavioral._states.clear()
    monkeypatch.setattr(behavioral, "MAX_READ_FILE_PER_10S", 2)
    session_id = "cap-read-session"
    result = None

    for idx in range(3):
        result = await behavioral.inspect_request(
            session_id,
            {
                "method": "tools/call",
                "params": {"name": "fetch_document", "arguments": {"path": f"/workspace/{idx}.txt"}},
            },
        )

    assert result is not None
    assert result.action == "BLOCK"
    assert result.rule_matches[0].rule_id == "BEH-001"
    assert "filesystem_read" in result.tool_capabilities


@pytest.mark.asyncio
async def test_l3_renamed_write_tool_contributes_to_privilege_sequence(monkeypatch):
    behavioral._states.clear()
    session_id = "cap-write-session"

    await behavioral.inspect_request(
        session_id,
        {
            "method": "tools/call",
            "params": {"name": "fetch_document", "arguments": {"path": "/etc/shadow"}},
        },
    )
    result = await behavioral.inspect_request(
        session_id,
        {
            "method": "tools/call",
            "params": {"name": "save_document", "arguments": {"path": "/tmp/report.txt"}},
        },
    )

    assert result is not None
    assert result.action == "BLOCK"
    assert result.rule_matches[0].rule_id == "BEH-003"
    assert "filesystem_write" in result.tool_capabilities


@pytest.mark.asyncio
async def test_l3_unknown_capability_does_not_overblock_by_default():
    behavioral._states.clear()

    result = await behavioral.inspect_request(
        "cap-unknown-session",
        {"method": "tools/call", "params": {"name": "opaque_business_action", "arguments": {"value": "ok"}}},
    )

    assert result is None


@pytest.mark.asyncio
async def test_l3_renamed_network_tool_contributes_to_session_risk(monkeypatch):
    behavioral._states.clear()
    RiskEngine.get_instance()._states.clear()
    monkeypatch.setattr(behavioral, "MAX_NETWORK_REQUEST_PER_10S", 2)
    session_id = "cap-network-session"
    result = None

    for idx in range(3):
        result = await behavioral.inspect_request(
            session_id,
            {
                "method": "tools/call",
                "params": {
                    "name": "call_partner_service",
                    "arguments": {"endpoint": f"https://api.example.test/{idx}"},
                },
            },
        )

    assert result is not None
    assert result.action == "WARN"
    assert result.rule_matches[0].rule_id == "BEH-007"
    assert "network_request" in result.tool_capabilities
    risk_state = RiskEngine.get_instance().get_state(session_id, "default")
    assert any(event["metadata"].get("detector") == "BEH-007" for event in risk_state.events)
