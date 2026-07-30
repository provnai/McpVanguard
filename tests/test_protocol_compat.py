"""Phase 0 MCP 2026-07-28 compatibility boundary tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from core.preflight import run_preflight
from core.protocol_compat import (
    ProtocolProfile,
    resolve_protocol_profile,
    routing_header_issues,
    unsupported_method_response,
    unsupported_protocol_reason,
)
from core.rules_engine import RulesEngine
from core.sse_server import ServerContext, handle_mcp


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "mcp_2026_07_28_phase0.yaml"


def _fixture() -> dict:
    return yaml.safe_load(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_phase0_fixture_has_versioned_schema():
    assert _fixture()["schema_version"] == "mcp_2026_07_28_phase0_v1"


def test_protocol_profile_defaults_and_rejects_unknown_values():
    assert resolve_protocol_profile(None) == ProtocolProfile.LEGACY_STATEFUL.value
    assert resolve_protocol_profile(" ") == ProtocolProfile.LEGACY_STATEFUL.value
    with pytest.raises(ValueError, match="Unknown MCP protocol profile"):
        resolve_protocol_profile("unsupported")


@pytest.mark.parametrize("case", _fixture()["routing_headers"], ids=lambda case: case["id"])
def test_routing_header_contract_is_deterministic(case):
    issues = routing_header_issues(
        profile=case["profile"],
        body_method=case["body_method"],
        body_tool_name=case["body_tool_name"],
        method_headers=case["method_headers"],
        name_headers=case["name_headers"],
    )
    assert issues == case["expected_issues"]


@pytest.mark.parametrize("method", _fixture()["unsupported_methods"])
def test_unsupported_2026_method_is_fail_closed(method):
    reason = unsupported_protocol_reason(ProtocolProfile.LEGACY_STATEFUL.value, method)
    assert reason and "not forwarded" in reason

    response = unsupported_method_response("phase0-method", reason)
    assert response["error"]["code"] == -32601
    assert response["error"]["data"]["rule"] == "VANGUARD-MCP-PROTOCOL-UNSUPPORTED"


def test_reserved_stateless_profile_never_falls_back_to_legacy():
    reason = unsupported_protocol_reason(
        ProtocolProfile.MCP_2026_07_28_STATELESS.value,
        "tools/call",
    )
    assert reason and "not implemented" in reason


@pytest.mark.parametrize("method", ["ping", "logging/setLevel"])
def test_legacy_profile_preserves_existing_methods(method):
    assert unsupported_protocol_reason(ProtocolProfile.LEGACY_STATEFUL.value, method) is None


@pytest.mark.parametrize("case", _fixture()["meta_invariants"], ids=lambda case: case["id"])
def test_meta_is_inspected_without_overriding_request_identity(case):
    message = case["message"]
    preflight = run_preflight(message, 65536, lambda _tool: True)
    normalized = preflight.normalized_message

    assert normalized["method"] == case["expected_method"]
    assert normalized["params"]["name"] == case["expected_tool_name"]

    if case["id"] == "meta_sensitive_value_is_inspected":
        engine = RulesEngine(rules_dir="rules")
        engine.safe_zones = []
        result = engine.check(message)
        assert result.allowed is False
        assert any("_meta" in (match.matched_field or "") for match in result.rule_matches)


@pytest.mark.asyncio
async def test_http_boundary_rejects_unsupported_method_before_manager():
    manager = MagicMock()
    manager.handle_request = AsyncMock()
    ctx = ServerContext(
        server_command=["python", "-c", "print('phase0')"],
        config=SimpleNamespace(protocol_profile=ProtocolProfile.LEGACY_STATEFUL.value),
        sse_transport=MagicMock(),
        streamable_manager=manager,
        cfg={
            "AUTH_MODE": "none",
            "API_KEY": "",
            "ALLOWED_IPS": [],
            "ALLOWED_ORIGINS": [],
            "REQUIRE_ORIGIN": False,
            "MAX_CONCURRENCY": 5,
            "MAX_GLOBAL_CONNECTIONS": 10,
            "RATE_LIMIT_PER_SEC": 100.0,
            "MAX_BODY_BYTES": 1024,
        },
    )
    scope = {
        "type": "http",
        "method": "POST",
        "client": ["127.0.0.1", 1234],
        "headers": [(b"content-type", b"application/json")],
    }
    messages: list[dict] = []

    async def send(message):
        messages.append(message)

    async def receive():
        return {
            "type": "http.request",
            "body": json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "server/discover"}
            ).encode("utf-8"),
            "more_body": False,
        }

    await handle_mcp(scope, receive, send, ctx)

    manager.handle_request.assert_not_called()
    assert messages[0]["status"] == 501
