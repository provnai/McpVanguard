import json
import re

from core import receipts
from core import __version__ as MCPVANGUARD_VERSION
from core.models import InspectionResult, RuleMatch
from core.proxy import ProxyConfig, VanguardProxy
from core.session import SessionState


HASH_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


def test_build_tool_call_receipt_event_matches_v01_contract(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "manifest.json").write_text('{"version":1,"rules":[]}\n', encoding="utf-8")

    raw = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/workspace/a.txt"}},
    }
    normalized = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/workspace/a.txt"}},
    }

    event = receipts.build_tool_call_receipt_event(
        timestamp="2026-06-05T12:34:56.789Z",
        session_id="session-1",
        server_id="server-1",
        principal_ref="api_key:test",
        policy_profile="strict",
        rules_dir=str(rules_dir),
        jsonrpc_method="tools/call",
        transport="stdio",
        direction="agent_to_server",
        tool_name="read_file",
        raw_policy_action="BLOCK",
        effective_policy_action="SHADOW-BLOCK",
        rule_matches=[RuleMatch(rule_id="FS-001", severity="HIGH", message="blocked")],
        semantic_score=0.9,
        risk_score=80.0,
        request_message=raw,
        normalized_message=normalized,
    )

    assert event["event_type"] == "receipt_v1"
    assert event["schema_version"] == "0.1.0"
    assert event["mcpvanguard_version"] == MCPVANGUARD_VERSION
    assert event["event_scope"] == "tool_call"
    assert event["jsonrpc_method"] == "tools/call"
    assert event["tool_name"] == "read_file"
    assert event["raw_policy_action"] == "BLOCK"
    assert event["effective_policy_action"] == "SHADOW-BLOCK"
    assert event["decision"] == "shadow_blocked"
    assert event["hash_algorithm"] == "sha256"
    assert event["canonicalization"] == "json-sort-keys-v1"
    assert HASH_RE.match(event["request_hash"])
    assert HASH_RE.match(event["normalized_message_hash"])
    assert HASH_RE.match(event["ruleset_hash"])
    assert event["findings"][0]["rule_id"] == "FS-001"


def test_append_receipt_event_writes_canonical_jsonl(tmp_path):
    target = tmp_path / "nested" / "receipts.jsonl"
    event = {
        "event_type": "receipt_v1",
        "schema_version": "0.1.0",
        "receipt_subject_id": "receipt-1",
    }

    receipts.append_receipt_event(target, event)

    line = target.read_text(encoding="utf-8").strip()
    assert json.loads(line) == event
    assert line == receipts.canonical_json(event)


def test_proxy_receipt_emission_is_disabled_by_default(tmp_path):
    config = ProxyConfig()
    config.receipts_enabled = False
    config.receipt_log_file = str(tmp_path / "receipts.jsonl")
    proxy = VanguardProxy(server_command=["python", "-c", "print('hello')"], config=config)
    proxy._session = SessionState(session_id="session-1", server_id=proxy._server_id)

    proxy._emit_tool_call_receipt(
        method="tools/call",
        tool_name="read_file",
        raw_message={"method": "tools/call"},
        normalized_message={"method": "tools/call"},
        result=InspectionResult.allow(),
    )

    assert not (tmp_path / "receipts.jsonl").exists()


def test_proxy_emits_receipt_when_enabled(tmp_path):
    config = ProxyConfig()
    config.receipts_enabled = True
    config.receipt_log_file = str(tmp_path / "receipts.jsonl")
    config.receipt_transport = "stdio"
    config.rules_dir = "rules"
    proxy = VanguardProxy(server_command=["python", "-c", "print('hello')"], config=config)
    proxy._session = SessionState(session_id="session-1", server_id=proxy._server_id)

    raw = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/workspace/a.txt"}},
    }

    proxy._emit_tool_call_receipt(
        method="tools/call",
        tool_name="read_file",
        raw_message=raw,
        normalized_message=raw,
        result=InspectionResult(
            allowed=False,
            action="SHADOW-BLOCK",
            raw_policy_action="BLOCK",
            effective_policy_action="SHADOW-BLOCK",
            rule_matches=[RuleMatch(rule_id="FS-001", severity="HIGH", message="blocked")],
            semantic_score=None,
        ),
    )

    events = [json.loads(line) for line in (tmp_path / "receipts.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(events) == 1
    assert events[0]["event_type"] == "receipt_v1"
    assert events[0]["decision"] == "shadow_blocked"
    assert events[0]["request_hash"].startswith("sha256:")
    assert events[0]["normalized_message_hash"].startswith("sha256:")
