import asyncio
import json
import time

import pytest

from core import auth
from core import behavioral
from core.management import ManagementContext, handle_vanguard_tool
from core.rules_engine import RulesEngine


def test_get_vanguard_audit_reads_real_log(tmp_path):
    log_file = tmp_path / "audit.log"
    log_file.write_text(
        "\n".join(
            [
                json.dumps({"session_id": "sess-a", "action": "ALLOW"}),
                json.dumps({"session_id": "sess-b", "action": "BLOCK"}),
                json.dumps({"session_id": "sess-b", "action": "SHADOW-BLOCK"}),
            ]
        ),
        encoding="utf-8",
    )

    context = ManagementContext(session_id="sess-b", log_file=str(log_file))
    result = asyncio.run(handle_vanguard_tool("get_vanguard_audit", {"limit": 2, "session_only": True}, context))

    assert result.get("isError") is not True
    assert len(result["entries"]) == 2
    assert all("sess-b" in line for line in result["entries"])


def test_vanguard_apply_rule_updates_live_rules_engine():
    engine = RulesEngine(rules_dir="rules")
    engine.safe_zones = []
    rule_yaml = """
id: RUNTIME-001
description: Block runtime secret
severity: CRITICAL
action: BLOCK
match_fields: ["params.arguments.path"]
pattern: "runtime_secret"
message: "Runtime rule fired."
"""
    context = ManagementContext(rules_engine=engine)
    result = asyncio.run(handle_vanguard_tool("vanguard_apply_rule", {"rule_yaml": rule_yaml}, context))

    assert result.get("isError") is not True
    assert "RUNTIME-001" in result["rule_ids"]

    msg = {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/runtime_secret.txt"}},
    }
    check = engine.check(msg)
    assert check.action == "BLOCK"
    assert check.rule_matches[0].rule_id == "RUNTIME-001"


def test_vanguard_reset_session_clears_behavioral_state():
    session_id = "mgmt-reset"
    state = behavioral.get_state(session_id)  # uses server_id="default"
    state.record_call("read_file", {"arguments": {"path": "/etc/passwd"}})
    # Phase 6: _states keys are now (session_id, server_id) tuples
    assert (session_id, "default") in behavioral._states

    result = asyncio.run(handle_vanguard_tool("vanguard_reset_session", {}, ManagementContext(session_id=session_id)))

    assert result.get("isError") is not True
    assert (session_id, "default") not in behavioral._states


def test_vanguard_flush_auth_cache_can_target_jwks_only():
    auth.clear_auth_caches()
    auth._JWKS_CACHE["https://issuer.example/jwks.json"] = auth._CachedDocument(
        payload={"keys": [{"kid": "jwks"}]},
        expires_at=time.time() + 300,
    )
    auth._DISCOVERY_CACHE["https://issuer.example/.well-known/openid-configuration"] = auth._CachedDocument(
        payload={"jwks_uri": "https://issuer.example/jwks.json"},
        expires_at=time.time() + 300,
    )

    result = asyncio.run(handle_vanguard_tool("vanguard_flush_auth_cache", {"scope": "jwks"}, ManagementContext()))

    assert result.get("isError") is not True
    assert result["summary"]["jwks_entries_cleared"] == 1
    assert result["summary"]["discovery_entries_cleared"] == 0
    assert len(auth._JWKS_CACHE) == 0
    assert len(auth._DISCOVERY_CACHE) == 1
    auth.clear_auth_caches()


def test_vanguard_refresh_auth_cache_reloads_remote_jwks(monkeypatch):
    auth.clear_auth_caches()
    calls: list[str] = []

    async def fake_fetch(url: str, *, timeout_secs: float, label: str):
        calls.append(url)
        return {"keys": [{"kty": "RSA", "kid": "refresh-key", "n": "AQAB", "e": "AQAB"}]}

    monkeypatch.setattr("core.auth._fetch_json_document", fake_fetch)
    monkeypatch.setenv("VANGUARD_JWKS_URL", "https://issuer.example/jwks.json")
    monkeypatch.delenv("VANGUARD_JWKS_JSON", raising=False)
    monkeypatch.delenv("VANGUARD_JWKS_FILE", raising=False)
    monkeypatch.delenv("VANGUARD_OAUTH_DISCOVERY_URL", raising=False)
    monkeypatch.delenv("VANGUARD_EXPECTED_BEARER_ISSUER", raising=False)

    result = asyncio.run(handle_vanguard_tool("vanguard_refresh_auth_cache", {"scope": "jwks"}, ManagementContext()))

    assert result.get("isError") is not True
    assert result["summary"]["jwks_refreshed"] is True
    assert result["summary"]["jwks_source"] == "jwks_url"
    assert result["summary"]["jwks_key_count"] == 1
    assert calls == ["https://issuer.example/jwks.json"]
    auth.clear_auth_caches()


def test_vanguard_get_auth_stats_reports_cache_entries():
    auth.clear_auth_caches()
    auth._JWKS_CACHE["https://issuer.example/jwks.json"] = auth._CachedDocument(
        payload={"keys": [{"kid": "jwks"}]},
        expires_at=time.time() + 300,
    )

    result = asyncio.run(handle_vanguard_tool("vanguard_get_auth_stats", {}, ManagementContext()))

    assert result.get("isError") is not True
    assert result["stats"]["jwks_entries"] == 1
    assert "JWKS Entries: 1" in result["content"][0]["text"]
    auth.clear_auth_caches()
