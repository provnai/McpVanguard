import asyncio
import json

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
    state = behavioral.get_state(session_id)
    state.record_call("read_file", {"arguments": {"path": "/etc/passwd"}})
    assert session_id in behavioral._states

    result = asyncio.run(handle_vanguard_tool("vanguard_reset_session", {}, ManagementContext(session_id=session_id)))

    assert result.get("isError") is not True
    assert session_id not in behavioral._states
