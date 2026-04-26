"""
tests/test_cross_server_isolation.py
Phase 6 — Cross-Server Isolation Guarantee Tests.

These tests prove that behavioral state (sliding windows, sensitive reads,
token buckets) is fully partitioned by (session_id, server_id) so that
one upstream MCP server cannot influence the security decisions made
for a different upstream server in the same session.

Each test is deliberately written to be falsifiable: if the isolation
partition is removed, the test must fail.
"""

import pytest
from core import behavioral
from core.session import SessionManager
from core.models import AuditEvent
from core.session_isolation import derive_server_id, check_server_boundary


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_behavioral_state():
    """Ensure a clean global state dict for each test."""
    behavioral._states.clear()
    yield
    behavioral._states.clear()


SERVER_A = "server-fs-abc123"
SERVER_B = "server-git-def456"
SESSION = "test-session-isolation"


# ---------------------------------------------------------------------------
# Test 1: Sliding windows are partitioned by server_id
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_behavioral_state_is_partitioned_by_server_id():
    """
    Server A's read_file calls must not pollute Server B's sliding window.
    If _states key were just session_id, Server B would see Server A's counts
    and a false BEH-001 block would fire on Server B's first read.
    """
    # Flood read_file on Server A up to the block threshold
    for _ in range(behavioral.MAX_READ_FILE_PER_10S):
        res = await behavioral.inspect_request(
            SESSION,
            {"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/a/file"}}},
            server_id=SERVER_A,
        )
        assert res is None, "Server A should not be blocked before threshold"

    # One more on Server A — should trigger BEH-001
    res_a = await behavioral.inspect_request(
        SESSION,
        {"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/a/over"}}},
        server_id=SERVER_A,
    )
    assert res_a is not None
    assert res_a.action == "BLOCK"
    assert "BEH-001" in res_a.rule_matches[0].rule_id

    # Server B's first read_file in the same session must NOT be blocked
    res_b = await behavioral.inspect_request(
        SESSION,
        {"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/b/clean"}}},
        server_id=SERVER_B,
    )
    assert res_b is None, (
        "Server B must not be affected by Server A's flood. "
        "This would fail if _states were keyed by session_id alone."
    )


# ---------------------------------------------------------------------------
# Test 2: Sensitive reads do not bleed across server identities
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sensitive_read_does_not_bleed_across_servers():
    """
    Server A reads /etc/passwd.
    Server B's write_file call must NOT trigger BEH-003.
    If _states were shared, Server B's write would fire a priv-esc block
    based on Server A's read history.
    """
    # Server A reads a sensitive file
    await behavioral.inspect_request(
        SESSION,
        {"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}},
        server_id=SERVER_A,
    )

    # Server B performs a write — must NOT trigger BEH-003 (priv-esc)
    res = await behavioral.inspect_request(
        SESSION,
        {"method": "tools/call", "params": {"name": "write_file", "arguments": {"path": "/tmp/out", "content": "ok"}}},
        server_id=SERVER_B,
    )
    assert res is None or res.action != "BLOCK", (
        "Server B's write must not be blocked by Server A's sensitive read. "
        "BEH-003 state must be partitioned by server_id."
    )


# ---------------------------------------------------------------------------
# Test 3: Same session, same server — priv-esc still fires correctly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_priv_esc_still_fires_within_same_server():
    """
    This is the positive control: the isolation must not accidentally
    disable intra-server priv-esc detection.
    Server A reads /etc/passwd, then writes — should BLOCK.
    """
    await behavioral.inspect_request(
        SESSION,
        {"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}},
        server_id=SERVER_A,
    )

    res = await behavioral.inspect_request(
        SESSION,
        {"method": "tools/call", "params": {"name": "write_file", "arguments": {"path": "/tmp/payload", "content": "x"}}},
        server_id=SERVER_A,
    )
    assert res is not None
    assert res.action == "BLOCK"
    assert "BEH-003" in res.rule_matches[0].rule_id


# ---------------------------------------------------------------------------
# Test 4: derive_server_id is stable and deterministic
# ---------------------------------------------------------------------------

def test_server_id_derivation_is_stable():
    """Same command argv must always produce the same server_id."""
    cmd = ["npx", "@modelcontextprotocol/server-filesystem", "."]
    id1 = derive_server_id(cmd)
    id2 = derive_server_id(cmd)
    assert id1 == id2, "derive_server_id must be deterministic"
    assert len(id1) == 12, "server_id must be 12 hex characters"
    assert id1.isalnum(), "server_id must be alphanumeric hex"


def test_different_commands_produce_different_ids():
    """Different server commands must produce different server_ids."""
    id_a = derive_server_id(["npx", "server-a"])
    id_b = derive_server_id(["npx", "server-b"])
    assert id_a != id_b


def test_empty_command_returns_unknown():
    """An empty command list should not crash — returns 'unknown'."""
    assert derive_server_id([]) == "unknown"


# ---------------------------------------------------------------------------
# Test 5: SessionState carries server_id
# ---------------------------------------------------------------------------

def test_session_state_carries_server_id():
    """SessionManager.create(server_id=...) must store the id on the session."""
    mgr = SessionManager()
    session = mgr.create(server_id="abc123ef0011")
    assert session.server_id == "abc123ef0011"


def test_session_state_server_id_in_summary():
    """SessionState.summary() must include server_id."""
    mgr = SessionManager()
    session = mgr.create(server_id="testserver01")
    s = session.summary()
    assert "server_id" in s
    assert s["server_id"] == "testserver01"


def test_session_state_default_server_id_is_none():
    """When no server_id is given to create(), it defaults to None."""
    mgr = SessionManager()
    session = mgr.create()
    assert session.server_id is None


# ---------------------------------------------------------------------------
# Test 6: AuditEvent includes server_id in text and JSON output
# ---------------------------------------------------------------------------

def test_audit_event_server_id_in_text_log():
    """AuditEvent.to_log_line() must include [srv:xxx] when server_id is set."""
    event = AuditEvent(
        session_id="aabbccdd-1234-5678-90ab-cdef01234567",
        server_id="abc123ef0011",
        direction="agent→server",
        action="BLOCK",
        blocked_reason="BEH-001 data scraping",
    )
    line = event.to_log_line(format="text")
    assert "[srv:abc123ef0011]" in line


def test_audit_event_no_server_id_omits_srv_tag():
    """AuditEvent.to_log_line() must NOT include [srv:...] when server_id is None."""
    event = AuditEvent(
        session_id="aabbccdd-1234-5678-90ab-cdef01234567",
        direction="agent→server",
        action="ALLOW",
    )
    line = event.to_log_line(format="text")
    assert "[srv:" not in line


def test_audit_event_server_id_in_json_log():
    """AuditEvent JSON output must include server_id field."""
    event = AuditEvent(
        session_id="aabbccdd-1234-5678-90ab-cdef01234567",
        server_id="deadbeef1234",
        direction="server→agent",
        action="WARN",
    )
    import json
    data = json.loads(event.to_log_line(format="json"))
    assert data.get("server_id") == "deadbeef1234"


def test_audit_event_risk_fields_are_stable_in_json_log():
    """Structured audit output should expose risk fields in a stable shape."""
    import json

    event = AuditEvent(
        session_id="aabbccdd-1234-5678-90ab-cdef01234567",
        direction="server→agent",
        action="WARN",
        risk_score=80.0,
        risk_enforcement="AUDIT",
    )

    data = json.loads(event.to_log_line(format="json"))
    assert "risk_score" in data
    assert "risk_enforcement" in data
    assert data["risk_score"] == 80.0
    assert data["risk_enforcement"] == "AUDIT"


def test_audit_event_default_risk_fields_remain_present_in_json_log():
    """Even pre-risk events should keep the audit JSON schema stable."""
    import json

    event = AuditEvent(
        session_id="aabbccdd-1234-5678-90ab-cdef01234567",
        direction="agent→server",
        action="ALLOW",
    )

    data = json.loads(event.to_log_line(format="json"))
    assert "risk_score" in data
    assert "risk_enforcement" in data
    assert data["risk_score"] is None
    assert data["risk_enforcement"] is None


# ---------------------------------------------------------------------------
# Test 7: check_server_boundary helper
# ---------------------------------------------------------------------------

def test_check_server_boundary_no_mismatch():
    """No event when session server_id matches incoming."""
    mgr = SessionManager()
    session = mgr.create(server_id="abc")
    result = check_server_boundary(session, "abc")
    assert result is None


def test_check_server_boundary_detects_mismatch():
    """CrossServerTransitionEvent returned when server_id differs."""
    mgr = SessionManager()
    session = mgr.create(server_id="abc")
    event = check_server_boundary(session, "xyz")
    assert event is not None
    assert event.original_server_id == "abc"
    assert event.incoming_server_id == "xyz"
    assert event.session_id == session.session_id


def test_check_server_boundary_no_event_when_session_has_no_id():
    """No event emitted if the session has no server_id recorded yet."""
    mgr = SessionManager()
    session = mgr.create()  # server_id=None
    result = check_server_boundary(session, "any-server")
    assert result is None
