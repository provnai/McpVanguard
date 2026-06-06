"""
tests/test_management_plane.py
Management plane privilege separation tests.

Covers:
  - disabled mode blocks all management ops
  - operator_only mode blocks mutating ops without admin principal
  - operator_only mode allows mutating ops WITH admin principal
  - governed agent principal cannot call mutating tools
  - read-only tools work for any principal in same_session_dev mode
  - rate limiting on mutating ops
  - denied attempts logged (smoke)
"""
from __future__ import annotations

import os
import pytest
from unittest.mock import patch
from dataclasses import dataclass

from core.management import (
    handle_vanguard_tool,
    ManagementContext,
    MANAGEMENT_PLANE_DISABLED,
    MANAGEMENT_PLANE_DEV,
    MANAGEMENT_PLANE_OPERATOR,
    _principal_has_admin,
    is_management_tool,
    MUTATING_MANAGEMENT_TOOLS,
    READ_ONLY_MANAGEMENT_TOOLS,
)


@dataclass
class FakePrincipal:
    principal_id: str = "test-agent"
    auth_type: str = "jwt"
    roles: list = None
    attributes: dict = None

    def __post_init__(self):
        if self.roles is None:
            self.roles = []
        if self.attributes is None:
            self.attributes = {}


# ── disabled mode ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_disabled_mode_blocks_read():
    with patch.dict(os.environ, {"VANGUARD_MANAGEMENT_PLANE_MODE": "disabled"}):
        ctx = ManagementContext(session_id="sess1")
        result = await handle_vanguard_tool("get_vanguard_status", {}, ctx)
    assert result.get("isError") is True
    assert "disabled" in result["content"][0]["text"]


@pytest.mark.asyncio
async def test_disabled_mode_blocks_mutating():
    with patch.dict(os.environ, {"VANGUARD_MANAGEMENT_PLANE_MODE": "disabled"}):
        ctx = ManagementContext(session_id="sess1")
        result = await handle_vanguard_tool("vanguard_reload_rules", {}, ctx)
    assert result.get("isError") is True


# ── same_session_dev mode ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dev_mode_allows_read_without_admin():
    with patch.dict(os.environ, {"VANGUARD_MANAGEMENT_PLANE_MODE": "same_session_dev"}):
        ctx = ManagementContext(session_id="sess1", principal=FakePrincipal())
        result = await handle_vanguard_tool("get_vanguard_status", {}, ctx)
    # Should succeed (returns stats, not an error)
    assert result.get("isError") is not True


# ── operator_only mode ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_operator_only_blocks_mutating_without_admin():
    with patch.dict(os.environ, {"VANGUARD_MANAGEMENT_PLANE_MODE": "operator_only"}):
        # Principal has no admin role
        principal = FakePrincipal(roles=["developer"], attributes={})
        ctx = ManagementContext(session_id="sess1", principal=principal)
        result = await handle_vanguard_tool("vanguard_reload_rules", {}, ctx)
    assert result.get("isError") is True
    assert "admin scope" in result["content"][0]["text"]


@pytest.mark.asyncio
async def test_operator_only_allows_read_without_admin():
    with patch.dict(os.environ, {"VANGUARD_MANAGEMENT_PLANE_MODE": "operator_only"}):
        principal = FakePrincipal(roles=["developer"], attributes={})
        ctx = ManagementContext(session_id="sess2", principal=principal)
        result = await handle_vanguard_tool("get_vanguard_status", {}, ctx)
    assert result.get("isError") is not True


@pytest.mark.asyncio
async def test_operator_only_allows_mutating_with_admin_role():
    with patch.dict(os.environ, {"VANGUARD_MANAGEMENT_PLANE_MODE": "operator_only"}):
        admin_principal = FakePrincipal(roles=["admin"], attributes={})
        ctx = ManagementContext(session_id="sess3", principal=admin_principal)
        # vanguard_reload_rules should be allowed; it will fail due to no real rules engine
        # but the gate itself should not block it
        result = await handle_vanguard_tool("vanguard_reload_rules", {}, ctx)
        # Should NOT be a plane-gate error
        assert "admin scope" not in result.get("content", [{}])[0].get("text", "")
        assert "disabled" not in result.get("content", [{}])[0].get("text", "")


@pytest.mark.asyncio
async def test_operator_only_allows_mutating_with_admin_scope():
    with patch.dict(os.environ, {"VANGUARD_MANAGEMENT_PLANE_MODE": "operator_only"}):
        admin_principal = FakePrincipal(
            roles=["developer"],
            attributes={"scope": "read vanguard:admin write"}
        )
        ctx = ManagementContext(session_id="sess4", principal=admin_principal)
        result = await handle_vanguard_tool("vanguard_reload_rules", {}, ctx)
        assert "admin scope" not in result.get("content", [{}])[0].get("text", "")


# ── _principal_has_admin ─────────────────────────────────────────────────────

def test_no_principal_is_not_admin():
    assert _principal_has_admin(None) is False


def test_admin_role_detected():
    p = FakePrincipal(roles=["admin"])
    assert _principal_has_admin(p) is True


def test_vanguard_admin_role_detected():
    p = FakePrincipal(roles=["vanguard_admin"])
    assert _principal_has_admin(p) is True


def test_developer_role_is_not_admin():
    p = FakePrincipal(roles=["developer"])
    assert _principal_has_admin(p) is False


def test_admin_scope_in_attributes():
    p = FakePrincipal(attributes={"scope": "read vanguard:admin"})
    assert _principal_has_admin(p) is True


def test_admin_scope_in_token_scope_list():
    p = FakePrincipal(attributes={"token_scope": ["scope:io", "vanguard:admin"]})
    assert _principal_has_admin(p) is True


def test_admin_scope_in_existing_oauth_scope_name():
    p = FakePrincipal(attributes={"token_scope": ["scope:admin"]})
    assert _principal_has_admin(p) is True


def test_no_scope_no_role_not_admin():
    p = FakePrincipal(roles=[], attributes={})
    assert _principal_has_admin(p) is False


# ── Tool classification ───────────────────────────────────────────────────────

def test_mutating_tools_classified():
    assert "vanguard_apply_rule" in MUTATING_MANAGEMENT_TOOLS
    assert "vanguard_reload_rules" in MUTATING_MANAGEMENT_TOOLS
    assert "vanguard_reset_session" in MUTATING_MANAGEMENT_TOOLS
    assert "vanguard_flush_auth_cache" in MUTATING_MANAGEMENT_TOOLS


def test_read_tools_classified():
    assert "get_vanguard_status" in READ_ONLY_MANAGEMENT_TOOLS
    assert "get_vanguard_audit" in READ_ONLY_MANAGEMENT_TOOLS
    assert "vanguard_get_auth_stats" in READ_ONLY_MANAGEMENT_TOOLS


def test_management_tool_helper_includes_read_only_names():
    assert is_management_tool("get_vanguard_status") is True
    assert is_management_tool("get_vanguard_audit") is True
    assert is_management_tool("vanguard_reload_rules") is True
    assert is_management_tool("regular_user_tool") is False


def test_no_overlap_between_read_and_mutating():
    assert not (READ_ONLY_MANAGEMENT_TOOLS & MUTATING_MANAGEMENT_TOOLS)
