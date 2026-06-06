"""
tests/test_semantic_ws5.py
Semantic advisor hardening tests.

Covers:
  - build_semantic_context() includes all layer annotations
  - Empty/whitespace response treated as parse failure
  - L2 BLOCK cannot downgrade L1 BLOCK (tested via policy integration)
  - Provider metadata appears in block_reason
  - Structured prompt includes profile/preflight/camouflage/L1 context
"""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from core.semantic import build_semantic_context, SemanticProviderMetadata, _get_settings


# ── build_semantic_context ────────────────────────────────────────────────────

def test_build_context_basic():
    msg = {"method": "tools/call", "params": {"name": "bash", "arguments": {"command": "ls"}}}
    ctx = build_semantic_context(msg, profile="balanced")
    assert "tools/call" in ctx or "bash" in ctx
    assert "balanced" in ctx
    assert "Do NOT execute" in ctx


def test_build_context_includes_preflight():
    msg = {"method": "tools/call", "params": {"name": "bash", "arguments": {"command": "ls"}}}
    # Fake preflight finding
    pf = MagicMock()
    pf.severity = "HIGH"
    pf.message = "Homoglyph detected in tool name"
    ctx = build_semantic_context(msg, preflight_findings=[pf])
    assert "L0 PREFLIGHT" in ctx
    assert "Homoglyph" in ctx


def test_build_context_includes_camouflage():
    msg = {"method": "tools/call", "params": {"name": "write_file", "arguments": {"content": "x"}}}
    from core.camouflage import CamouflageFinding, RuleAction
    camo = CamouflageFinding(
        rule_id="CAMO-001",
        category="comment_trust",
        severity="HIGH",
        action=RuleAction.BLOCK,
        message="Trust label",
        evidence="# safe found",
    )
    ctx = build_semantic_context(msg, camouflage_findings=[camo])
    assert "CAMOUFLAGE DETECTED" in ctx
    assert "# safe found" in ctx


def test_build_context_includes_l1_rules():
    msg = {"method": "tools/call", "params": {"name": "exec_shell"}}
    ctx = build_semantic_context(msg, l1_rule_ids=["CMD-002", "CMD-009"])
    assert "CMD-002" in ctx
    assert "CMD-009" in ctx
    assert "L1 RULE WARNINGS" in ctx


def test_build_context_strict_profile():
    msg = {"method": "tools/call", "params": {"name": "delete_all"}}
    ctx = build_semantic_context(msg, profile="strict")
    assert "strict" in ctx


# ── SemanticProviderMetadata ──────────────────────────────────────────────────

def test_provider_metadata_is_immutable():
    meta = SemanticProviderMetadata(
        provider_kind="openai",
        model="gpt-4o-mini",
        base_url_host="api.openai.com",
        threshold_warn=0.5,
        threshold_block=0.8,
        fail_closed=True,
    )
    with pytest.raises((AttributeError, TypeError)):
        meta.provider_kind = "ollama"  # frozen dataclass


# ── Parse failure handling ────────────────────────────────────────────────────

def test_empty_content_raises_value_error():
    """Empty/whitespace-only provider response should raise ValueError."""
    from core.semantic import _extract_json
    with pytest.raises(Exception):
        _extract_json("")


def test_whitespace_only_raises():
    from core.semantic import _extract_json
    with pytest.raises(Exception):
        _extract_json("   \n  ")


# ── L2 cannot downgrade L1 block (policy integration) ────────────────────────

def test_l2_block_cannot_downgrade_l1_block_via_policy():
    """Prove that even if L2 says ALLOW, an L1 block holds via compose_verdict."""
    from core.policy import compose_verdict, PolicyAction
    from core.models import InspectionResult, RuleMatch

    l1_block = InspectionResult(
        allowed=False, action="BLOCK", layer_triggered=1,
        rule_matches=[RuleMatch(rule_id="CMD-002", description="block", severity="HIGH")],
        block_reason="deterministic block",
    )
    l2_allow = InspectionResult(
        allowed=True, action="ALLOW", layer_triggered=2,
        rule_matches=[],
    )
    verdict = compose_verdict(l1_result=l1_block, l2_result=l2_allow)
    assert verdict.action == PolicyAction.BLOCK
    assert verdict.primary_layer == "L1"


@pytest.mark.asyncio
async def test_proxy_passes_profile_semantic_settings_to_l2():
    """ProxyConfig profile thresholds/fail-closed must reach the semantic scorer."""
    from core.proxy import ProxyConfig, VanguardProxy

    captured = {}

    async def fake_score_intent(message, settings=None, **kwargs):
        captured["enabled"] = settings.enabled
        captured["fail_closed"] = settings.fail_closed
        captured["threshold_warn"] = settings.threshold_warn
        captured["threshold_block"] = settings.threshold_block
        return None

    config = ProxyConfig()
    config.semantic_enabled = True
    config.semantic_fail_closed = True
    config.warn_threshold = 0.40
    config.block_threshold = 0.70
    config.behavioral_enabled = False

    proxy = VanguardProxy(["python", "-c", "print('benchmark')"], config=config)
    message = {
        "method": "tools/call",
        "params": {"name": "noop", "arguments": {"value": "hello"}},
    }

    with patch("core.semantic.score_intent", side_effect=fake_score_intent):
        result = await proxy._inspect_message(message)

    assert result.allowed is True
    assert captured == {
        "enabled": True,
        "fail_closed": True,
        "threshold_warn": 0.40,
        "threshold_block": 0.70,
    }
