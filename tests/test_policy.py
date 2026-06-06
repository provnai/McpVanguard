"""
tests/test_policy.py
Final policy composer tests.

Covers:
  - Highest severity always wins (BLOCK > WARN > ALLOW)
  - No later layer can downgrade a BLOCK
  - Monitor mode converts BLOCK to SHADOW-BLOCK
  - Strict mode converts REVIEW to BLOCK
  - Profile changes effective_action but not raw action
  - Review webhook fail-closed in strict mode
"""
from __future__ import annotations

import pytest
from core.policy import PolicyAction, PolicyVerdict, compose_verdict, maybe_deliver_review
from core.models import InspectionResult, RuleMatch


def _block(rule_id="TEST-001", layer=1, reason="test block"):
    return InspectionResult(
        allowed=False,
        action="BLOCK",
        layer_triggered=layer,
        rule_matches=[RuleMatch(rule_id=rule_id, description="test", severity="HIGH")],
        block_reason=reason,
    )


def _warn(rule_id="TEST-WARN-001"):
    return InspectionResult(
        allowed=True,
        action="WARN",
        layer_triggered=1,
        rule_matches=[RuleMatch(rule_id=rule_id, description="warn", severity="MEDIUM")],
    )


def _allow():
    return InspectionResult(allowed=True, action="ALLOW", layer_triggered=0, rule_matches=[])


# ── Basic precedence ────────────────────────────────────────────────────────

def test_all_allow_gives_allow():
    v = compose_verdict(l1_result=_allow(), l2_result=_allow())
    assert v.action == PolicyAction.ALLOW
    assert v.effective_action == PolicyAction.ALLOW


def test_block_wins_over_warn():
    v = compose_verdict(l1_result=_block(), l2_result=_warn())
    assert v.action == PolicyAction.BLOCK


def test_warn_wins_over_allow():
    v = compose_verdict(l1_result=_warn(), l2_result=_allow())
    assert v.action == PolicyAction.WARN


def test_l2_semantic_cannot_downgrade_l1_block():
    """Core invariant: L2 (semantic) is advisory; it cannot override a deterministic block."""
    block = _block("L1-001", reason="L1 deterministic block")
    # L2 says ALLOW (low score); this should still be BLOCK.
    allow = _allow()
    v = compose_verdict(l1_result=block, l2_result=allow)
    assert v.action == PolicyAction.BLOCK
    assert v.primary_layer == "L1"


def test_auth_block_wins_over_all():
    v = compose_verdict(
        auth_result=_block("AUTH-001"),
        l1_result=_warn(),
        l2_result=_allow(),
    )
    assert v.action == PolicyAction.BLOCK
    assert v.primary_layer == "AUTH"


def test_l0_preflight_block():
    v = compose_verdict(preflight_result=_block("PRE-001"), l1_result=_allow())
    assert v.action == PolicyAction.BLOCK
    assert v.primary_layer == "L0"


def test_camo_block_higher_priority_than_l2():
    v = compose_verdict(camo_result=_block("CAMO-001"), l2_result=_warn())
    assert v.action == PolicyAction.BLOCK
    assert v.primary_layer == "L1.5"


# ── Profile / mode adjustments ──────────────────────────────────────────────

def test_monitor_mode_converts_block_to_shadow_block():
    v = compose_verdict(mode="monitor", l1_result=_block())
    assert v.action == PolicyAction.BLOCK          # raw still BLOCK
    assert v.effective_action == PolicyAction.SHADOW_BLOCK  # effective is SHADOW


def test_audit_mode_converts_block_to_shadow_block():
    """Profile monitor resolves to mode=audit, so audit mode must shadow-block too."""
    v = compose_verdict(profile="monitor", mode="audit", l1_result=_block())
    assert v.action == PolicyAction.BLOCK
    assert v.effective_action == PolicyAction.SHADOW_BLOCK


def test_review_result_is_ingested():
    review_result = InspectionResult(
        allowed=True,
        action="REVIEW",
        layer_triggered=1,
        rule_matches=[RuleMatch(rule_id="REVIEW-001", description="review", severity="MEDIUM")],
        block_reason="manual review required",
    )
    v = compose_verdict(profile="balanced", mode="enforce", camo_result=review_result)
    assert v.action == PolicyAction.REVIEW
    assert v.effective_action == PolicyAction.REVIEW
    assert v.primary_layer == "L1.5"


def test_strict_profile_converts_review_to_block():
    """REVIEW in strict profile is escalated to BLOCK (no human-in-loop delay)."""
    review_result = InspectionResult(
        allowed=True,
        action="REVIEW",
        layer_triggered=1,
        rule_matches=[RuleMatch(rule_id="CAMO-001", description="review", severity="MEDIUM")],
    )
    v = compose_verdict(profile="strict", mode="enforce", camo_result=review_result)
    assert v.action == PolicyAction.REVIEW
    assert v.effective_action == PolicyAction.BLOCK


def test_enforce_mode_keeps_block():
    v = compose_verdict(mode="enforce", l1_result=_block())
    assert v.effective_action == PolicyAction.BLOCK


def test_no_findings_is_allow():
    v = compose_verdict()
    assert v.action == PolicyAction.ALLOW


# ── Multi-layer ─────────────────────────────────────────────────────────────

def test_highest_of_many_wins():
    v = compose_verdict(
        l1_result=_warn("WARN-001"),
        l2_result=_block("SEM-BLOCK"),
        l3_result=_warn("BEH-001"),
    )
    assert v.action == PolicyAction.BLOCK
    assert v.rule_id == "SEM-BLOCK"


def test_findings_list_includes_all_contributing():
    v = compose_verdict(
        l1_result=_warn("L1-WARN"),
        l2_result=_block("L2-BLOCK"),
    )
    assert len(v.findings) == 2


def test_semantic_score_propagated():
    sem = InspectionResult(
        allowed=False,
        action="BLOCK",
        layer_triggered=2,
        rule_matches=[RuleMatch(rule_id="SEM-BLOCK", description="high score", severity="HIGH")],
        semantic_score=0.91,
        block_reason="semantic block",
    )
    v = compose_verdict(l2_result=sem)
    assert v.semantic_score == pytest.approx(0.91)


# ── Webhook fail-closed ─────────────────────────────────────────────────────

def test_review_webhook_failclosed_in_strict(monkeypatch):
    """If webhook delivery fails in strict mode, the verdict escalates to BLOCK."""
    # Build a REVIEW verdict
    v = PolicyVerdict(
        action=PolicyAction.REVIEW,
        effective_action=PolicyAction.REVIEW,
        reason="test review",
        primary_layer="L1.5",
        rule_id="CAMO-001",
    )
    # Simulate webhook URL set but delivery always fails
    monkeypatch.setenv("VANGUARD_REVIEW_WEBHOOK_URL", "http://localhost:19999/webhook")
    result = maybe_deliver_review(v, {}, "sess1", "srv1", None, "strict", strict_mode=True)
    assert result is False
    assert v.effective_action == PolicyAction.BLOCK
