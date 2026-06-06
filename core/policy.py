"""
core/policy.py
Final Policy Composer

Composes the definitive PolicyVerdict from all inspection layer results
plus the active profile. This is the single authoritative source of truth
for what action Vanguard takes on any MCP message.

Design invariants:
  - BLOCK always wins; no later layer can downgrade it.
  - REVIEW (human-in-the-loop) sits between WARN and BLOCK.
  - SHADOW_BLOCK is monitor-mode equivalent of BLOCK (audited, not enforced).
  - Profile converts BLOCK to SHADOW_BLOCK in monitor mode.
  - Webhook delivery for REVIEW events is attempted once; failure in strict
    mode causes the request to be hard-blocked (fail-closed).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx

from core.models import InspectionResult, RuleMatch

logger = logging.getLogger("vanguard.policy")


# ---------------------------------------------------------------------------
# Action Enum — ordered from least to most severe
# ---------------------------------------------------------------------------

class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    REVIEW = "REVIEW"
    SHADOW_BLOCK = "SHADOW-BLOCK"
    BLOCK = "BLOCK"

    def severity(self) -> int:
        return {
            "ALLOW": 0,
            "WARN": 1,
            "REVIEW": 2,
            "SHADOW-BLOCK": 3,
            "BLOCK": 4,
        }[self.value]

    def __gt__(self, other: "PolicyAction") -> bool:
        return self.severity() > other.severity()

    def __ge__(self, other: "PolicyAction") -> bool:
        return self.severity() >= other.severity()


# ---------------------------------------------------------------------------
# PolicyVerdict
# ---------------------------------------------------------------------------

@dataclass
class PolicyVerdict:
    """
    The final, unified decision emitted by compose_verdict().

    ``action``           — raw action from layer analysis (what the layers say).
    ``effective_action`` — profile-adjusted action (what actually happens).
                           In monitor mode BLOCK → SHADOW_BLOCK.
    ``reason``           — human-readable summary for audit.
    ``primary_layer``    — which layer drove the verdict (L0/L1/L1.5/L2/L3/AUTH).
    ``rule_id``          — first matching rule ID if available.
    ``findings``         — all contributing InspectionResult objects.
    ``semantic_score``   — propagated from L2 if available.
    ``risk_score``       — propagated from L3 if available.
    """
    action: PolicyAction
    effective_action: PolicyAction
    reason: str
    primary_layer: str
    rule_id: Optional[str]
    findings: list[InspectionResult] = field(default_factory=list)
    semantic_score: Optional[float] = None
    risk_score: Optional[float] = None


# ---------------------------------------------------------------------------
# Review webhook
# ---------------------------------------------------------------------------

_webhook_lock = threading.Lock()

def _deliver_review_webhook(
    payload: dict[str, Any],
    url: str,
    secret: Optional[str],
    timeout: float = 5.0,
) -> bool:
    """
    Attempt a single signed POST to the review webhook URL.
    Returns True on 2xx, False otherwise.
    Failure is logged; caller decides enforcement consequence.
    """
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers: dict[str, str] = {"Content-Type": "application/json"}

    if secret:
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Vanguard-Signature-256"] = f"sha256={sig}"

    try:
        resp = httpx.post(url, content=body, headers=headers, timeout=timeout)
        if resp.is_success:
            logger.info("Review webhook delivered (status=%d)", resp.status_code)
            return True
        logger.warning(
            "Review webhook non-2xx response: %d %s", resp.status_code, resp.text[:200]
        )
        return False
    except Exception as exc:
        logger.warning("Review webhook delivery failed: %s", exc)
        return False


def _build_review_event(
    verdict: PolicyVerdict,
    message: dict,
    session_id: str,
    server_id: str,
    principal_id: Optional[str],
    profile: str,
) -> dict[str, Any]:
    """Build the signed REVIEW webhook payload per the checklist spec."""
    tool_name = message.get("params", {}).get("name") if message.get("method") == "tools/call" else None
    payload_bytes = json.dumps(message, separators=(",", ":")).encode()
    digest = hashlib.sha256(payload_bytes).hexdigest()
    # Bounded excerpt — first 512 chars of JSON-serialised message
    excerpt = json.dumps(message)[:512]

    return {
        "event_type": "mcpvanguard.review.required",
        "schema_version": "1.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "session_id": session_id,
        "server_id": server_id,
        "principal_id": principal_id,
        "profile": profile,
        "tool_name": tool_name,
        "method": message.get("method"),
        "primary_layer": verdict.primary_layer,
        "rule_id": verdict.rule_id,
        "action": verdict.action.value,
        "reason": verdict.reason,
        "semantic_score": verdict.semantic_score,
        "risk_score": verdict.risk_score,
        "findings": [],           # populated by caller if desired
        "payload_digest": f"sha256:{digest}",
        "payload_excerpt": "[REDACTED]" if os.getenv("VANGUARD_REDACT_REVIEW_EXCERPTS") else excerpt,
    }


# ---------------------------------------------------------------------------
# Core verdict composer
# ---------------------------------------------------------------------------

def compose_verdict(
    *,
    profile: str = "balanced",
    mode: str = "enforce",
    auth_result: Optional[InspectionResult] = None,
    preflight_result: Optional[InspectionResult] = None,
    l1_result: Optional[InspectionResult] = None,
    camo_result: Optional[InspectionResult] = None,
    l2_result: Optional[InspectionResult] = None,
    l3_result: Optional[InspectionResult] = None,
    metadata_result: Optional[InspectionResult] = None,
) -> PolicyVerdict:
    """
    Compose the final PolicyVerdict from all layer results.

    Priority (highest wins, cannot be downgraded by later layers):
      AUTH > L0 (preflight) > L1 (rules) > L1.5 (camouflage) > L3 (behavioral)
      > L2 (semantic — advisor only) > metadata

    Profile adjustments:
      monitor : BLOCK → SHADOW-BLOCK (audit only, not enforced)
      balanced: BLOCK stays BLOCK; REVIEW stays REVIEW
      strict  : REVIEW → BLOCK (no human-in-the-loop delay)
    """
    candidates: list[tuple[PolicyAction, str, Optional[str], Optional[InspectionResult]]] = []

    def _ingest(result: Optional[InspectionResult], layer_label: str) -> None:
        if result is None:
            return
        if result.action == "BLOCK":
            rule_id = result.rule_matches[0].rule_id if result.rule_matches else None
            candidates.append((PolicyAction.BLOCK, layer_label, rule_id, result))
        elif result.action == "REVIEW":
            rule_id = result.rule_matches[0].rule_id if result.rule_matches else None
            candidates.append((PolicyAction.REVIEW, layer_label, rule_id, result))
        elif result.action == "WARN":
            rule_id = result.rule_matches[0].rule_id if result.rule_matches else None
            candidates.append((PolicyAction.WARN, layer_label, rule_id, result))

    _ingest(auth_result, "AUTH")
    _ingest(preflight_result, "L0")
    _ingest(l1_result, "L1")
    _ingest(camo_result, "L1.5")
    _ingest(l3_result, "L3")
    _ingest(l2_result, "L2")       # advisory — lowest priority
    _ingest(metadata_result, "META")

    if not candidates:
        return PolicyVerdict(
            action=PolicyAction.ALLOW,
            effective_action=PolicyAction.ALLOW,
            reason="All layers passed.",
            primary_layer="NONE",
            rule_id=None,
        )

    # Highest severity candidate wins
    best_action, best_layer, best_rule_id, best_result = max(
        candidates, key=lambda c: c[0].severity()
    )

    reason = best_result.block_reason or (
        f"Layer {best_layer} triggered {best_action.value}"
        + (f" — rule {best_rule_id}" if best_rule_id else "")
    )

    all_findings = [r for (_, _, _, r) in candidates if r is not None]
    sem_score = next((r.semantic_score for (_, lbl, _, r) in candidates if lbl == "L2" and r), None)
    risk_score = next((getattr(r, 'risk_score', None) for (_, lbl, _, r) in candidates if lbl == "L3" and r), None)

    # Profile adjustment
    effective = best_action
    if best_action == PolicyAction.BLOCK and (mode == "monitor" or mode == "audit" or profile == "monitor"):
        effective = PolicyAction.SHADOW_BLOCK
    elif best_action == PolicyAction.REVIEW and profile == "strict":
        effective = PolicyAction.BLOCK  # strict: no human-in-loop delay

    return PolicyVerdict(
        action=best_action,
        effective_action=effective,
        reason=reason,
        primary_layer=best_layer,
        rule_id=best_rule_id,
        findings=all_findings,
        semantic_score=sem_score,
        risk_score=risk_score,
    )


def maybe_deliver_review(
    verdict: PolicyVerdict,
    message: dict,
    session_id: str,
    server_id: str,
    principal_id: Optional[str],
    profile: str,
    strict_mode: bool = False,
) -> bool:
    """
    If the verdict is REVIEW, attempt webhook delivery.
    In strict mode, webhook failure escalates verdict to BLOCK (fail-closed).
    Returns True if the review was successfully delivered or not needed.
    """
    if verdict.action != PolicyAction.REVIEW:
        return True

    webhook_url = os.getenv("VANGUARD_REVIEW_WEBHOOK_URL")
    if not webhook_url:
        logger.warning(
            "REVIEW verdict but VANGUARD_REVIEW_WEBHOOK_URL not configured; treating as WARN."
        )
        return True

    secret = os.getenv("VANGUARD_REVIEW_WEBHOOK_SECRET")
    event = _build_review_event(verdict, message, session_id, server_id, principal_id, profile)

    with _webhook_lock:
        delivered = _deliver_review_webhook(event, webhook_url, secret)

    if not delivered and strict_mode:
        logger.error("Review webhook failed in strict mode — escalating to BLOCK (fail-closed).")
        verdict.action = PolicyAction.BLOCK
        verdict.effective_action = PolicyAction.BLOCK
        verdict.reason += " [WEBHOOK-FAILED: escalated to BLOCK]"
        return False

    return delivered
