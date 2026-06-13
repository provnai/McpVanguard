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
    ``explanation``      — stable operator-facing decision explanation.
    """
    action: PolicyAction
    effective_action: PolicyAction
    reason: str
    primary_layer: str
    rule_id: Optional[str]
    findings: list[InspectionResult] = field(default_factory=list)
    semantic_score: Optional[float] = None
    risk_score: Optional[float] = None
    explanation: dict[str, Any] = field(default_factory=dict)


def _rule_family(rule_id: Optional[str]) -> Optional[str]:
    """Return a coarse rule family for reports without coupling to exact rule IDs."""
    if not rule_id:
        return None
    if rule_id.startswith("VANGUARD-SAFEZONE"):
        return "safe_zone"
    if rule_id.startswith("SEM"):
        return "semantic"
    if rule_id.startswith("BEH"):
        return "behavioral"
    if rule_id.startswith("CAMO"):
        return "camouflage"
    if rule_id.startswith("AUTH"):
        return "auth"
    if rule_id.startswith("VANGUARD-"):
        return "preflight"
    return rule_id.split("-", 1)[0].lower()


def _match_message(match: RuleMatch) -> str:
    return match.message or match.description or match.rule_name or match.rule_id


def _safe_zone_details(match: Optional[RuleMatch]) -> Optional[dict[str, Any]]:
    if match is None or not match.rule_id.startswith("VANGUARD-SAFEZONE"):
        return None

    return {
        "requested_field": match.matched_field,
        "requested_path": match.matched_value,
        "allowed_prefixes_summary": match.description,
        "note": (
            "Outside configured safe-zone policy does not necessarily mean malicious; "
            "tune safe zones for legitimate workspaces before strict enforcement."
        ),
    }


def _profile_effect(profile: str, mode: str, raw: PolicyAction, effective: PolicyAction) -> str:
    if raw == effective:
        return "no_profile_change"
    if effective == PolicyAction.SHADOW_BLOCK:
        return "monitor_or_audit_mode_forwarded_would_block"
    if raw == PolicyAction.REVIEW and effective == PolicyAction.BLOCK and profile == "strict":
        return "strict_profile_escalated_review_to_block"
    return f"{profile or 'balanced'}_{mode or 'enforce'}_adjusted_{raw.value}_to_{effective.value}"


def _operator_hint(
    layer: str,
    rule_id: Optional[str],
    effective: PolicyAction,
    safe_zone: Optional[dict[str, Any]],
) -> str:
    if safe_zone:
        return (
            "Review rules/safe_zones.yaml for the tool and add only the intended workspace prefixes. "
            "Do not disable safe-zone enforcement globally to resolve a benign block."
        )
    if layer == "L2":
        return (
            "Semantic scoring escalated the decision; review threshold, prompt context, "
            "and benchmark false-positive cases before lowering deterministic controls."
        )
    if layer == "L3":
        return (
            "Behavioral/session context drove the decision; inspect recent calls for enumeration, "
            "flooding, or high-entropy extraction patterns."
        )
    if layer == "L0":
        return (
            "Preflight normalization or input-shape validation triggered; inspect decoded/canonicalized "
            "input before allowing this traffic."
        )
    if layer in {"L1", "L1.5"}:
        return (
            "Deterministic policy triggered; prefer a narrow rule or safe-zone tuning change "
            "over weakening the profile."
        )
    if layer == "AUTH":
        return (
            "Transport or principal policy blocked the request; validate issuer, audience, scopes, "
            "claims, and destructive-tool policy."
        )
    if effective == PolicyAction.ALLOW:
        return "No policy action required."
    return f"Review rule {rule_id or 'unknown'} and the active profile before changing enforcement."


def _build_policy_explanation(
    *,
    profile: str,
    mode: str,
    verdict_action: PolicyAction,
    effective_action: PolicyAction,
    primary_layer: str,
    primary_rule_id: Optional[str],
    reason: str,
    candidates: list[tuple[PolicyAction, str, Optional[str], Optional[InspectionResult]]],
) -> dict[str, Any]:
    primary_match = None
    for _, layer, rule_id, result in candidates:
        if layer == primary_layer and rule_id == primary_rule_id and result and result.rule_matches:
            primary_match = result.rule_matches[0]
            break

    safe_zone = _safe_zone_details(primary_match)
    has_l2 = any(layer == "L2" for _, layer, _, _ in candidates)
    semantic_role = "skipped"
    if has_l2 and primary_layer == "L2":
        semantic_role = "escalated"
    elif has_l2:
        semantic_role = "advisory"
    upstream_called = effective_action in {
        PolicyAction.ALLOW,
        PolicyAction.WARN,
        PolicyAction.REVIEW,
        PolicyAction.SHADOW_BLOCK,
    }

    supporting_findings: list[dict[str, Any]] = []
    for action, layer, rule_id, result in candidates:
        if result is None:
            continue
        if result.rule_matches:
            for match in result.rule_matches:
                supporting_findings.append(
                    {
                        "layer": layer,
                        "rule_id": match.rule_id,
                        "rule_family": _rule_family(match.rule_id),
                        "severity": match.severity,
                        "action": match.action or action.value,
                        "message": _match_message(match),
                    }
                )
        else:
            supporting_findings.append(
                {
                    "layer": layer,
                    "rule_id": rule_id,
                    "rule_family": _rule_family(rule_id),
                    "severity": None,
                    "action": action.value,
                    "message": result.block_reason,
                }
            )

    explanation = {
        "schema_version": "policy_explanation_v1",
        "active_profile": profile or "balanced",
        "final_verdict": effective_action.value,
        "primary_layer": primary_layer,
        "primary_rule_id": primary_rule_id,
        "primary_rule_family": _rule_family(primary_rule_id),
        "primary_finding": reason,
        "supporting_findings": supporting_findings,
        "profile_effect": _profile_effect(profile, mode, verdict_action, effective_action),
        "raw_policy_action": verdict_action.value,
        "effective_policy_action": effective_action.value,
        "semantic_role": semantic_role,
        "operator_hint": _operator_hint(primary_layer, primary_rule_id, effective_action, safe_zone),
        "upstream_called": upstream_called,
    }
    if safe_zone:
        explanation["safe_zone"] = safe_zone
    return explanation


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
        explanation = _build_policy_explanation(
            profile=profile,
            mode=mode,
            verdict_action=PolicyAction.ALLOW,
            effective_action=PolicyAction.ALLOW,
            primary_layer="NONE",
            primary_rule_id=None,
            reason="All layers passed.",
            candidates=[],
        )
        return PolicyVerdict(
            action=PolicyAction.ALLOW,
            effective_action=PolicyAction.ALLOW,
            reason="All layers passed.",
            primary_layer="NONE",
            rule_id=None,
            explanation=explanation,
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

    explanation = _build_policy_explanation(
        profile=profile,
        mode=mode,
        verdict_action=best_action,
        effective_action=effective,
        primary_layer=best_layer,
        primary_rule_id=best_rule_id,
        reason=reason,
        candidates=candidates,
    )

    return PolicyVerdict(
        action=best_action,
        effective_action=effective,
        reason=reason,
        primary_layer=best_layer,
        rule_id=best_rule_id,
        findings=all_findings,
        semantic_score=sem_score,
        risk_score=risk_score,
        explanation=explanation,
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
