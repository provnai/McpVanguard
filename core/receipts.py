"""receipt_v1 JSONL emission helpers.

This module is intentionally dependency-free so McpVanguard can emit runtime
receipt events without depending on the standalone mcp-receipt package.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from core import __version__ as MCPVANGUARD_VERSION
from core.models import RuleMatch

SCHEMA_VERSION = "0.1.0"
HASH_ALGORITHM = "sha256"
CANONICALIZATION = "json-sort-keys-v1"


def utc_timestamp() -> str:
    """Return an ISO 8601 UTC timestamp compatible with mcp-receipt."""
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    """Canonical JSON representation used for receipt content hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_prefixed(value: Any) -> str:
    """Return sha256:<64-hex> for a JSON-serializable value."""
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def receipt_event_hash(event: dict[str, Any]) -> str:
    """Hash a receipt event without its self-referential receipt_hash field."""
    payload = dict(event)
    payload.pop("receipt_hash", None)
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def file_sha256_prefixed(path: str | Path) -> str | None:
    """Return sha256:<64-hex> for a file if it exists."""
    target = Path(path)
    if not target.exists() or not target.is_file():
        return None
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return f"sha256:{digest}"


def ruleset_hash(rules_dir: str) -> str | None:
    """Best-effort hash of the active ruleset manifest."""
    manifest_hash = file_sha256_prefixed(Path(rules_dir) / "manifest.json")
    if manifest_hash:
        return manifest_hash
    return None


def findings_from_matches(matches: list[RuleMatch]) -> list[dict[str, Any]]:
    """Convert RuleMatch objects into receipt_v1 finding dictionaries."""
    findings: list[dict[str, Any]] = []
    for match in matches:
        message = match.message or match.description or match.rule_name
        finding: dict[str, Any] = {"rule_id": match.rule_id}
        if match.severity:
            finding["severity"] = match.severity
        if message:
            finding["message"] = message
        if match.action:
            finding["action"] = match.action
        if match.matched_field:
            finding["matched_field"] = match.matched_field
        findings.append(finding)
    return findings


def normalize_decision(action: str) -> str:
    """Map McpVanguard policy actions to mcp-receipt decisions."""
    normalized = action.replace("-", "_").upper()
    if normalized == "ALLOW":
        return "allowed"
    if normalized == "WARN":
        return "warned"
    if normalized == "REVIEW":
        return "reviewed"
    if normalized == "SHADOW_BLOCK":
        return "shadow_blocked"
    return "blocked"


def build_tool_call_receipt_event(
    *,
    timestamp: str | None,
    session_id: str | None,
    server_id: str | None,
    principal_ref: str | None,
    policy_profile: str,
    rules_dir: str,
    jsonrpc_method: str,
    transport: str,
    direction: str,
    tool_name: str,
    raw_policy_action: str,
    effective_policy_action: str,
    rule_matches: list[RuleMatch],
    semantic_score: float | None,
    risk_score: float | None,
    request_message: dict[str, Any],
    normalized_message: dict[str, Any] | None,
    policy_explanation: dict[str, Any] | None = None,
    tool_capabilities: list[str] | None = None,
    redaction_mode: str = "partial",
) -> dict[str, Any]:
    """Build one receipt_v1 event for a tool-call gate decision."""
    event: dict[str, Any] = {
        "event_type": "receipt_v1",
        "schema_version": SCHEMA_VERSION,
        "receipt_subject_id": str(uuid4()),
        "timestamp": timestamp or utc_timestamp(),
        "mcpvanguard_version": MCPVANGUARD_VERSION,
        "server_id": server_id,
        "session_id": session_id,
        "principal_ref": principal_ref,
        "policy_profile": policy_profile,
        "ruleset_hash": ruleset_hash(rules_dir),
        "event_scope": "tool_call",
        "jsonrpc_method": jsonrpc_method,
        "transport": transport,
        "direction": direction,
        "tool_name": tool_name,
        "raw_policy_action": raw_policy_action,
        "effective_policy_action": effective_policy_action,
        "decision": normalize_decision(effective_policy_action),
        "findings": findings_from_matches(rule_matches),
        "semantic_score": semantic_score,
        "risk_score": risk_score,
        "hash_algorithm": HASH_ALGORITHM,
        "canonicalization": CANONICALIZATION,
        "request_hash": sha256_prefixed(request_message),
        "normalized_message_hash": sha256_prefixed(normalized_message) if normalized_message is not None else None,
        "response_hash": None,
        "redaction_mode": redaction_mode,
    }
    extensions: dict[str, Any] = {}
    if policy_explanation:
        extensions["policy_explanation_hash"] = sha256_prefixed(policy_explanation)
    if tool_capabilities:
        extensions["tool_capabilities"] = sorted(str(value) for value in tool_capabilities)
    if extensions:
        event["extensions"] = {"mcpvanguard": extensions}
    return event


def append_receipt_event(path: str | Path, event: dict[str, Any]) -> None:
    """Append a receipt_v1 event as one JSONL record."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical_json(event) + "\n")


def _read_receipt_events(path: str | Path) -> list[dict[str, Any]]:
    target = Path(path)
    if not target.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        events.append(json.loads(line))
    return events


def append_chained_receipt_event(
    path: str | Path,
    event: dict[str, Any],
    *,
    stream_id: str | None = None,
) -> dict[str, Any]:
    """
    Append an event with an opt-in hash chain.

    The default `append_receipt_event` keeps the base receipt_v1 contract. This
    helper adds optional chain fields for operators who want local deletion,
    reordering, and mutation detection before export/signing.
    """
    target = Path(path)
    prior_events = _read_receipt_events(target)
    previous = prior_events[-1] if prior_events else None
    previous_hash = previous.get("receipt_hash") if isinstance(previous, dict) else None

    chained = dict(event)
    chained["receipt_stream_id"] = stream_id or f"file:{hashlib.sha256(str(target).encode('utf-8')).hexdigest()[:16]}"
    chained["receipt_sequence"] = len(prior_events)
    chained["prev_receipt_hash"] = previous_hash
    chained["receipt_hash_algorithm"] = HASH_ALGORITHM
    if prior_events and not previous_hash:
        chained["chain_restart"] = True
    chained["receipt_hash"] = receipt_event_hash(chained)
    append_receipt_event(target, chained)
    return chained


def verify_receipt_chain(path: str | Path) -> dict[str, Any]:
    """
    Verify an opt-in receipt hash chain.

    Returns a structured result instead of raising so operators can use this in
    CI/release gates and still inspect all detected issues.
    """
    issues: list[str] = []
    events = _read_receipt_events(path)
    previous_hash: str | None = None
    stream_id: str | None = None

    for index, event in enumerate(events):
        if stream_id is None:
            stream_id = event.get("receipt_stream_id")
        elif event.get("receipt_stream_id") != stream_id:
            issues.append(f"event {index}: receipt_stream_id changed")

        if event.get("receipt_sequence") != index:
            issues.append(f"event {index}: receipt_sequence mismatch")

        if event.get("prev_receipt_hash") != previous_hash:
            issues.append(f"event {index}: prev_receipt_hash mismatch")

        stored_hash = event.get("receipt_hash")
        if not stored_hash:
            issues.append(f"event {index}: missing receipt_hash")
            previous_hash = None
            continue

        computed_hash = receipt_event_hash(event)
        if stored_hash != computed_hash:
            issues.append(f"event {index}: receipt_hash mismatch")
        previous_hash = stored_hash

    return {
        "valid": not issues,
        "checked": len(events),
        "issues": issues,
        "last_receipt_hash": previous_hash,
    }
