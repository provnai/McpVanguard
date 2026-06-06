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
    return event


def append_receipt_event(path: str | Path, event: dict[str, Any]) -> None:
    """Append a receipt_v1 event as one JSONL record."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical_json(event) + "\n")
