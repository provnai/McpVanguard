"""
core/management.py
Native tools exposed by McpVanguard itself.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from core import __version__, telemetry

MAX_RUNTIME_RULE_YAML_BYTES = 8 * 1024
RUNTIME_RULE_APPLY_LIMIT = 5
RUNTIME_RULE_APPLY_WINDOW_SECS = 60.0
_RUNTIME_RULE_APPLY_WINDOWS: dict[str, deque[float]] = {}

# ---------------------------------------------------------------------------
# Management plane privilege separation
# ---------------------------------------------------------------------------

# Allowed values for VANGUARD_MANAGEMENT_PLANE_MODE
#   disabled         - management tools hidden from agent (default)
#   same_session_dev - dev/local only; tools shared with governed session
#   operator_only    - mutating tools require admin scope in same session
MANAGEMENT_PLANE_DISABLED = "disabled"
MANAGEMENT_PLANE_DEV = "same_session_dev"
MANAGEMENT_PLANE_OPERATOR = "operator_only"

# Read-only management tools: safe for any authenticated principal.
READ_ONLY_MANAGEMENT_TOOLS = {
    "get_vanguard_status",
    "get_vanguard_audit",
    "vanguard_get_auth_stats",
}

# Mutating management tools: require admin scope in operator_only mode.
MUTATING_MANAGEMENT_TOOLS = {
    "vanguard_apply_rule",
    "vanguard_reload_rules",
    "vanguard_reset_session",
    "vanguard_flush_auth_cache",
    "vanguard_refresh_auth_cache",
}

# Admin scope/role identifiers (checked in principal.roles/attributes)
ADMIN_SCOPES = {"scope:admin", "vanguard:admin", "vanguard:management", "admin"}
ADMIN_ROLES = {"admin", "vanguard_admin", "operator"}


def is_management_tool(name: str) -> bool:
    """Return True if a tool name is one of Vanguard's native management tools."""
    return name in READ_ONLY_MANAGEMENT_TOOLS or name in MUTATING_MANAGEMENT_TOOLS


@dataclass
class ManagementContext:
    session_id: Optional[str] = None
    log_file: str = "audit.log"
    rules_engine: Any = None
    principal: Any = None  # AuthPrincipal | None; carries roles/scopes.
    plane_mode: Optional[str] = None  # proxy sets from config; direct calls fall back to env


def _normalize_plane_mode(value: str | None) -> str:
    raw = (value or MANAGEMENT_PLANE_DISABLED).strip().lower()
    if raw in {MANAGEMENT_PLANE_DISABLED, MANAGEMENT_PLANE_DEV, MANAGEMENT_PLANE_OPERATOR}:
        return raw
    return MANAGEMENT_PLANE_DISABLED


def _get_plane_mode(context: "ManagementContext" | None = None) -> str:
    """Resolve the active management plane mode from context or env."""
    if context is not None and context.plane_mode is not None:
        return _normalize_plane_mode(context.plane_mode)
    return _normalize_plane_mode(os.getenv("VANGUARD_MANAGEMENT_PLANE_MODE"))


def _principal_has_admin(principal: Any) -> bool:
    """Return True if the principal carries any recognised admin role or scope."""
    if principal is None:
        return False
    roles = set(getattr(principal, "roles", []) or [])
    attrs = getattr(principal, "attributes", {}) or {}
    scopes: set[str] = set()
    for key in ("scope", "token_scope"):
        raw = attrs.get(key, "")
        if isinstance(raw, str):
            scopes.update(raw.split())
        elif isinstance(raw, (list, tuple, set)):
            scopes.update(str(item) for item in raw)
    return bool(roles & ADMIN_ROLES) or bool(scopes & ADMIN_SCOPES)


def _management_surface(name: str) -> str:
    if name in READ_ONLY_MANAGEMENT_TOOLS:
        return "read_only"
    if name in MUTATING_MANAGEMENT_TOOLS:
        return "mutating"
    return "unknown"


def _principal_id(principal: Any) -> str | None:
    if principal is None:
        return None
    return getattr(principal, "principal_id", None) or getattr(principal, "sub", None)


def _audit_management_action(
    name: str,
    context: "ManagementContext",
    *,
    outcome: str,
    reason: str = "",
    plane_mode: str | None = None,
) -> None:
    """Record management-plane activity in logs and RiskEngine where useful."""
    import logging

    log = logging.getLogger("vanguard.management")
    level = logging.WARNING if outcome in {"DENIED", "ERROR"} else logging.INFO
    log.log(
        level,
        "Management op %s | tool=%s surface=%s plane=%s session=%s principal=%s reason=%s",
        outcome,
        name,
        _management_surface(name),
        plane_mode or _get_plane_mode(context),
        context.session_id,
        _principal_id(context.principal) or "anonymous",
        reason or "-",
    )

    try:
        from core.risk import RiskEngine
        event_type = None
        if outcome == "DENIED":
            event_type = "MANAGEMENT_DENIED"
        elif outcome == "SUCCESS" and name in MUTATING_MANAGEMENT_TOOLS:
            event_type = "MANAGEMENT_MUTATION"
        if event_type:
            RiskEngine.get_instance().record_event(
                context.session_id or "unknown",
                "management",
                event_type,
                {
                    "tool": name,
                    "surface": _management_surface(name),
                    "plane_mode": plane_mode or _get_plane_mode(context),
                    "principal_id": _principal_id(context.principal),
                    "reason": reason,
                },
            )
    except Exception:
        pass  # risk engine may not be initialised; non-fatal


def _base_vanguard_tools() -> List[Dict[str, Any]]:
    return [
        {
            "name": "get_vanguard_status",
            "description": "Returns the health, version, and metrics of the McpVanguard proxy.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "include_layers": {"type": "boolean", "default": True}
                }
            },
            "readOnlyHint": True,
            "title": "Vanguard: System Status"
        },
        {
            "name": "get_vanguard_audit",
            "description": "Returns recent audit log entries from the active McpVanguard instance.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 10},
                    "session_only": {"type": "boolean", "default": False}
                }
            },
            "readOnlyHint": True,
            "title": "Vanguard: Audit Log"
        },
        {
            "name": "vanguard_apply_rule",
            "description": "Inject a temporary Layer 1 rule into the active proxy at runtime.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rule_yaml": {"type": "string", "description": "L1 rule definition in YAML format."}
                },
                "required": ["rule_yaml"]
            },
            "destructiveHint": True,
            "title": "Vanguard: Hot-Patch Rule"
        },
        {
            "name": "vanguard_reset_session",
            "description": "Clears behavioral analysis counters and rate limits for the current session.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            },
            "destructiveHint": True,
            "title": "Vanguard: Reset Session Metrics"
        },
        {
            "name": "vanguard_flush_auth_cache",
            "description": "Clears cached JWKS and/or OIDC discovery documents. Forces a refresh on the next auth check.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "enum": ["all", "jwks", "discovery"],
                        "default": "all",
                    },
                    "target_url": {
                        "type": "string",
                        "description": "Optional exact cached document URL to clear."
                    },
                }
            },
            "destructiveHint": True,
            "title": "Vanguard: Flush Auth Cache"
        },
        {
            "name": "vanguard_refresh_auth_cache",
            "description": "Force-refresh configured JWKS and/or OIDC discovery caches using the active auth configuration.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "enum": ["all", "jwks", "discovery"],
                        "default": "all",
                    }
                }
            },
            "destructiveHint": False,
            "title": "Vanguard: Refresh Auth Cache"
        },
        {
            "name": "vanguard_get_auth_stats",
            "description": "Returns cache performance metrics and current cache state for JWKS and OIDC documents.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            },
            "readOnlyHint": True,
            "title": "Vanguard: Auth Cache Stats"
        },
        {
            "name": "vanguard_reload_rules",
            "description": "Trigger an atomic, global reload of security rules and safe zones from the local rules directory.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            },
            "destructiveHint": False,
            "title": "Vanguard: Hot-Reload Policy"
        }
    ]


def get_vanguard_tools(
    *,
    plane_mode: str | None = None,
    principal: Any = None,
) -> List[Dict[str, Any]]:
    """Return native Vanguard tools visible to the current management surface."""
    resolved_mode = _normalize_plane_mode(plane_mode or os.getenv("VANGUARD_MANAGEMENT_PLANE_MODE"))
    if resolved_mode == MANAGEMENT_PLANE_DISABLED:
        return []

    tools = _base_vanguard_tools()
    if resolved_mode == MANAGEMENT_PLANE_DEV:
        return tools

    if resolved_mode == MANAGEMENT_PLANE_OPERATOR and _principal_has_admin(principal):
        return tools

    return [
        tool for tool in tools
        if tool.get("name") in READ_ONLY_MANAGEMENT_TOOLS
    ]


def _result_text(text: str, is_error: bool = False, extra: Optional[dict[str, Any]] = None) -> Dict[str, Any]:
    payload = {"content": [{"type": "text", "text": text}]}
    if is_error:
        payload["isError"] = True
    if extra:
        payload.update(extra)
    return payload


def _tail_lines(path: Path, limit: int) -> list[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        lines = deque(f, maxlen=limit)
    return [line.rstrip("\n") for line in lines]


def _management_rate_key(context: ManagementContext) -> str:
    return context.session_id or "anonymous"


def _consume_runtime_rule_budget(context: ManagementContext) -> bool:
    key = _management_rate_key(context)
    now = time.monotonic()
    window = _RUNTIME_RULE_APPLY_WINDOWS.setdefault(key, deque())
    cutoff = now - RUNTIME_RULE_APPLY_WINDOW_SECS
    while window and window[0] < cutoff:
        window.popleft()
    if len(window) >= RUNTIME_RULE_APPLY_LIMIT:
        return False
    window.append(now)
    return True

async def handle_vanguard_tool(
    name: str,
    arguments: Dict[str, Any],
    context: Optional[ManagementContext] = None,
) -> Dict[str, Any]:
    """Execute a Vanguard native tool and return a JSON-RPC-style tool result."""
    context = context or ManagementContext()

    # Management plane gate.
    plane_mode = _get_plane_mode(context)

    if plane_mode == MANAGEMENT_PLANE_DISABLED:
        reason = "Management plane is disabled (VANGUARD_MANAGEMENT_PLANE_MODE=disabled)."
        _audit_management_action(name, context, outcome="DENIED", reason=reason, plane_mode=plane_mode)
        return _result_text(reason, is_error=True)

    if plane_mode == MANAGEMENT_PLANE_OPERATOR and name in MUTATING_MANAGEMENT_TOOLS:
        if not _principal_has_admin(context.principal):
            reason = f"Mutating management op '{name}' requires admin scope; principal lacks required role."
            _audit_management_action(name, context, outcome="DENIED", reason=reason, plane_mode=plane_mode)
            return _result_text(reason, is_error=True)

    # Rate-limit mutating ops per session.
    if name in MUTATING_MANAGEMENT_TOOLS and not _consume_runtime_rule_budget(context):
        reason = "Management op rate limit exceeded."
        _audit_management_action(name, context, outcome="DENIED", reason=reason, plane_mode=plane_mode)
        return _result_text("Runtime management rate limit exceeded. Try again later.", is_error=True)

    if name == "get_vanguard_status":
        stats = telemetry.metrics.get_stats()
        _audit_management_action(name, context, outcome="SUCCESS", plane_mode=plane_mode)
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"McpVanguard v{__version__}\n"
                        f"Uptime: {stats['uptime_seconds']}s\n"
                        f"Allowed: {stats['counts']['allowed']}\n"
                        f"Blocked: {stats['counts']['blocked']}\n"
                        f"Warned: {stats['counts']['warned']}\n"
                        f"L1 avg: {stats['layers']['L1']['avg_ms']}ms\n"
                        f"L2 avg: {stats['layers']['L2']['avg_ms']}ms\n"
                        f"L3 avg: {stats['layers']['L3']['avg_ms']}ms"
                    ),
                }
            ],
            "stats": stats,
        }

    if name == "get_vanguard_audit":
        limit = int(arguments.get("limit", 10))
        limit = max(1, min(limit, 100))
        session_only = bool(arguments.get("session_only", False))

        lines = _tail_lines(Path(context.log_file), limit * 5)
        if session_only and context.session_id:
            lines = [line for line in lines if context.session_id in line]
        lines = lines[-limit:]

        if not lines:
            _audit_management_action(name, context, outcome="SUCCESS", reason="no matching audit entries", plane_mode=plane_mode)
            return _result_text("No matching audit entries found.")

        _audit_management_action(name, context, outcome="SUCCESS", plane_mode=plane_mode)
        return {
            "content": [{"type": "text", "text": "\n".join(lines)}],
            "entries": lines,
        }

    if name == "vanguard_apply_rule":
        rule_yaml = arguments.get("rule_yaml", "")
        if not isinstance(rule_yaml, str) or not rule_yaml.strip():
            _audit_management_action(name, context, outcome="ERROR", reason="empty rule_yaml", plane_mode=plane_mode)
            return _result_text("rule_yaml must be a non-empty YAML string.", is_error=True)
        if len(rule_yaml.encode("utf-8")) > MAX_RUNTIME_RULE_YAML_BYTES:
            _audit_management_action(name, context, outcome="ERROR", reason="oversized rule_yaml", plane_mode=plane_mode)
            return _result_text(
                f"rule_yaml exceeds the {MAX_RUNTIME_RULE_YAML_BYTES}-byte runtime safety limit.",
                is_error=True,
            )
        if context.rules_engine is None:
            _audit_management_action(name, context, outcome="ERROR", reason="rules engine unavailable", plane_mode=plane_mode)
            return _result_text("Active rules engine unavailable for runtime patching.", is_error=True)

        try:
            added_ids = context.rules_engine.add_runtime_rules(rule_yaml, source_file="runtime")
        except Exception as exc:
            _audit_management_action(name, context, outcome="ERROR", reason=str(exc), plane_mode=plane_mode)
            return _result_text(f"Failed to apply runtime rule: {exc}", is_error=True)

        _audit_management_action(name, context, outcome="SUCCESS", reason=f"added={len(added_ids)}", plane_mode=plane_mode)
        return {
            "content": [{"type": "text", "text": f"Applied {len(added_ids)} runtime rule(s): {', '.join(added_ids)}"}],
            "rule_ids": added_ids,
        }

    if name == "vanguard_reset_session":
        if not context.session_id:
            _audit_management_action(name, context, outcome="ERROR", reason="no active session", plane_mode=plane_mode)
            return _result_text("No active session is available to reset.", is_error=True)

        from core import behavioral

        behavioral.clear_state(context.session_id)
        _audit_management_action(name, context, outcome="SUCCESS", plane_mode=plane_mode)
        return {
            "content": [{"type": "text", "text": f"Behavioral counters reset for session {context.session_id}."}],
            "session_id": context.session_id,
        }

    if name == "vanguard_flush_auth_cache":
        from core import auth

        scope = arguments.get("scope", "all")
        target_url = arguments.get("target_url")
        if target_url is not None and not isinstance(target_url, str):
            _audit_management_action(name, context, outcome="ERROR", reason="invalid target_url", plane_mode=plane_mode)
            return _result_text("target_url must be a string when provided.", is_error=True)
        try:
            summary = auth.clear_auth_caches(scope=scope, target_url=target_url)
        except ValueError as exc:
            _audit_management_action(name, context, outcome="ERROR", reason=str(exc), plane_mode=plane_mode)
            return _result_text(str(exc), is_error=True)
        _audit_management_action(name, context, outcome="SUCCESS", reason=f"scope={summary['scope']}", plane_mode=plane_mode)
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        "Authentication caches flushed successfully.\n"
                        f"Scope: {summary['scope']}\n"
                        f"JWKS entries cleared: {summary['jwks_entries_cleared']}\n"
                        f"Discovery entries cleared: {summary['discovery_entries_cleared']}"
                    ),
                }
            ],
            "summary": summary,
        }

    if name == "vanguard_refresh_auth_cache":
        from core import auth

        scope = arguments.get("scope", "all")
        try:
            summary = await auth.refresh_auth_caches(auth.load_auth_config(), scope=scope)
        except ValueError as exc:
            _audit_management_action(name, context, outcome="ERROR", reason=str(exc), plane_mode=plane_mode)
            return _result_text(str(exc), is_error=True)
        except auth.AuthValidationError as exc:
            _audit_management_action(name, context, outcome="ERROR", reason=str(exc), plane_mode=plane_mode)
            return _result_text(f"Failed to refresh auth cache: {exc}", is_error=True)

        lines = [
            "Authentication caches refreshed successfully.",
            f"Scope: {summary['scope']}",
            f"JWKS refreshed: {summary['jwks_refreshed']}",
            f"Discovery refreshed: {summary['discovery_refreshed']}",
        ]
        if summary.get("jwks_source"):
            lines.append(f"JWKS source: {summary['jwks_source']}")
        if summary.get("jwks_key_count") is not None:
            lines.append(f"JWKS key count: {summary.get('jwks_key_count', 0)}")
        _audit_management_action(name, context, outcome="SUCCESS", reason=f"scope={summary['scope']}", plane_mode=plane_mode)
        return {
            "content": [{"type": "text", "text": "\n".join(lines)}],
            "summary": summary,
        }

    if name == "vanguard_get_auth_stats":
        from core import auth

        stats = auth.get_auth_cache_stats()
        _audit_management_action(name, context, outcome="SUCCESS", plane_mode=plane_mode)
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"Auth Cache Performance:\n"
                        f"Hits: {stats['jwks_hits']}\n"
                        f"Misses: {stats['jwks_misses']}\n"
                        f"Discovery Hits: {stats['oidc_hits']}\n"
                        f"Discovery Misses: {stats['oidc_misses']}\n"
                        f"JWKS Entries: {stats['jwks_entries']}\n"
                        f"Discovery Entries: {stats['oidc_entries']}"
                    ),
                }
            ],
            "stats": stats,
        }

    if name == "vanguard_reload_rules":
        from core.rules_engine import RulesEngine
        
        count = RulesEngine.get_instance().reload()
        _audit_management_action(name, context, outcome="SUCCESS", reason=f"rule_count={count}", plane_mode=plane_mode)
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"McpVanguard Policy Reloaded: {count} active rules and {len(RulesEngine.get_instance().safe_zones)} safe zones now enforced."
                }
            ],
            "rule_count": count
        }

    _audit_management_action(name, context, outcome="ERROR", reason="unknown tool", plane_mode=plane_mode)
    return _result_text(f"Unknown Vanguard tool: {name}", is_error=True)
