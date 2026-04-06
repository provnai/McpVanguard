"""
core/management.py
Native tools exposed by McpVanguard itself.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from core import __version__, telemetry


@dataclass
class ManagementContext:
    session_id: Optional[str] = None
    log_file: str = "audit.log"
    rules_engine: Any = None


def get_vanguard_tools() -> List[Dict[str, Any]]:
    """Return the list of native Vanguard tools with safety hints."""
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
        }
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


async def handle_vanguard_tool(
    name: str,
    arguments: Dict[str, Any],
    context: Optional[ManagementContext] = None,
) -> Dict[str, Any]:
    """Execute a Vanguard native tool and return a JSON-RPC-style tool result."""
    context = context or ManagementContext()

    if name == "get_vanguard_status":
        stats = telemetry.metrics.get_stats()
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
            return _result_text("No matching audit entries found.")

        return {
            "content": [{"type": "text", "text": "\n".join(lines)}],
            "entries": lines,
        }

    if name == "vanguard_apply_rule":
        rule_yaml = arguments.get("rule_yaml", "")
        if not isinstance(rule_yaml, str) or not rule_yaml.strip():
            return _result_text("rule_yaml must be a non-empty YAML string.", is_error=True)
        if context.rules_engine is None:
            return _result_text("Active rules engine unavailable for runtime patching.", is_error=True)

        try:
            added_ids = context.rules_engine.add_runtime_rules(rule_yaml, source_file="runtime")
        except Exception as exc:
            return _result_text(f"Failed to apply runtime rule: {exc}", is_error=True)

        return {
            "content": [{"type": "text", "text": f"Applied {len(added_ids)} runtime rule(s): {', '.join(added_ids)}"}],
            "rule_ids": added_ids,
        }

    if name == "vanguard_reset_session":
        if not context.session_id:
            return _result_text("No active session is available to reset.", is_error=True)

        from core import behavioral

        behavioral.clear_state(context.session_id)
        return {
            "content": [{"type": "text", "text": f"Behavioral counters reset for session {context.session_id}."}],
            "session_id": context.session_id,
        }

    return _result_text(f"Unknown Vanguard tool: {name}", is_error=True)
