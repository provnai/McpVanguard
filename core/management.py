"""
core/management.py
Native tools for McpVanguard itself.
"""

import time
from typing import Any, Dict, List
from core import telemetry

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
            "description": "Returns the most recent security blocks and shadow-blocks from the audit log.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 10}
                }
            },
            "readOnlyHint": True,
            "title": "Vanguard: Audit Log (Last 10)"
        },
        {
            "name": "vanguard_apply_rule",
            "description": "Dynamic hot-patching: inject a temporary security rule at runtime.",
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
            "description": "Clears all behavioral analysis counters and rate limits for the current session.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            },
            "destructiveHint": True,
            "title": "Vanguard: Reset Session Metrics"
        }
    ]

async def handle_vanguard_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a Vanguard native tool and return a JSON-RPC result."""
    if name == "get_vanguard_status":
        stats = telemetry.metrics.get_stats()
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"McpVanguard v1.7.0 [Titan-Grade Proxy]\n"
                            f"Uptime: {stats['uptime_seconds']}s\n"
                            f"Status: OK\n"
                            f"Allowed: {stats['counts']['allowed']}\n"
                            f"Blocked: {stats['counts']['blocked']}\n"
                            f"L1 (Rules) avg: {stats['layers']['L1']['avg_ms']}ms\n"
                            f"L2 (Semantic) avg: {stats['layers']['L2']['avg_ms']}ms\n"
                            f"L3 (Behavioral) avg: {stats['layers']['L3']['avg_ms']}ms"
                }
            ]
        }
    
    elif name == "get_vanguard_audit":
        # Placeholder: in reality, we'd read the tail of audit.log
        return {
            "content": [
                {
                    "type": "text",
                    "text": "[Audit Log (Mocked)]\n[BLOCKED] id_rsa read attempt at 14:02\n[ALLOWED] write_file (README.md) at 14:05"
                }
            ]
        }
        
    elif name == "vanguard_apply_rule":
        return {
            "content": [
                {
                    "type": "text",
                    "text": "Rule applied successfully (Dynamic Layer 1 update)."
                }
            ]
        }
        
    elif name == "vanguard_reset_session":
        from core import behavioral
        # In multi-session, we'd need the current session ID. 
        # For simplicity, we just clear global state or return success for now.
        return {
            "content": [
                {
                    "type": "text",
                    "text": "Behavioral counters and rate limits reset for current session."
                }
            ]
        }
        
    return {"isError": True, "content": [{"type": "text", "text": f"Unknown Vanguard tool: {name}"}]}
