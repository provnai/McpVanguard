"""
core/models.py
Pydantic models for JSON-RPC 2.0 messages used by MCP.
"""

from __future__ import annotations
from typing import Any, Literal, Optional, Union
from pydantic import BaseModel, Field
import time
import uuid


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 Base Types
# ---------------------------------------------------------------------------

class JsonRpcRequest(BaseModel):
    """A JSON-RPC 2.0 Request (agent → server, tool calls)."""
    jsonrpc: Literal["2.0"] = "2.0"
    id: Optional[Union[str, int]] = None
    method: str
    params: Optional[dict[str, Any]] = None

    def is_tool_call(self) -> bool:
        return self.method == "tools/call"

    def is_notification(self) -> bool:
        return self.id is None

    def get_tool_name(self) -> Optional[str]:
        if self.is_tool_call() and self.params:
            return self.params.get("name")
        return None

    def get_tool_args(self) -> dict[str, Any]:
        if self.is_tool_call() and self.params:
            return self.params.get("arguments", {})
        return {}


class JsonRpcResponse(BaseModel):
    """A JSON-RPC 2.0 Response (server → agent)."""
    jsonrpc: Literal["2.0"] = "2.0"
    id: Optional[Union[str, int]] = None
    result: Optional[Any] = None
    error: Optional[JsonRpcError] = None


class JsonRpcError(BaseModel):
    """JSON-RPC 2.0 Error object."""
    code: int
    message: str
    data: Optional[Any] = None


# ---------------------------------------------------------------------------
# Vanguard-specific Types
# ---------------------------------------------------------------------------

class RuleSeverity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RuleAction:
    BLOCK = "BLOCK"
    WARN = "WARN"
    LOG = "LOG"


class RuleMatch(BaseModel):
    """Represents a rule that matched a message."""
    rule_id: str
    rule_name: Optional[str] = None
    severity: str
    action: Optional[str] = None
    matched_field: Optional[str] = None
    matched_value: Optional[str] = None
    description: Optional[str] = None  # Replaces 'message' for clarity
    message: Optional[str] = None      # Keep for backward compatibility


class InspectionResult(BaseModel):
    """Result of running a message through all inspection layers."""
    allowed: bool
    action: str  # ALLOW | BLOCK | WARN
    layer_triggered: Optional[int] = None  # 1, 2, or 3
    rule_matches: list[RuleMatch] = Field(default_factory=list)
    semantic_score: Optional[float] = None
    block_reason: Optional[str] = None

    @classmethod
    def allow(cls) -> "InspectionResult":
        return cls(allowed=True, action="ALLOW")

    @classmethod
    def block(cls, reason: str, layer: int, rule_matches: list[RuleMatch] = None) -> "InspectionResult":
        return cls(
            allowed=False,
            action="BLOCK",
            layer_triggered=layer,
            rule_matches=rule_matches or [],
            block_reason=reason,
        )

    @classmethod
    def warn(cls, reason: str, layer: int, rule_matches: list[RuleMatch] = None) -> "InspectionResult":
        return cls(
            allowed=True,
            action="WARN",
            layer_triggered=layer,
            rule_matches=rule_matches or [],
            block_reason=reason,
        )


class AuditEvent(BaseModel):
    """An entry written to audit.log for every proxied message."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: float = Field(default_factory=time.time)
    session_id: str
    direction: str  # "agent→server" | "server→agent"
    method: Optional[str] = None
    tool_name: Optional[str] = None
    action: str  # ALLOW | BLOCK | WARN
    layer_triggered: Optional[int] = None
    rule_id: Optional[str] = None
    semantic_score: Optional[float] = None
    latency_ms: Optional[float] = None
    blocked_reason: Optional[str] = None

    def to_log_line(self) -> str:
        from datetime import datetime
        ts = datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        icon = {"ALLOW": "✅", "BLOCK": "🚫", "WARN": "⚠️"}.get(self.action, "?")
        tool = f" [{self.tool_name}]" if self.tool_name else ""
        reason = f" — {self.blocked_reason}" if self.blocked_reason else ""
        layer = f" (Layer {self.layer_triggered})" if self.layer_triggered else ""
        return f"[{ts}] {icon} {self.action}{layer} | {self.session_id[:8]} | {self.direction}{tool}{reason}"


# ---------------------------------------------------------------------------
# Vanguard Error Responses
# ---------------------------------------------------------------------------

def make_block_response(request_id: Any, reason: str, rule_id: str = "VANGUARD") -> dict:
    """Create a valid JSON-RPC error response for a blocked call."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32600,
            "message": f"[McpVanguard] BLOCKED — {reason}",
            "data": {
                "blocked_by": "McpVanguard",
                "rule": rule_id,
            }
        }
    }
