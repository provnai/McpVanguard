"""
core/models.py
Pydantic models for JSON-RPC 2.0 messages used by MCP.
"""

from __future__ import annotations
from typing import Any, Literal, Optional, Union
from pydantic import BaseModel, Field
import time
import uuid
import platform


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


class SafeZone(BaseModel):
    """Definition of a restricted 'jail' for a specific tool."""
    tool: str
    allowed_prefixes: list[str]
    max_entropy: Optional[float] = None
    recursive: bool = True


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

    def to_log_line(self, format: str = "text") -> str:
        if format == "json":
            return self.model_dump_json()
        
        from datetime import datetime
        ts = datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        tag = f"[{self.action}]"
        tool = f" [{self.tool_name}]" if self.tool_name else ""
        reason = f" — {self.blocked_reason}" if self.blocked_reason else ""
        layer = f" (Layer {self.layer_triggered})" if self.layer_triggered else ""
        return f"[{ts}] {tag:<9} {layer:<10} | {self.session_id[:8]} | {self.direction}{tool}{reason}"


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


# ---------------------------------------------------------------------------
# Task 4: Secure Tool Manifest (OPA-Ready / VEX Forensic Handoff)
# ---------------------------------------------------------------------------

class SecureToolManifest(BaseModel):
    """
    Standardized forensic evidence package generated when a tool call is blocked.

    This format is designed to be:
    - OPA-compatible: Can be fed directly as `input` to an OPA/Rego policy.
    - Cerbos-compatible: Maps to the Principal-Action-Resource model.
    - VEX-ready: Provides rich context for TitanGate's formal verification engine.
    """
    # --- Event Identity ---
    manifest_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_utc: float = Field(default_factory=time.time)
    session_id: str
    blocked_by_layer: int

    # --- OPA/Cerbos: Principal-Action-Resource ---
    principal: dict[str, Any] = Field(default_factory=dict)
    # e.g. {"id": "agent-001", "roles": ["untrusted"], "jwt_claims": {...}}
    action: str  # e.g. "tools/call"
    resource: dict[str, Any] = Field(default_factory=dict)
    # e.g. {"kind": "Filesystem", "id": "/etc/passwd", "tool": "read_file"}

    # --- Forensic Context ---
    rule_triggered: Optional[str] = None
    block_reason: str
    shannon_entropy: Optional[float] = None  # H(X) of the response body, if applicable
    entropy_risk_label: Optional[str] = None
    
    # --- Sensor Data (Hardening Spec 01) ---
    gate_sensors: dict[str, Any] = Field(default_factory=dict)
    # e.g. {"path_violation": {...}, "entropy_violation": {...}}

    # --- Environment Snapshot ---
    os_platform: str = Field(default_factory=platform.system)
    python_version: str = Field(default_factory=lambda: platform.python_version())

    def to_opa_input(self) -> dict:
        """Serialize as an OPA policy evaluation input document."""
        return {
            "input": {
                "principal": self.principal,
                "action": {"name": self.action},
                "resource": self.resource,
                "context": {
                    "manifest_id": self.manifest_id,
                    "session_id": self.session_id,
                    "timestamp": self.timestamp_utc,
                    "entropy": {
                        "score": self.shannon_entropy,
                        "risk": self.entropy_risk_label,
                    },
                    "environment": {
                        "os": self.os_platform,
                        "python": self.python_version,
                    }
                }
            }
        }


def build_manifest(
    session_id: str,
    message: dict,
    result: "InspectionResult",
    entropy: Optional[float] = None,
    entropy_label: Optional[str] = None,
) -> SecureToolManifest:
    """Helper to build a SecureToolManifest from a blocked InspectionResult."""
    params = message.get("params", {})
    tool_name = params.get("name", "unknown")
    args = params.get("arguments", {})
    path = args.get("path") or args.get("filepath") or args.get("dir", "")

    # Build hardening-spec gate sensors
    gate_sensors = {}
    if "SAFEZONE" in (rule_id or ""):
        gate_sensors["path_violation"] = {
            "attempted_path": path,
            "resolved_physical_path": "RESOLVED_SYMLINK_LOGIC_ACTIVE", # Placeholder for L1 resolution
            "policy_root": "RESTRICTED_SAFE_ZONE"
        }
    
    if entropy is not None:
        gate_sensors["entropy_violation"] = {
            "bits_per_byte": entropy,
            "total_bytes": len(message.get("params", {}).get("content", "")), # or response len
            "exfiltration_risk_score": 1.0 if entropy > 7.5 else (entropy / 7.5)
        }

    return SecureToolManifest(
        session_id=session_id,
        blocked_by_layer=result.layer_triggered or 1,
        principal={"id": session_id, "roles": ["agent"]},
        action=message.get("method", "tools/call"),
        resource={"kind": "Filesystem", "id": path, "tool": tool_name},
        rule_triggered=rule_id,
        block_reason=result.block_reason or "Unknown",
        shannon_entropy=entropy,
        entropy_risk_label=entropy_label,
        gate_sensors=gate_sensors,
    )
