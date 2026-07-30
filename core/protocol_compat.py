"""Explicit MCP protocol compatibility boundaries.

This module deliberately separates protocol compatibility profiles from the
security deployment profiles (monitor, balanced, and strict). The 2026-07-28
stateless profile is a reserved boundary in this release: selecting it must
not silently fall back to the legacy stateful runtime.
"""

from __future__ import annotations

from enum import Enum
from typing import Sequence


PROTOCOL_PROFILE_ENV = "VANGUARD_MCP_PROTOCOL_PROFILE"


class ProtocolProfile(str, Enum):
    """Supported or explicitly reserved MCP protocol profiles."""

    LEGACY_STATEFUL = "legacy_stateful"
    MCP_2026_07_28_STATELESS = "mcp_2026_07_28_stateless"


UNSUPPORTED_2026_METHODS = frozenset(
    {
        "server/discover",
        "subscriptions/listen",
        "tasks/get",
        "tasks/update",
        "tasks/result",
        "tasks/list",
        "resources/subscribe",
        "resources/unsubscribe",
    }
)


def resolve_protocol_profile(value: str | None = None) -> str:
    """Return a validated protocol profile, defaulting to legacy stateful."""

    normalized = (value or ProtocolProfile.LEGACY_STATEFUL.value).strip().lower()
    if not normalized:
        normalized = ProtocolProfile.LEGACY_STATEFUL.value
    valid = {profile.value for profile in ProtocolProfile}
    if normalized not in valid:
        raise ValueError(
            f"Unknown MCP protocol profile '{value}'. "
            f"Valid values: {', '.join(sorted(valid))}"
        )
    return normalized


def routing_header_issues(
    *,
    profile: str,
    body_method: str,
    body_tool_name: str,
    method_headers: Sequence[str],
    name_headers: Sequence[str],
) -> list[str]:
    """Validate routing headers without applying a transport-side policy.

    Legacy clients may omit the future headers. Conflicting duplicates are
    rejected in every profile, and the reserved stateless profile defines the
    required-header contract for its future implementation.
    """

    issues: list[str] = []
    unique_methods = set(method_headers)
    unique_names = set(name_headers)

    if len(unique_methods) > 1:
        issues.append("Mcp-Method contains conflicting duplicate values.")
    if len(unique_names) > 1:
        issues.append("Mcp-Name contains conflicting duplicate values.")

    method_header = method_headers[0] if method_headers else ""
    name_header = name_headers[0] if name_headers else ""
    normalized_profile = resolve_protocol_profile(profile)

    if normalized_profile == ProtocolProfile.MCP_2026_07_28_STATELESS.value:
        if not method_header:
            issues.append("Mcp-Method is required in the stateless MCP profile.")
        if body_method == "tools/call" and not name_header:
            issues.append("Mcp-Name is required for tools/call in the stateless MCP profile.")

    if method_header and method_header != body_method:
        issues.append(
            f"Mcp-Method={method_header!r} does not match body method={body_method!r}."
        )
    if name_header and body_method == "tools/call" and name_header != body_tool_name:
        issues.append(
            f"Mcp-Name={name_header!r} does not match body params.name={body_tool_name!r}."
        )

    return issues


def unsupported_protocol_reason(profile: str, method: str) -> str | None:
    """Return a fail-closed reason for an unsupported profile or method."""

    normalized_profile = resolve_protocol_profile(profile)
    if normalized_profile == ProtocolProfile.MCP_2026_07_28_STATELESS.value:
        return (
            "The MCP 2026-07-28 stateless profile is reserved but not implemented; "
            "the request was not forwarded."
        )
    if method in UNSUPPORTED_2026_METHODS:
        return (
            f"MCP method {method!r} is not implemented by the active compatibility "
            "profile; the request was not forwarded."
        )
    return None


def unsupported_method_response(request_id: object, reason: str) -> dict:
    """Build a stable JSON-RPC response for a rejected unsupported method."""

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32601,
            "message": "MCP method is not supported by the active compatibility profile.",
            "data": {
                "blocked_by": "McpVanguard",
                "rule": "VANGUARD-MCP-PROTOCOL-UNSUPPORTED",
                "reason": reason,
            },
        },
    }
