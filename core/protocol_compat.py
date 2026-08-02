"""Explicit MCP protocol compatibility boundaries.

This module deliberately separates protocol compatibility profiles from the
security deployment profiles (monitor, balanced, and strict). The 2026-07-28
stateless profile is a reserved boundary in this release: selecting it must
not silently fall back to the legacy stateful runtime.
"""

from __future__ import annotations

import hashlib
import re
from enum import Enum
from typing import Any, Mapping, Sequence


PROTOCOL_PROFILE_ENV = "VANGUARD_MCP_PROTOCOL_PROFILE"
MCP_2026_PROTOCOL_VERSION = "2026-07-28"
MCP_2026_SERVER_DISCOVER_METHOD = "server/discover"
MCP_2026_SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"
MCP_2026_REQUIRED_REQUEST_META = (
    "io.modelcontextprotocol/protocolVersion",
    "io.modelcontextprotocol/clientCapabilities",
)
MCP_2026_CACHEABLE_METHODS = frozenset(
    {
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/read",
        "resources/templates/list",
    }
)
MCP_2026_TRACE_CONTEXT_KEYS = ("traceparent", "tracestate", "baggage")
_TRACEPARENT_RE = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")
_MAX_TRACESTATE_LENGTH = 512
_MAX_BAGGAGE_LENGTH = 8192


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
    if (
        normalized_profile == ProtocolProfile.MCP_2026_07_28_STATELESS.value
        and method == MCP_2026_SERVER_DISCOVER_METHOD
    ):
        return None
    if method in UNSUPPORTED_2026_METHODS:
        return (
            f"MCP method {method!r} is not implemented by the active compatibility "
            "profile; the request was not forwarded."
        )
    return None


def stateless_request_issues(
    payload: Mapping[str, Any],
    *,
    method_headers: Sequence[str] = (),
    name_headers: Sequence[str] = (),
    protocol_headers: Sequence[str] = (),
) -> list[str]:
    """Validate the request contract required by the 2026 stateless profile.

    This is deliberately transport-independent. The caller still decides when
    the stateless runtime is enabled; until then the profile remains fail-closed.
    """

    issues: list[str] = []
    method = payload.get("method")
    if not isinstance(method, str) or not method:
        issues.append("MCP stateless requests require a non-empty method.")

    params = payload.get("params")
    if params is not None and not isinstance(params, Mapping):
        issues.append("MCP request params must be an object when present.")

    meta = params.get("_meta") if isinstance(params, Mapping) else None
    if not isinstance(meta, Mapping):
        issues.append("MCP stateless requests require params._meta.")
        meta = {}

    protocol_version = meta.get("io.modelcontextprotocol/protocolVersion")
    if protocol_version != MCP_2026_PROTOCOL_VERSION:
        issues.append(
            "params._meta.io.modelcontextprotocol/protocolVersion must be "
            f"{MCP_2026_PROTOCOL_VERSION!r}."
        )

    unique_protocol_headers = set(protocol_headers)
    if len(unique_protocol_headers) > 1:
        issues.append("Mcp-Protocol-Version contains conflicting duplicate values.")
    protocol_header = protocol_headers[0] if protocol_headers else ""
    if protocol_header != MCP_2026_PROTOCOL_VERSION:
        issues.append(
            "Mcp-Protocol-Version must be "
            f"{MCP_2026_PROTOCOL_VERSION!r} in the stateless MCP profile."
        )

    capabilities = meta.get("io.modelcontextprotocol/clientCapabilities")
    if not isinstance(capabilities, Mapping):
        issues.append(
            "params._meta.io.modelcontextprotocol/clientCapabilities must be an object."
        )

    issues.extend(
        routing_header_issues(
            profile=ProtocolProfile.MCP_2026_07_28_STATELESS.value,
            body_method=method if isinstance(method, str) else "",
            body_tool_name=(
                params.get("name", "")
                if isinstance(params, Mapping) and isinstance(params.get("name", ""), str)
                else ""
            ),
            method_headers=method_headers,
            name_headers=name_headers,
        )
    )

    issues.extend(stateless_trace_context_issues(payload))
    return issues


def _has_control_chars(value: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)


def stateless_trace_context_issues(payload: Mapping[str, Any]) -> list[str]:
    """Validate the official W3C trace fields carried in request ``_meta``."""

    params = payload.get("params")
    meta = params.get("_meta") if isinstance(params, Mapping) else None
    if not isinstance(meta, Mapping):
        return []

    issues: list[str] = []
    traceparent = meta.get("traceparent")
    if traceparent is not None:
        if not isinstance(traceparent, str):
            issues.append("_meta.traceparent must be a string when present.")
        else:
            match = _TRACEPARENT_RE.fullmatch(traceparent)
            if (
                not match
                or traceparent.startswith("ff-")
                or set(match.group(1)) == {"0"}
                or set(match.group(2)) == {"0"}
            ):
                issues.append("_meta.traceparent is not a valid W3C traceparent value.")

    tracestate = meta.get("tracestate")
    if tracestate is not None:
        if not isinstance(tracestate, str):
            issues.append("_meta.tracestate must be a string when present.")
        elif len(tracestate) > _MAX_TRACESTATE_LENGTH or _has_control_chars(tracestate):
            issues.append("_meta.tracestate exceeds the bounded trace-state format.")

    baggage = meta.get("baggage")
    if baggage is not None:
        if not isinstance(baggage, str):
            issues.append("_meta.baggage must be a string when present.")
        elif len(baggage) > _MAX_BAGGAGE_LENGTH or _has_control_chars(baggage):
            issues.append("_meta.baggage exceeds the bounded baggage format.")
    return issues


def extract_stateless_trace_context(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return safe audit fields for valid stateless trace context.

    Raw baggage is intentionally never returned because it may contain
    application-specific or sensitive values. Its digest supports correlation
    without turning audit logs into a baggage exfiltration surface.
    """

    if stateless_trace_context_issues(payload):
        return None
    params = payload.get("params")
    meta = params.get("_meta") if isinstance(params, Mapping) else None
    if not isinstance(meta, Mapping):
        return None

    trace_context: dict[str, Any] = {}
    for key in MCP_2026_TRACE_CONTEXT_KEYS[:2]:
        value = meta.get(key)
        if isinstance(value, str):
            trace_context[key] = value
    baggage = meta.get("baggage")
    if isinstance(baggage, str):
        trace_context["baggage_present"] = True
        trace_context["baggage_sha256"] = hashlib.sha256(baggage.encode("utf-8")).hexdigest()
    return trace_context or None


def build_server_discover_result(
    *,
    supported_versions: Sequence[str] = (MCP_2026_PROTOCOL_VERSION,),
    capabilities: Mapping[str, Any] | None = None,
    server_info: Mapping[str, Any] | None = None,
    instructions: str | None = None,
    ttl_ms: int = 0,
    cache_scope: str = "private",
) -> dict[str, Any]:
    """Build the canonical successful ``server/discover`` result envelope."""

    versions = list(dict.fromkeys(supported_versions))
    if not versions:
        raise ValueError("server/discover requires at least one protocol version.")
    if not isinstance(capabilities, Mapping):
        capabilities = {}
    if not isinstance(server_info, Mapping) or not server_info.get("name") or not server_info.get("version"):
        raise ValueError("server/discover requires server_info.name and server_info.version.")
    if not isinstance(ttl_ms, int) or isinstance(ttl_ms, bool) or ttl_ms < 0:
        raise ValueError("server/discover ttl_ms must be a non-negative integer.")
    if cache_scope not in {"private", "public"}:
        raise ValueError("server/discover cache_scope must be 'private' or 'public'.")
    return {
        "resultType": "complete",
        "ttlMs": ttl_ms,
        "cacheScope": cache_scope,
        "supportedVersions": versions,
        "capabilities": dict(capabilities),
        "_meta": {MCP_2026_SERVER_INFO_META_KEY: dict(server_info)},
        **({"instructions": instructions} if instructions is not None else {}),
    }


def normalize_stateless_result_response(
    response: Mapping[str, Any],
    *,
    request_method: str | None,
    default_ttl_ms: int = 0,
    default_cache_scope: str = "private",
) -> tuple[dict[str, Any], bool]:
    """Add the required 2026 result envelope fields without changing payloads.

    The 2026 profile requires ``resultType`` on successful results and cache
    hints on list/read responses. McpVanguard uses a zero-TTL private default
    when an upstream server omits those hints, preserving safety without
    pretending that a response is cacheable. Existing valid upstream values
    are preserved. The returned boolean indicates whether the envelope changed.
    """

    normalized = dict(response)
    result = normalized.get("result")
    if not isinstance(result, Mapping):
        return normalized, False

    result_copy = dict(result)
    changed = False
    if "resultType" not in result_copy:
        result_copy["resultType"] = "complete"
        changed = True

    if request_method in MCP_2026_CACHEABLE_METHODS and result_copy.get("resultType") == "complete":
        ttl_ms = result_copy.get("ttlMs", default_ttl_ms)
        if not isinstance(ttl_ms, int) or isinstance(ttl_ms, bool) or ttl_ms < 0:
            ttl_ms = default_ttl_ms
        cache_scope = result_copy.get("cacheScope", default_cache_scope)
        if cache_scope not in {"private", "public"}:
            cache_scope = default_cache_scope
        if "ttlMs" not in result_copy or result_copy["ttlMs"] != ttl_ms:
            result_copy["ttlMs"] = ttl_ms
            changed = True
        if "cacheScope" not in result_copy or result_copy["cacheScope"] != cache_scope:
            result_copy["cacheScope"] = cache_scope
            changed = True

    if changed:
        normalized["result"] = result_copy
    return normalized, changed


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
