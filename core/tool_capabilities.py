"""
core/tool_capabilities.py

Heuristic capability inference for MCP tools.

The classifier is intentionally conservative: it improves behavioral accounting
and audit visibility, but explicit operator policy and deterministic rules remain
the enforcement boundary.
"""

from __future__ import annotations

import json
import os
from enum import Enum
from typing import Any


class ToolCapability(str, Enum):
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    SHELL_EXEC = "shell_exec"
    NETWORK_REQUEST = "network_request"
    DATABASE_QUERY = "database_query"
    BROWSER_AUTOMATION = "browser_automation"
    CREDENTIAL_ADJACENT = "credential_adjacent"
    METADATA_SENSITIVE = "metadata_sensitive"
    UNKNOWN = "unknown"


_READ_NAME_HINTS = ("read", "fetch", "load", "open", "cat", "view", "get_file", "get_document")
_WRITE_NAME_HINTS = ("write", "save", "put", "create", "append", "edit", "update", "delete", "remove")
_SHELL_NAME_HINTS = ("shell", "exec", "command", "run", "terminal", "powershell", "bash", "subprocess")
_NETWORK_NAME_HINTS = ("http", "url", "fetch_url", "request", "webhook", "curl", "download", "upload")
_DATABASE_NAME_HINTS = ("sql", "query", "database", "db", "postgres", "mysql", "sqlite", "mongo")
_BROWSER_NAME_HINTS = ("browser", "page", "playwright", "selenium", "click", "navigate", "screenshot")
_METADATA_NAME_HINTS = ("list", "discover", "describe", "schema", "metadata", "manifest", "capability")
_CREDENTIAL_HINTS = (
    "credential",
    "secret",
    "token",
    "password",
    "passwd",
    "shadow",
    ".env",
    ".ssh",
    "id_rsa",
    ".aws",
    ".kube",
)
_PATH_KEYS = {"path", "file", "filepath", "filename", "directory", "dir", "target", "source", "cwd"}
_URL_KEYS = {"url", "uri", "endpoint", "host", "hostname", "webhook", "address"}
_COMMAND_KEYS = {"command", "cmd", "shell", "script", "code", "argv", "args", "executable"}
_QUERY_KEYS = {"query", "sql", "statement", "database", "collection"}


def _override_map() -> dict[str, set[ToolCapability]]:
    raw = os.getenv("VANGUARD_TOOL_CAPABILITIES_JSON", "").strip()
    if not raw:
        return {}

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}

    if not isinstance(payload, dict):
        return {}

    overrides: dict[str, set[ToolCapability]] = {}
    for tool, values in payload.items():
        if not isinstance(tool, str):
            continue
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            continue
        caps = set()
        for value in values:
            try:
                caps.add(ToolCapability(str(value)))
            except ValueError:
                continue
        if caps:
            overrides[tool.lower()] = caps
    return overrides


def _walk_keys_and_values(value: Any):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key).lower(), nested
            yield from _walk_keys_and_values(nested)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys_and_values(item)


def infer_tool_definition_capabilities(tool: dict[str, Any]) -> set[ToolCapability]:
    """Infer capabilities from a tools/list tool definition and JSON schema fields."""
    if not isinstance(tool, dict):
        return {ToolCapability.UNKNOWN}

    synthetic_message = {
        "name": tool.get("name", ""),
        "description": tool.get("description", ""),
        "params": {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "arguments": {},
        },
    }
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    properties = schema.get("properties") if isinstance(schema, dict) else {}
    if isinstance(properties, dict):
        synthetic_message["params"]["arguments"] = {
            key: value.get("description", "") if isinstance(value, dict) else ""
            for key, value in properties.items()
        }

    return infer_tool_capabilities(synthetic_message)


def infer_tool_capabilities(message: dict[str, Any]) -> set[ToolCapability]:
    """Infer coarse tool capabilities from tool name, descriptions, and arguments."""
    params = message.get("params") if isinstance(message, dict) else {}
    params = params if isinstance(params, dict) else {}
    tool_name = str(params.get("name") or message.get("name") or "").strip()
    arguments = params.get("arguments")
    arguments = arguments if isinstance(arguments, dict) else {}
    description = str(params.get("description") or message.get("description") or "")

    overrides = _override_map()
    if tool_name.lower() in overrides:
        return overrides[tool_name.lower()]

    text = f"{tool_name} {description}".lower()
    caps: set[ToolCapability] = set()

    if any(hint in text for hint in _READ_NAME_HINTS):
        caps.add(ToolCapability.FILESYSTEM_READ)
    if any(hint in text for hint in _WRITE_NAME_HINTS):
        caps.add(ToolCapability.FILESYSTEM_WRITE)
    if any(hint in text for hint in _SHELL_NAME_HINTS):
        caps.add(ToolCapability.SHELL_EXEC)
    if any(hint in text for hint in _NETWORK_NAME_HINTS):
        caps.add(ToolCapability.NETWORK_REQUEST)
    if any(hint in text for hint in _DATABASE_NAME_HINTS):
        caps.add(ToolCapability.DATABASE_QUERY)
    if any(hint in text for hint in _BROWSER_NAME_HINTS):
        caps.add(ToolCapability.BROWSER_AUTOMATION)
    if any(hint in text for hint in _METADATA_NAME_HINTS):
        caps.add(ToolCapability.METADATA_SENSITIVE)

    for key, value in _walk_keys_and_values(arguments):
        value_text = str(value).lower()
        if key in _PATH_KEYS:
            caps.add(ToolCapability.FILESYSTEM_READ)
        if key in _URL_KEYS or value_text.startswith(("http://", "https://")):
            caps.add(ToolCapability.NETWORK_REQUEST)
        if key in _COMMAND_KEYS:
            caps.add(ToolCapability.SHELL_EXEC)
        if key in _QUERY_KEYS:
            caps.add(ToolCapability.DATABASE_QUERY)
        if any(hint in value_text for hint in _CREDENTIAL_HINTS):
            caps.add(ToolCapability.CREDENTIAL_ADJACENT)

    if ToolCapability.SHELL_EXEC in caps:
        caps.add(ToolCapability.FILESYSTEM_WRITE)

    return caps or {ToolCapability.UNKNOWN}


def capability_values(capabilities: set[ToolCapability]) -> list[str]:
    """Return stable string values for logs and JSON fields."""
    return sorted(cap.value for cap in capabilities)


def capabilities_from_manifest(manifest: dict[str, Any], tool_name: str) -> set[ToolCapability]:
    """
    Return inferred capabilities for a tool from a capability manifest.

    Manifests are produced by `core.capability_fingerprint`. Missing or invalid
    labels resolve to UNKNOWN so callers do not silently assume a tool is safe.
    """
    tools_wrapper = manifest.get("tools") if isinstance(manifest, dict) else None
    tools = tools_wrapper.get("tools") if isinstance(tools_wrapper, dict) else None
    if not isinstance(tools, list):
        return {ToolCapability.UNKNOWN}

    target = tool_name.strip().lower()
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        if str(tool.get("name") or "").strip().lower() != target:
            continue
        labels = tool.get("tool_capabilities")
        if not isinstance(labels, list):
            return {ToolCapability.UNKNOWN}
        capabilities: set[ToolCapability] = set()
        for label in labels:
            try:
                capabilities.add(ToolCapability(str(label)))
            except ValueError:
                continue
        return capabilities or {ToolCapability.UNKNOWN}

    return {ToolCapability.UNKNOWN}
