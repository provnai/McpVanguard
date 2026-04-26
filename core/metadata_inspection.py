"""
core/metadata_inspection.py
Inspection for model-visible metadata returned by MCP servers.

This module focuses on metadata that can influence model behavior before any
tool call is made, especially initialize instructions and tool descriptions.
"""

from __future__ import annotations

import concurrent.futures
from typing import Any, Iterable

from core.models import InspectionResult, RuleMatch
from core import safe_regex

# ReDoS guard: match each pattern in a thread with a hard timeout.
# Fail-closed: timeout → BLOCK (consistent with rules_engine.py).
_META_MATCH_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="vg-meta")
_META_REGEX_TIMEOUT = 0.1  # 100 ms


_PATTERN_SPECS: list[tuple[str, str, str]] = [
    (
        "META-001",
        r"(?i)(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|system|safety|these)\s+(instructions?|rules?|guidelines?|prompts?)",
        "Prompt-injection language detected in MCP metadata.",
    ),
    (
        "META-002",
        r"(?i)(you are now|pretend to be|act as|you must now)\b",
        "Persona-switching language detected in MCP metadata.",
    ),
    (
        "META-003",
        r"(?i)(reveal|print|output|send|exfiltrate|leak)\s+.*(system prompt|env vars?|environment variables?|secrets?|ssh keys?|credentials?)",
        "Exfiltration-oriented instructions detected in MCP metadata.",
    ),
    (
        "META-004",
        r"(?i)(bypass|disable|override)\s+.*(safety|policy|guardrails?|protections?)",
        "Safety-bypass language detected in MCP metadata.",
    ),
]

_COMPILED_PATTERNS = [
    (rule_id, safe_regex.compile(pattern), message)
    for rule_id, pattern, message in _PATTERN_SPECS
]


def _iter_tool_metadata_strings(tool: dict[str, Any]) -> Iterable[tuple[str, str]]:
    candidates = [
        ("result.tools[].name", tool.get("name")),
        ("result.tools[].title", tool.get("title")),
        ("result.tools[].description", tool.get("description")),
    ]

    annotations = tool.get("annotations")
    if isinstance(annotations, dict):
        for key, value in annotations.items():
            if isinstance(value, str):
                candidates.append((f"result.tools[].annotations.{key}", value))

    input_schema = tool.get("inputSchema")
    if isinstance(input_schema, dict):
        candidates.extend(_iter_schema_strings(input_schema, "result.tools[].inputSchema"))

    for field, value in candidates:
        if isinstance(value, str) and value.strip():
            yield field, value


def _iter_schema_strings(schema: dict[str, Any], prefix: str) -> Iterable[tuple[str, str]]:
    for key in ("description", "title", "default"):
        value = schema.get(key)
        if isinstance(value, str) and value.strip():
            yield f"{prefix}.{key}", value

    examples = schema.get("examples")
    if isinstance(examples, list):
        for index, example in enumerate(examples):
            if isinstance(example, str) and example.strip():
                yield f"{prefix}.examples[{index}]", example

    enum_values = schema.get("enum")
    if isinstance(enum_values, list):
        for index, enum_value in enumerate(enum_values):
            if isinstance(enum_value, str) and enum_value.strip():
                yield f"{prefix}.enum[{index}]", enum_value

    properties = schema.get("properties")
    if isinstance(properties, dict):
        for key, prop in properties.items():
            if isinstance(prop, dict):
                yield from _iter_schema_strings(prop, f"{prefix}.properties.{key}")

    items = schema.get("items")
    if isinstance(items, dict):
        yield from _iter_schema_strings(items, f"{prefix}.items")


def inspect_initialize_payload(payload: dict[str, Any]) -> InspectionResult | None:
    result = payload.get("result")
    if not isinstance(result, dict):
        return None

    instructions = result.get("instructions")
    if not isinstance(instructions, str) or not instructions.strip():
        return None

    return _inspect_strings([("result.instructions", instructions)])


def inspect_tool_list_payload(payload: dict[str, Any]) -> InspectionResult | None:
    result = payload.get("result")
    if not isinstance(result, dict):
        return None

    tools = result.get("tools")
    if not isinstance(tools, list):
        return None

    strings: list[tuple[str, str]] = []
    for tool in tools:
        if isinstance(tool, dict):
            strings.extend(_iter_tool_metadata_strings(tool))

    if not strings:
        return None

    return _inspect_strings(strings)


def inspect_tool_metadata(tool: dict[str, Any]) -> InspectionResult | None:
    strings = list(_iter_tool_metadata_strings(tool))
    if not strings:
        return None
    return _inspect_strings(strings)


def filter_poisoned_tools(tools: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[tuple[dict[str, Any], InspectionResult]]]:
    safe_tools: list[dict[str, Any]] = []
    dropped_tools: list[tuple[dict[str, Any], InspectionResult]] = []

    for tool in tools:
        result = inspect_tool_metadata(tool)
        if result and not result.allowed:
            dropped_tools.append((tool, result))
        else:
            safe_tools.append(tool)

    return safe_tools, dropped_tools


def _inspect_strings(strings: list[tuple[str, str]]) -> InspectionResult | None:
    matches: list[RuleMatch] = []

    for field, value in strings:
        for rule_id, pattern, message in _COMPILED_PATTERNS:
            if safe_regex.is_re2_pattern(pattern):
                try:
                    found = pattern.search(value)
                except Exception:
                    matches.append(
                        RuleMatch(
                            rule_id="META-REDOS",
                            rule_name="Metadata Inspection",
                            severity="HIGH",
                            action="BLOCK",
                            matched_field=field,
                            matched_value=value[:200],
                            message="Metadata pattern match failed under RE2 (fail-closed).",
                        )
                    )
                    continue
                if not found:
                    continue
                matches.append(
                    RuleMatch(
                        rule_id=rule_id,
                        rule_name="Metadata Inspection",
                        severity="HIGH",
                        action="BLOCK",
                        matched_field=field,
                        matched_value=value[:200],
                        message=message,
                    )
                )
                continue

            try:
                future = _META_MATCH_POOL.submit(pattern.search, value)
                found = future.result(timeout=_META_REGEX_TIMEOUT)
            except concurrent.futures.TimeoutError:
                # Fail-closed: a pattern that times out is treated as a match
                # to prevent a ReDoS-crafted metadata payload from bypassing inspection.
                matches.append(
                    RuleMatch(
                        rule_id="META-REDOS",
                        rule_name="Metadata Inspection",
                        severity="HIGH",
                        action="BLOCK",
                        matched_field=field,
                        matched_value=value[:200],
                        message="Metadata pattern match timed out (ReDoS guard — fail-closed).",
                    )
                )
                continue
            if not found:
                continue
            matches.append(
                RuleMatch(
                    rule_id=rule_id,
                    rule_name="Metadata Inspection",
                    severity="HIGH",
                    action="BLOCK",
                    matched_field=field,
                    matched_value=value[:200],
                    message=message,
                )
            )

    if not matches:
        return None

    return InspectionResult.block(
        reason=matches[0].message or "Suspicious MCP metadata detected.",
        layer=1,
        rule_matches=matches,
    )
