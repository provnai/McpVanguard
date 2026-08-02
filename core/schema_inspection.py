"""Bounded inspection for MCP tool input schemas.

The 2026 protocol permits full JSON Schema 2020-12. McpVanguard validates the
schema document itself, never resolves external references, and bounds the
document before handing it to any other metadata or capability logic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator


MAX_SCHEMA_BYTES = 128 * 1024
MAX_SCHEMA_NODES = 2048
MAX_SCHEMA_DEPTH = 32


@dataclass(frozen=True)
class SchemaInspectionResult:
    valid: bool
    issues: tuple[str, ...] = ()
    node_count: int = 0
    max_depth: int = 0
    external_ref_count: int = 0


def inspect_tool_input_schema(schema: Any) -> SchemaInspectionResult:
    """Validate one tool schema without network access or reference expansion."""

    if schema is None:
        return SchemaInspectionResult(valid=True)
    if not isinstance(schema, dict):
        return SchemaInspectionResult(valid=False, issues=("inputSchema must be a JSON object.",))

    try:
        encoded = json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        return SchemaInspectionResult(valid=False, issues=(f"inputSchema is not JSON-serializable: {exc}.",))
    if len(encoded.encode("utf-8")) > MAX_SCHEMA_BYTES:
        return SchemaInspectionResult(
            valid=False,
            issues=(f"inputSchema exceeds the {MAX_SCHEMA_BYTES}-byte bound.",),
        )

    issues: list[str] = []
    node_count = 0
    max_depth = 0
    external_ref_count = 0

    def walk(value: Any, depth: int) -> None:
        nonlocal node_count, max_depth, external_ref_count
        node_count += 1
        max_depth = max(max_depth, depth)
        if node_count > MAX_SCHEMA_NODES:
            return
        if depth > MAX_SCHEMA_DEPTH:
            return
        if isinstance(value, dict):
            for key in ("$ref", "$dynamicRef"):
                if key not in value:
                    continue
                reference = value[key]
                if not isinstance(reference, str):
                    issues.append(f"{key} must be a string when present.")
                elif not reference.startswith("#"):
                    external_ref_count += 1
            for child in value.values():
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                walk(child, depth + 1)

    walk(schema, 0)
    if node_count > MAX_SCHEMA_NODES:
        issues.append(f"inputSchema exceeds the {MAX_SCHEMA_NODES}-node bound.")
    if max_depth > MAX_SCHEMA_DEPTH:
        issues.append(f"inputSchema exceeds the depth-{MAX_SCHEMA_DEPTH} bound.")

    if not issues:
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            issues.append(f"inputSchema is not valid JSON Schema 2020-12: {exc}.")

    return SchemaInspectionResult(
        valid=not issues,
        issues=tuple(dict.fromkeys(issues)),
        node_count=node_count,
        max_depth=max_depth,
        external_ref_count=external_ref_count,
    )
