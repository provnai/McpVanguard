"""
core/taxonomy.py
Helpers for loading and reporting MCP-38 taxonomy coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

VALID_STATUSES = {"implemented", "partial", "gap"}
EXPECTED_IDS = [f"MCP-{index:02d}" for index in range(1, 39)]


@dataclass(frozen=True)
class TaxonomyEntry:
    taxonomy_id: str
    title: str
    status: str
    summary: str
    controls: tuple[str, ...]
    evidence: tuple[str, ...]


def load_mcp38_coverage(path: str | Path = "rules/mcp38_coverage.yaml") -> list[TaxonomyEntry]:
    coverage_path = Path(path)
    payload = yaml.safe_load(coverage_path.read_text(encoding="utf-8"))

    if not isinstance(payload, list):
        raise ValueError("MCP-38 coverage file must be a list of entries.")

    entries: list[TaxonomyEntry] = []
    seen_ids: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("Each MCP-38 coverage entry must be a mapping.")

        taxonomy_id = str(item.get("id", "")).strip().upper()
        title = str(item.get("title", "")).strip()
        status = str(item.get("status", "")).strip().lower()
        summary = str(item.get("summary", "")).strip()
        controls = _normalize_str_list(item.get("controls", []))
        evidence = _normalize_str_list(item.get("evidence", []))

        if not taxonomy_id:
            raise ValueError("Coverage entry is missing an id.")
        if taxonomy_id in seen_ids:
            raise ValueError(f"Duplicate taxonomy id in coverage map: {taxonomy_id}")
        if status not in VALID_STATUSES:
            raise ValueError(f"Unsupported taxonomy status for {taxonomy_id}: {status}")
        if not title:
            raise ValueError(f"Coverage entry {taxonomy_id} is missing a title.")
        if not summary:
            raise ValueError(f"Coverage entry {taxonomy_id} is missing a summary.")

        seen_ids.add(taxonomy_id)
        entries.append(
            TaxonomyEntry(
                taxonomy_id=taxonomy_id,
                title=title,
                status=status,
                summary=summary,
                controls=controls,
                evidence=evidence,
            )
        )

    actual_ids = [entry.taxonomy_id for entry in entries]
    if actual_ids != EXPECTED_IDS:
        raise ValueError(
            "MCP-38 coverage map must contain every taxonomy id from MCP-01 through MCP-38 in order."
        )

    return entries


def summarize_coverage(entries: Iterable[TaxonomyEntry]) -> dict[str, int]:
    summary = {status: 0 for status in VALID_STATUSES}
    total = 0
    for entry in entries:
        summary[entry.status] += 1
        total += 1
    summary["total"] = total
    return summary


def _normalize_str_list(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("Coverage list fields must be lists of strings.")
    normalized: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            normalized.append(text)
    return tuple(normalized)
