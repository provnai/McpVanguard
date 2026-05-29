from __future__ import annotations

import json
from pathlib import Path

from scripts.phase7_live_evidence_probe import build_live_evidence_probe


def test_live_evidence_probe_reports_unavailable_when_unconfigured():
    payload = build_live_evidence_probe(2)

    assert payload["semantic"]["status"] in {"unavailable", "live"}
    assert payload["redis"]["status"] in {"unavailable", "live"}
    assert payload["decision"]["attestation"] == "research-only"


def test_live_evidence_probe_can_write_outputs(tmp_path, monkeypatch):
    json_path = tmp_path / "live-evidence.json"
    md_path = tmp_path / "live-evidence.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "phase7_live_evidence_probe.py",
            "--iterations",
            "2",
            "--output-json",
            str(json_path),
            "--output-md",
            str(md_path),
        ],
    )
    from scripts.phase7_live_evidence_probe import main

    assert main() == 0
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert "semantic" in data and "redis" in data
    assert md_path.exists()
