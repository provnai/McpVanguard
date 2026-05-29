from __future__ import annotations

import json
from pathlib import Path

from scripts.phase7_status import build_phase7_status


def test_phase7_status_summarizes_local_and_live_boundaries():
    payload = build_phase7_status(2)

    assert "headline" in payload
    assert payload["local_validated"]
    assert payload["synthetic_validated"]
    assert isinstance(payload["live_open"], list)
    assert payload["measurement"]["attestation"] == "research-only"


def test_phase7_status_can_write_outputs(tmp_path, monkeypatch):
    json_path = tmp_path / "phase7-status.json"
    md_path = tmp_path / "phase7-status.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "phase7_status.py",
            "--iterations",
            "2",
            "--output-json",
            str(json_path),
            "--output-md",
            str(md_path),
        ],
    )
    from scripts.phase7_status import main

    assert main() == 0
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert "live_open" in data
    assert md_path.exists()
    assert "Still Open" in md_path.read_text(encoding="utf-8")
