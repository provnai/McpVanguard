from __future__ import annotations

import json
from pathlib import Path

from scripts.phase7_closeout import build_closeout_summary


def test_closeout_summary_lists_open_items():
    payload = build_closeout_summary(2)
    assert "evidence" in payload
    assert "remaining_open" in payload
    assert isinstance(payload["remaining_open"], list)


def test_closeout_summary_can_write_outputs(tmp_path, monkeypatch):
    json_path = tmp_path / "closeout.json"
    md_path = tmp_path / "closeout.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "phase7_closeout.py",
            "--iterations",
            "2",
            "--output-json",
            str(json_path),
            "--output-md",
            str(md_path),
        ],
    )
    from scripts.phase7_closeout import main

    assert main() == 0
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert "recommended_status" in data
    assert md_path.exists()
