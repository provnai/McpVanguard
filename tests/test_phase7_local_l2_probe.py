from __future__ import annotations

import json
from pathlib import Path

from scripts.phase7_local_l2_probe import main as probe_main


def test_local_l2_probe_outputs(tmp_path, monkeypatch):
    json_path = tmp_path / "probe.json"
    md_path = tmp_path / "probe.md"
    argv = [
        "phase7_local_l2_probe.py",
        "--iterations",
        "5",
        "--output-json",
        str(json_path),
        "--output-md",
        str(md_path),
    ]
    monkeypatch.setattr("sys.argv", argv)
    assert probe_main() == 0

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["backend"] == "mock-openai-compatible"
    assert data["runs"] == 5
    assert md_path.exists()


def test_local_l2_probe_exports_when_requested(monkeypatch):
    json_path = Path(r"C:\tmp\phase7-local-l2-probe.json")
    md_path = Path(r"C:\tmp\phase7-local-l2-probe.md")
    monkeypatch.setattr(
        "sys.argv",
        [
            "phase7_local_l2_probe.py",
            "--iterations",
            "8",
            "--output-json",
            str(json_path),
            "--output-md",
            str(md_path),
        ],
    )
    assert probe_main() == 0
    assert json_path.exists()
    assert md_path.exists()
