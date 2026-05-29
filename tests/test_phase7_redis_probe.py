from __future__ import annotations

import json
from pathlib import Path

from scripts.phase7_redis_probe import main as redis_probe_main


def test_redis_probe_outputs(tmp_path, monkeypatch):
    json_path = tmp_path / "redis-probe.json"
    md_path = tmp_path / "redis-probe.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "phase7_redis_probe.py",
            "--iterations",
            "8",
            "--output-json",
            str(json_path),
            "--output-md",
            str(md_path),
        ],
    )
    assert redis_probe_main() == 0
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["native"]["mode"] == "in-memory"
    assert data["synthetic"]["mode"] == "synthetic-redis"
    assert md_path.exists()
