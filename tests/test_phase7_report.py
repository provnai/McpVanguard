from __future__ import annotations

import json
from pathlib import Path

from scripts.phase7_report import generate_phase7_report


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_generate_phase7_report(tmp_path):
    benchmark_run = _write_json(
        tmp_path / "benchmark-run.json",
        {
            "summary": {"total": 2, "passed": 2, "failed": 0, "pass_rate": 1.0},
        },
    )
    gpu_harden = _write_json(
        tmp_path / "gpu-harden.json",
        {
            "summary": {"total": 4, "passed": 4, "failed": 0},
            "quality": {
                "adversarial_block_rate": 1.0,
                "benign_allow_rate": 1.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
            },
        },
    )
    gpu_thresholds = _write_json(
        tmp_path / "gpu-thresholds.json",
        {
            "thresholds": [
                {
                    "warn_threshold": 0.5,
                    "block_threshold": 0.8,
                    "summary": {"pass_rate": 1.0},
                    "quality": {
                        "adversarial_block_rate": 1.0,
                        "benign_allow_rate": 1.0,
                        "false_positive_rate": 0.0,
                    },
                }
            ]
        },
    )

    report = generate_phase7_report(benchmark_run, gpu_harden, gpu_thresholds)

    assert "# Phase 7 Measurement Summary" in report
    assert "recommended warn/block pair: 0.50 / 0.80" in report
    assert "combined benchmark pass rate: 100%" in report
    assert "This report is generated from the JSON artifacts" in report

