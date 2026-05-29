from __future__ import annotations

import json
from pathlib import Path

from scripts.phase7_prepare_log import build_phase7_log_draft


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_build_phase7_log_draft(tmp_path):
    benchmark_run = _write_json(tmp_path / "benchmark-run.json", {"summary": {"total": 2, "passed": 2, "failed": 0, "pass_rate": 1.0}})
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

    draft = build_phase7_log_draft(
        benchmark_run,
        gpu_harden,
        gpu_thresholds,
        date="2026-05-26",
        environment="GitHub Actions ubuntu-latest",
        backend="local OpenAI-compatible",
        profile="balanced",
        workflow_run_url="https://github.com/provnai/McpVanguard/actions/runs/1",
        artifact_location="phase7-measurement-artifacts",
    )

    assert "# Phase 7 Results Log Draft" in draft
    assert "- Date: 2026-05-26" in draft
    assert "- Environment: GitHub Actions ubuntu-latest" in draft
    assert "recommended warn/block pair: 0.50 / 0.80" in draft
    assert "pending live measurement" in draft
