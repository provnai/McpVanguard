from __future__ import annotations

import json
import os
from pathlib import Path
from scripts.phase7_measure_local import build_phase7_measurement, build_phase7_results_log


def test_build_phase7_measurement_and_log():
    measurement = build_phase7_measurement()
    log = build_phase7_results_log(measurement, workflow_run_url="https://example.com/run/1")

    assert "## Layer 3 Profile" in log
    assert "## Local L2 Profile" in log
    assert "Final conclusion:" in log
    assert measurement["decision"] in {
        "CPU path is good enough; keep GPU work research-only",
        "local L2 is stable and supported; continue with current semantic path",
    }


def test_export_phase7_artifacts_from_env():
    if os.getenv("PHASE7_EXPORT_ARTIFACTS") == "0":
        return

    json_path = os.getenv("PHASE7_OUTPUT_JSON") or r"C:\tmp\phase7-measurement.json"
    md_path = os.getenv("PHASE7_OUTPUT_MD") or r"C:\tmp\phase7-results-log.md"
    workflow_run_url = os.getenv("PHASE7_WORKFLOW_RUN_URL")

    measurement = build_phase7_measurement()
    Path(json_path).parent.mkdir(parents=True, exist_ok=True)
    Path(json_path).write_text(json.dumps(measurement, indent=2), encoding="utf-8")
    Path(md_path).write_text(build_phase7_results_log(measurement, workflow_run_url=workflow_run_url), encoding="utf-8")
    assert Path(json_path).exists()
    assert Path(md_path).exists()
