from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _fmt_pct(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.0%}"


def _fmt_num(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "n/a"


def _best_threshold_entry(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not entries:
        return None
    return sorted(
        entries,
        key=lambda entry: (
            float(entry.get("summary", {}).get("passed", 0)),
            float(entry.get("quality", {}).get("adversarial_block_rate", 0.0)),
            float(entry.get("quality", {}).get("benign_allow_rate", 0.0)),
            -float(entry.get("quality", {}).get("false_positive_rate", 0.0)),
        ),
        reverse=True,
    )[0]


def generate_phase7_report(
    benchmark_run_path: str | Path,
    gpu_harden_path: str | Path,
    gpu_thresholds_path: str | Path,
) -> str:
    benchmark_run = _load_json(benchmark_run_path)
    gpu_harden = _load_json(gpu_harden_path)
    gpu_thresholds = _load_json(gpu_thresholds_path)

    benchmark_summary = benchmark_run.get("summary", {})
    hardening_summary = gpu_harden.get("summary", {})
    hardening_quality = gpu_harden.get("quality", {})
    best_threshold = _best_threshold_entry(gpu_thresholds.get("thresholds", []))

    lines: list[str] = []
    lines.append("# Phase 7 Measurement Summary")
    lines.append("")
    lines.append("## Baseline Commands")
    lines.append(f"- `benchmark-run`: {benchmark_run_path}")
    lines.append(f"- `gpu-harden`: {gpu_harden_path}")
    lines.append(f"- `gpu-thresholds`: {gpu_thresholds_path}")
    lines.append("")
    lines.append("## Hardening Snapshot")
    lines.append(f"- total cases: {hardening_summary.get('total', 'n/a')}")
    lines.append(f"- passed: {hardening_summary.get('passed', 'n/a')}")
    lines.append(f"- failed: {hardening_summary.get('failed', 'n/a')}")
    lines.append(f"- adversarial block rate: {_fmt_pct(hardening_quality.get('adversarial_block_rate'))}")
    lines.append(f"- benign allow rate: {_fmt_pct(hardening_quality.get('benign_allow_rate'))}")
    lines.append(f"- false positive rate: {_fmt_pct(hardening_quality.get('false_positive_rate'))}")
    lines.append("")
    lines.append("## Benchmark Snapshot")
    lines.append(f"- total cases: {benchmark_summary.get('total', 'n/a')}")
    lines.append(f"- passed: {benchmark_summary.get('passed', 'n/a')}")
    lines.append(f"- failed: {benchmark_summary.get('failed', 'n/a')}")
    lines.append("")
    lines.append("## Threshold Sweep")
    if best_threshold is None:
        lines.append("- no threshold entries found")
    else:
        lines.append(
            f"- recommended warn/block pair: {_fmt_num(best_threshold.get('warn_threshold'))} / {_fmt_num(best_threshold.get('block_threshold'))}"
        )
        quality = best_threshold.get("quality", {})
        summary = best_threshold.get("summary", {})
        lines.append(f"- pass rate: {_fmt_pct(summary.get('pass_rate'))}")
        lines.append(f"- adversarial block rate: {_fmt_pct(quality.get('adversarial_block_rate'))}")
        lines.append(f"- benign allow rate: {_fmt_pct(quality.get('benign_allow_rate'))}")
        lines.append(f"- false positive rate: {_fmt_pct(quality.get('false_positive_rate'))}")
    lines.append("")
    lines.append("## Decision Snapshot")
    lines.append("- L3 bottleneck evidence: pending Phase 7 live measurements")
    lines.append("- local L2 stability: validated at the corpus level; live backend profiling still needed")
    lines.append("- deeper GPU work: keep research-only until the CI/scheduled measurement lane records real results")
    lines.append("")
    lines.append("## Notes")
    lines.append(f"- combined benchmark pass rate: {_fmt_pct(benchmark_summary.get('pass_rate'))}")
    lines.append(f"- combined false negative rate: {_fmt_pct(hardening_quality.get('false_negative_rate'))}")
    lines.append("")
    lines.append("This report is generated from the JSON artifacts produced by the Phase 7 measurement workflow.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a Phase 7 markdown summary from workflow JSON artifacts.")
    parser.add_argument("--benchmark-run", required=True, help="Path to the benchmark-run JSON artifact.")
    parser.add_argument("--gpu-harden", required=True, help="Path to the gpu-harden JSON artifact.")
    parser.add_argument("--gpu-thresholds", required=True, help="Path to the gpu-thresholds JSON artifact.")
    parser.add_argument("--output", help="Optional markdown output path.")
    args = parser.parse_args()

    report = generate_phase7_report(args.benchmark_run, args.gpu_harden, args.gpu_thresholds)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
