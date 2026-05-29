from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from scripts.phase7_closeout import build_closeout_summary
from scripts.phase7_live_evidence_probe import build_live_evidence_probe
from scripts.phase7_measure_local import build_phase7_measurement


def build_phase7_status(iterations: int) -> dict[str, Any]:
    measurement = build_phase7_measurement()
    live_evidence = build_live_evidence_probe(iterations)
    closeout = build_closeout_summary(iterations)

    l3 = measurement["l3"]
    l2 = measurement["l2"]
    local_validated = [
        "L3 request-path latency",
        "entropy scan cost",
        "sliding-window cost",
        "session-state growth behavior",
        "mock local L2 code-path probe",
        "mock Redis-like behavioral code-path probe",
    ]
    synthetic_validated = [
        "mock OpenAI-compatible local L2 probe",
        "Redis code-path probe",
    ]
    live_open = closeout["remaining_open"]

    return {
        "headline": closeout["recommended_status"],
        "local_validated": local_validated,
        "synthetic_validated": synthetic_validated,
        "live_open": live_open,
        "measurement": {
            "l3_request_mean_ms": l3["request_summary"]["mean_ms"],
            "l3_request_p95_ms": l3["request_summary"]["p95_ms"],
            "entropy_scan_mean_ms": l3["high_entropy_response_summary"]["mean_ms"],
            "sliding_window_mean_ms": l3["request_burst_summary"]["mean_ms"],
            "l2_backend": l2["backend"],
            "l2_status": l2["status"],
            "attestation": measurement["attestation"]["status"],
        },
        "live_evidence": live_evidence,
        "closeout": closeout,
        "decision": measurement["decision"],
        "note": "Local and synthetic probes are useful for plumbing and baseline evidence; live infrastructure gates stay open until a real run closes them.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Print a compact Phase 7 status summary.")
    parser.add_argument("--iterations", type=int, default=8)
    parser.add_argument("--output-json", help="Optional JSON output path.")
    parser.add_argument("--output-md", help="Optional markdown output path.")
    args = parser.parse_args()

    payload = build_phase7_status(args.iterations)
    if args.output_json:
        Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.output_md:
        lines = [
            "# Phase 7 Status",
            "",
            f"- Headline: {payload['headline']}",
            "",
            "## Locally Validated",
        ]
        lines.extend(f"- {item}" for item in payload["local_validated"])
        lines.extend(
            [
                "",
                "## Synthetic / Mock Validated",
            ]
        )
        lines.extend(f"- {item}" for item in payload["synthetic_validated"])
        lines.extend(
            [
                "",
                "## Still Open (Live Evidence Only)",
            ]
        )
        lines.extend(f"- {item}" for item in payload["live_open"])
        lines.extend(
            [
                "",
                "## Decision Snapshot",
                f"- CPU path: {payload['decision']}",
                f"- L3 request mean: {payload['measurement']['l3_request_mean_ms']:.3f} ms",
                f"- L3 request p95: {payload['measurement']['l3_request_p95_ms']:.3f} ms",
                f"- Entropy scan mean: {payload['measurement']['entropy_scan_mean_ms']:.3f} ms",
                f"- Sliding-window mean: {payload['measurement']['sliding_window_mean_ms']:.3f} ms",
                f"- L2 backend: {payload['measurement']['l2_backend']} ({payload['measurement']['l2_status']})",
                f"- Attestation: {payload['measurement']['attestation']}",
                "",
                payload["note"],
            ]
        )
        Path(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
