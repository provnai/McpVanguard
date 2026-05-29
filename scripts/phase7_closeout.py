from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from scripts.phase7_live_evidence_probe import build_live_evidence_probe


def build_closeout_summary(iterations: int) -> dict[str, Any]:
    evidence = build_live_evidence_probe(iterations)
    decision = evidence["decision"]
    remaining = []
    if evidence["redis"]["status"] != "live":
        remaining.append("Redis overhead")
    if evidence["semantic"]["status"] != "live":
        remaining.append("Local L2 throughput")
    if decision["attestation"] != "verified":
        remaining.append("GPU attestation")

    return {
        "evidence": evidence,
        "remaining_open": remaining,
        "recommended_status": "open by design" if remaining else "ready to close",
        "note": "Mock and synthetic probes are useful, but they do not replace live evidence.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a Phase 7 closeout summary.")
    parser.add_argument("--iterations", type=int, default=8)
    parser.add_argument("--output-json", help="Optional JSON output path.")
    parser.add_argument("--output-md", help="Optional markdown output path.")
    args = parser.parse_args()

    payload = build_closeout_summary(args.iterations)
    if args.output_json:
        Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.output_md:
        lines = [
            "# Phase 7 Closeout Summary",
            "",
            f"- Recommended status: {payload['recommended_status']}",
            f"- Remaining open items: {', '.join(payload['remaining_open']) if payload['remaining_open'] else 'none'}",
            "",
            "## Evidence Snapshot",
            f"- Semantic backend status: {payload['evidence']['semantic']['status']}",
            f"- Redis status: {payload['evidence']['redis']['status']}",
            f"- Attestation status: {payload['evidence']['decision']['attestation']}",
            "",
            payload["note"],
        ]
        Path(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
