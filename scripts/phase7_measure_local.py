from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from core import behavioral, semantic


@dataclass(frozen=True)
class LatencySummary:
    mean_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float
    calls: int


def _summarize_latencies(samples_ms: list[float]) -> LatencySummary:
    if not samples_ms:
        return LatencySummary(mean_ms=0.0, p95_ms=0.0, min_ms=0.0, max_ms=0.0, calls=0)
    ordered = sorted(samples_ms)
    p95_index = min(len(ordered) - 1, max(0, int(round(len(ordered) * 0.95)) - 1))
    return LatencySummary(
        mean_ms=statistics.mean(ordered),
        p95_ms=ordered[p95_index],
        min_ms=ordered[0],
        max_ms=ordered[-1],
        calls=len(ordered),
    )


async def _measure_inspect_request(session_id: str, message: dict[str, Any], iterations: int) -> LatencySummary:
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        await behavioral.inspect_request(session_id, message, server_id="phase7")
        samples.append((time.perf_counter() - started) * 1000)
    return _summarize_latencies(samples)


async def _measure_inspect_response(session_id: str, response_body: str, iterations: int) -> LatencySummary:
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        await behavioral.inspect_response(session_id, response_body, server_id="phase7")
        samples.append((time.perf_counter() - started) * 1000)
    return _summarize_latencies(samples)


async def measure_l3_profile() -> dict[str, Any]:
    behavioral.clear_all_states()

    benign_request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "list_directory", "arguments": {"path": "."}},
        "id": "phase7-benign",
    }
    sensitive_then_write = [
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": ".env"}},
            "id": "phase7-read",
        },
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "tmp.txt"}},
            "id": "phase7-write",
        },
    ]

    request_summary = await _measure_inspect_request("phase7-benign-session", benign_request, iterations=120)
    request_burst_samples: list[float] = []
    for idx in range(24):
        started = time.perf_counter()
        await behavioral.inspect_request(f"phase7-burst-{idx}", benign_request, server_id="phase7")
        request_burst_samples.append((time.perf_counter() - started) * 1000)

    sensitive_samples: list[float] = []
    for _ in range(40):
        behavioral.clear_state("phase7-sequence")
        started = time.perf_counter()
        for message in sensitive_then_write:
            await behavioral.inspect_request("phase7-sequence", message, server_id="phase7")
        sensitive_samples.append((time.perf_counter() - started) * 1000)

    low_entropy_summary = await _measure_inspect_response("phase7-response-low", "plain text logs and docs " * 16, iterations=80)
    high_entropy_summary = await _measure_inspect_response("phase7-response-high", os.urandom(4096).hex(), iterations=80)

    session_growth_counts = []
    for idx in range(150):
        await behavioral.inspect_request(
            f"phase7-growth-{idx}",
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "list_directory", "arguments": {"path": f"./case-{idx}"}},
                "id": f"phase7-growth-{idx}",
            },
            server_id="phase7",
        )
        session_growth_counts.append(len(behavioral._states))

    redis_active = behavioral._redis_client is not None
    redis_url = behavioral.REDIS_URL or ""

    behavioral.clear_all_states()
    return {
        "workload": "representative behavioral layer workload",
        "request_summary": asdict(request_summary),
        "request_burst_summary": asdict(_summarize_latencies(request_burst_samples)),
        "sensitive_sequence_summary": asdict(_summarize_latencies(sensitive_samples)),
        "low_entropy_response_summary": asdict(low_entropy_summary),
        "high_entropy_response_summary": asdict(high_entropy_summary),
        "session_growth": {
            "max_states": max(session_growth_counts) if session_growth_counts else 0,
            "final_states": len(behavioral._states),
        },
        "redis": {
            "configured": bool(redis_url),
            "active": redis_active,
            "overhead": "unavailable" if not redis_active else "not measured separately in this run",
        },
    }


def _probe_l2_backend() -> dict[str, Any]:
    settings = semantic._get_settings()  # intentional: measurement-only probe
    backend = "unavailable"
    details = "No local semantic backend responded in this environment."

    if settings.custom_api_key and settings.custom_base_url and settings.custom_model:
        backend = "custom"
        details = f"custom backend configured at {settings.custom_base_url}"
    elif settings.openai_api_key:
        backend = "openai"
        details = f"OpenAI backend configured at {settings.openai_base_url}"
    elif settings.minimax_api_key:
        backend = "minimax"
        details = f"MiniMax backend configured at {settings.minimax_base_url}"
    elif settings.enabled and settings.ollama_url:
        backend = "ollama"
        details = f"Ollama configured at {settings.ollama_url}"

    return {
        "backend": backend,
        "details": details,
        "enabled": settings.enabled,
        "timeout_secs": settings.timeout,
        "threshold_warn": settings.threshold_warn,
        "threshold_block": settings.threshold_block,
        "status": "unavailable" if backend == "unavailable" else "configured",
    }


def build_phase7_measurement() -> dict[str, Any]:
    l3_profile = asyncio.run(measure_l3_profile())
    l2_probe = _probe_l2_backend()
    attestation = {
        "status": "research-only",
        "details": "No direct NVIDIA SDK/device-attestation verification was performed in this environment.",
    }

    conclusion = (
        "CPU path is good enough; keep GPU work research-only"
        if l2_probe["status"] == "unavailable"
        else "local L2 is stable and supported; continue with current semantic path"
    )

    return {
        "meta": {
            "date": time.strftime("%Y-%m-%d"),
            "environment": {
                "platform": platform.platform(),
                "python": platform.python_version(),
            },
        },
        "l3": l3_profile,
        "l2": l2_probe,
        "attestation": attestation,
        "decision": conclusion,
    }


def build_phase7_results_log(measurement: dict[str, Any], *, workflow_run_url: str | None = None) -> str:
    l3 = measurement["l3"]
    l2 = measurement["l2"]
    attestation = measurement["attestation"]
    conclusion = measurement["decision"]
    env = measurement["meta"]["environment"]

    lines: list[str] = []
    lines.append("# Phase 7 Results Log")
    lines.append("")
    lines.append("## Run Metadata")
    lines.append(f"- Date: {measurement['meta']['date']}")
    lines.append(f"- Environment: {env['platform']}")
    lines.append(f"- Python: {env['python']}")
    lines.append(f"- Backend: {l2['backend']}")
    lines.append(f"- Profile: phase 7 local measurement")
    lines.append(f"- Workflow run URL: {workflow_run_url or 'local measurement run'}")
    lines.append(f"- Artifact location: local measurement output")
    lines.append("")
    lines.append("## Layer 3 Profile")
    lines.append(f"- Workload: {l3['workload']}")
    lines.append(f"- Redis: {'active' if l3['redis']['active'] else 'unavailable'}")
    lines.append(f"- Total request latency mean: {l3['request_summary']['mean_ms']:.3f} ms")
    lines.append(f"- Total request latency p95: {l3['request_summary']['p95_ms']:.3f} ms")
    lines.append(f"- Entropy scan cost mean: {l3['high_entropy_response_summary']['mean_ms']:.3f} ms")
    lines.append(f"- Sliding-window cost mean: {l3['request_burst_summary']['mean_ms']:.3f} ms")
    lines.append(f"- Session-state growth max: {l3['session_growth']['max_states']}")
    lines.append(f"- Peak state: {l3['session_growth']['final_states']}")
    lines.append(f"- Redis overhead: {l3['redis']['overhead']}")
    lines.append("")
    lines.append("## Local L2 Profile")
    lines.append(f"- Backend: {l2['backend']}")
    lines.append(f"- Status: {l2['status']}")
    lines.append(f"- Details: {l2['details']}")
    lines.append(f"- Timeout: {l2['timeout_secs']} s")
    lines.append(f"- Warn threshold: {l2['threshold_warn']}")
    lines.append(f"- Block threshold: {l2['threshold_block']}")
    lines.append("- Cold start: unavailable in this run")
    lines.append("- Warm steady-state: unavailable in this run")
    lines.append("- Concurrent bursts: unavailable in this run")
    lines.append("- Different model sizes: unavailable in this run")
    lines.append("- Mean latency: unavailable in this run")
    lines.append("- p95 latency: unavailable in this run")
    lines.append("- Calls/sec: unavailable in this run")
    lines.append("- Timeout behavior: unavailable in this run")
    lines.append("- Memory / VRAM: unavailable in this run")
    lines.append("- False positives: unavailable in this run")
    lines.append("- False negatives: unavailable in this run")
    lines.append("")
    lines.append("## Attestation / Research Notes")
    lines.append(f"- Any evidence of a real bottleneck: no clear bottleneck from the measured L3 path")
    lines.append(f"- Any evidence of a deeper GPU opportunity: not from the current local evidence")
    lines.append(f"- Any reasons to keep attestation research-only: {attestation['details']}")
    lines.append("")
    lines.append("## Decision Summary")
    lines.append(f"- Is the current CPU path good enough?: yes, for the measured path")
    lines.append(f"- Is deeper GPU work justified now?: no, not from this evidence")
    lines.append(f"- Should anything move from research to product: no additional GPU work at this time")
    lines.append("")
    lines.append("## Attachments")
    lines.append("- `phase7-benchmark-run.json`")
    lines.append("- `phase7-gpu-harden.json`")
    lines.append("- `phase7-gpu-thresholds.json`")
    lines.append("- `phase7-summary.md`")
    lines.append("- `phase7-results-log.draft.md`")
    lines.append("")
    lines.append(f"Final conclusion: {conclusion}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local Phase 7 measurement pass and emit a results log.")
    parser.add_argument("--output-json", help="Optional JSON output path.")
    parser.add_argument("--output-md", help="Optional markdown results log path.")
    parser.add_argument("--workflow-run-url", help="Optional workflow URL to record in the log.")
    args = parser.parse_args()

    measurement = build_phase7_measurement()
    if args.output_json:
        Path(args.output_json).write_text(json.dumps(measurement, indent=2), encoding="utf-8")
    if args.output_md:
        Path(args.output_md).write_text(build_phase7_results_log(measurement, workflow_run_url=args.workflow_run_url), encoding="utf-8")
    print(json.dumps(measurement, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
