from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from core import behavioral, semantic


@dataclass(frozen=True)
class ProbeResult:
    status: str
    backend: str
    calls: int
    mean_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float
    note: str


def _summarize(samples_ms: list[float], *, status: str, backend: str, note: str) -> ProbeResult:
    ordered = sorted(samples_ms)
    p95_index = min(len(ordered) - 1, max(0, int(round(len(ordered) * 0.95)) - 1))
    return ProbeResult(
        status=status,
        backend=backend,
        calls=len(samples_ms),
        mean_ms=(sum(ordered) / len(ordered)) if ordered else 0.0,
        p95_ms=ordered[p95_index] if ordered else 0.0,
        min_ms=ordered[0] if ordered else 0.0,
        max_ms=ordered[-1] if ordered else 0.0,
        note=note,
    )


async def _probe_real_semantic_backend(iterations: int) -> ProbeResult:
    settings = semantic._get_settings()
    backend = "unavailable"
    if settings.custom_api_key and settings.custom_base_url and settings.custom_model:
        backend = "custom"
    elif settings.openai_api_key:
        backend = "openai"
    elif settings.minimax_api_key:
        backend = "minimax"
    elif settings.enabled:
        backend = "ollama"

    if backend == "unavailable":
        return _summarize([], status="unavailable", backend=backend, note="No live semantic backend configured.")

    payload = {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/example.txt"}},
    }
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        result = await semantic.score_intent(payload, settings=settings)
        samples.append((time.perf_counter() - started) * 1000)
        if result is None:
            continue
    return _summarize(
        samples,
        status="live",
        backend=backend,
        note="Live semantic backend probe completed successfully.",
    )


async def _probe_live_redis(iterations: int) -> ProbeResult:
    if not behavioral.REDIS_URL or behavioral._redis_client is None:
        return _summarize([], status="unavailable", backend="redis", note="No live Redis backend configured.")

    payload = {
        "method": "tools/call",
        "params": {"name": "list_directory", "arguments": {"path": "."}},
    }
    samples: list[float] = []
    for idx in range(iterations):
        started = time.perf_counter()
        await behavioral.inspect_request(f"phase7-live-redis-{idx}", payload, server_id="phase7-live")
        samples.append((time.perf_counter() - started) * 1000)
    return _summarize(
        samples,
        status="live",
        backend="redis",
        note="Live Redis-backed behavioral probe completed successfully.",
    )


def build_live_evidence_probe(iterations: int) -> dict[str, Any]:
    semantic_probe = asyncio.run(_probe_real_semantic_backend(iterations))
    redis_probe = asyncio.run(_probe_live_redis(iterations))
    return {
        "semantic": asdict(semantic_probe),
        "redis": asdict(redis_probe),
        "decision": {
            "semantic_live": semantic_probe.status == "live",
            "redis_live": redis_probe.status == "live",
            "attestation": "research-only",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe live external evidence gates for Phase 7.")
    parser.add_argument("--iterations", type=int, default=8)
    parser.add_argument("--output-json", help="Optional JSON output path.")
    parser.add_argument("--output-md", help="Optional markdown output path.")
    args = parser.parse_args()

    payload = build_live_evidence_probe(args.iterations)
    if args.output_json:
        Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.output_md:
        lines = [
            "# Phase 7 Live Evidence Probe",
            "",
            f"- Semantic backend status: {payload['semantic']['status']}",
            f"- Semantic backend: {payload['semantic']['backend']}",
            f"- Semantic mean latency: {payload['semantic']['mean_ms']:.3f} ms",
            f"- Redis status: {payload['redis']['status']}",
            f"- Redis backend: {payload['redis']['backend']}",
            f"- Redis mean latency: {payload['redis']['mean_ms']:.3f} ms",
            "",
            "If a backend is unavailable, that is the correct result for this workstation and should stay open in the checklist.",
        ]
        Path(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
