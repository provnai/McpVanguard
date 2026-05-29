from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from core import behavioral


@dataclass(frozen=True)
class ProbeResult:
    mode: str
    calls: int
    mean_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, Any] = {}
        self.sorted_sets: dict[str, dict[str, float]] = {}

    def ping(self):
        return True

    def zadd(self, key, mapping):
        self.sorted_sets.setdefault(key, {}).update(mapping)

    def expire(self, key, seconds):
        return True

    def zremrangebyscore(self, key, min_score, max_score):
        return 0

    def zcard(self, key):
        return len(self.sorted_sets.get(key, {}))

    def sadd(self, key, value):
        self.store.setdefault(key, set()).add(value)

    def scard(self, key):
        return len(self.store.get(key, set()))

    def setex(self, key, seconds, value):
        self.store[key] = value

    def exists(self, key):
        return 1 if key in self.store else 0

    def smembers(self, key):
        return set(self.store.get(key, set()))

    def incrby(self, key, amount):
        self.store[key] = int(self.store.get(key, 0)) + int(amount)
        return self.store[key]

    def scan_iter(self, match=None, count=None):
        yield from list(self.store.keys()) + list(self.sorted_sets.keys())

    def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)
            self.sorted_sets.pop(key, None)


def _summarize(samples_ms: list[float]) -> ProbeResult:
    ordered = sorted(samples_ms)
    p95_index = min(len(ordered) - 1, max(0, int(round(len(ordered) * 0.95)) - 1))
    return ProbeResult(
        mode="native",
        calls=len(samples_ms),
        mean_ms=statistics.mean(ordered) if ordered else 0.0,
        p95_ms=ordered[p95_index] if ordered else 0.0,
        min_ms=ordered[0] if ordered else 0.0,
        max_ms=ordered[-1] if ordered else 0.0,
    )


async def _run_once(iterations: int) -> list[float]:
    samples: list[float] = []
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "list_directory", "arguments": {"path": "."}},
        "id": "phase7-redis",
    }
    for idx in range(iterations):
        started = time.perf_counter()
        await behavioral.inspect_request(f"phase7-redis-{idx}", payload, server_id="phase7")
        samples.append((time.perf_counter() - started) * 1000)
    return samples


def _measure_mode(mode: str, iterations: int) -> ProbeResult:
    behavioral.clear_all_states()
    samples: list[float] = []
    original = behavioral._redis_client
    try:
        if mode == "synthetic-redis":
            behavioral._redis_client = _FakeRedis()
        else:
            behavioral._redis_client = None
        samples = asyncio.run(_run_once(iterations))
    finally:
        behavioral._redis_client = original
        behavioral.clear_all_states()
    result = _summarize(samples)
    return ProbeResult(
        mode=mode,
        calls=result.calls,
        mean_ms=result.mean_ms,
        p95_ms=result.p95_ms,
        min_ms=result.min_ms,
        max_ms=result.max_ms,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare behavioral-layer code paths with and without Redis-like state.")
    parser.add_argument("--iterations", type=int, default=80)
    parser.add_argument("--output-json", help="Optional JSON output path.")
    parser.add_argument("--output-md", help="Optional markdown output path.")
    args = parser.parse_args()

    native = _measure_mode("in-memory", args.iterations)
    synthetic = _measure_mode("synthetic-redis", args.iterations)

    payload = {
        "native": asdict(native),
        "synthetic": asdict(synthetic),
        "note": "The synthetic-redis mode is a code-path probe, not a live Redis deployment benchmark.",
    }

    if args.output_json:
        Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.output_md:
        Path(args.output_md).write_text(
            "\n".join(
                [
                    "# Redis Probe",
                    "",
                    f"- In-memory mean latency: {native.mean_ms:.3f} ms",
                    f"- In-memory p95 latency: {native.p95_ms:.3f} ms",
                    f"- Synthetic Redis-like mean latency: {synthetic.mean_ms:.3f} ms",
                    f"- Synthetic Redis-like p95 latency: {synthetic.p95_ms:.3f} ms",
                    "",
                    "The synthetic-redis result is only a code-path probe; it does not replace a real Redis deployment measurement.",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
