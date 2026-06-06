from __future__ import annotations

import argparse
import asyncio
import json
import threading
import time
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from core import semantic


@dataclass(frozen=True)
class ProbeSummary:
    backend: str
    runs: int
    mean_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float
    blocks: int
    warns: int
    allows: int


class _MockOpenAIHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        if self.path.endswith("/chat/completions"):
            self._handle_chat()
            return
        if self.path.endswith("/api/chat"):
            self._handle_ollama_chat()
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        if self.path.endswith("/api/tags"):
            payload = {"models": [{"name": "mock-local-l2"}]}
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def _handle_chat(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        payload = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "score": 0.42,
                                "reason": "mock local backend for Phase 7 measurement",
                            }
                        )
                    }
                }
            ]
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_ollama_chat(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        payload = {
            "message": {
                "content": json.dumps(
                    {
                        "score": 0.42,
                        "reason": "mock local backend for Phase 7 measurement",
                    }
                )
            }
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A003
        return


def _summarize(samples_ms: list[float], actions: list[str]) -> ProbeSummary:
    ordered = sorted(samples_ms)
    p95_index = min(len(ordered) - 1, max(0, int(round(len(ordered) * 0.95)) - 1))
    return ProbeSummary(
        backend="mock-openai-compatible",
        runs=len(samples_ms),
        mean_ms=sum(ordered) / len(ordered) if ordered else 0.0,
        p95_ms=ordered[p95_index] if ordered else 0.0,
        min_ms=ordered[0] if ordered else 0.0,
        max_ms=ordered[-1] if ordered else 0.0,
        blocks=sum(1 for action in actions if action == "BLOCK"),
        warns=sum(1 for action in actions if action == "WARN"),
        allows=sum(1 for action in actions if action == "ALLOW"),
    )


async def _run_probe(base_url: str, iterations: int, threshold_warn: float, threshold_block: float) -> ProbeSummary:
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/example.txt"}},
        "id": "phase7-local-l2",
    }
    settings = semantic.SemanticSettings(
        ollama_url=base_url,
        ollama_model="mock",
        openai_api_key=None,
        openai_model="mock-local",
        openai_base_url=base_url,
        minimax_api_key=None,
        minimax_model="mock",
        minimax_base_url=base_url,
        custom_api_key=None,
        custom_model="mock-local",
        custom_base_url=None,
        threshold_block=threshold_block,
        threshold_warn=threshold_warn,
        enabled=True,
        fail_closed=True,
        timeout=2.0,
    )

    samples_ms: list[float] = []
    actions: list[str] = []
    for _ in range(iterations):
        started = time.perf_counter()
        result = await semantic.score_intent(payload, settings=settings)
        samples_ms.append((time.perf_counter() - started) * 1000)
        if result is None:
            actions.append("ALLOW")
        else:
            actions.append(result.action)
    return _summarize(samples_ms, actions)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local mock L2 probe to exercise the semantic path.")
    parser.add_argument("--iterations", type=int, default=25)
    parser.add_argument("--threshold-warn", type=float, default=0.5)
    parser.add_argument("--threshold-block", type=float, default=0.8)
    parser.add_argument("--output-json", help="Optional JSON output path.")
    parser.add_argument("--output-md", help="Optional markdown output path.")
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockOpenAIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        summary = asyncio.run(_run_probe(f"http://127.0.0.1:{server.server_port}", args.iterations, args.threshold_warn, args.threshold_block))
    finally:
        server.shutdown()
        server.server_close()

    payload: dict[str, Any] = asdict(summary)
    payload["note"] = "This is a mock local L2 probe, not a real backend measurement."

    if args.output_json:
        output_json = Path(args.output_json)
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.output_md:
        output_md = Path(args.output_md)
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(
            "\n".join(
                [
                    "# Local L2 Mock Probe",
                    "",
                    f"- Backend: {summary.backend}",
                    f"- Runs: {summary.runs}",
                    f"- Mean latency: {summary.mean_ms:.3f} ms",
                    f"- p95 latency: {summary.p95_ms:.3f} ms",
                    f"- Min latency: {summary.min_ms:.3f} ms",
                    f"- Max latency: {summary.max_ms:.3f} ms",
                    f"- Blocks: {summary.blocks}",
                    f"- Warns: {summary.warns}",
                    f"- Allows: {summary.allows}",
                    "",
                    "This probe only exercises the semantic code path with a mock OpenAI-compatible backend.",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
