"""Verify the bundled synthetic upstream, without credentials or real targets."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from importlib import resources
from pathlib import Path


def _require(condition: bool, message: object) -> None:
    if not condition:
        raise ValueError(str(message))


def _session(root: Path, guarded: bool) -> dict:
    arguments = [sys.executable, "-m", "core.cli", "demo-server", "--mode", "stdio"]
    if guarded:
        arguments = [sys.executable, "-m", "core.cli", "start", "--profile", "balanced",
                     "--rules-dir", str(root / "rules"), "--server",
                     f'"{sys.executable}" -m core.cli demo-server --mode stdio']
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("VANGUARD_", "DEMO_")) and key != "PYTHONPATH"}
    environment["VANGUARD_LOG_FILE"] = str(root / "audit.log")
    process = subprocess.Popen(arguments, cwd=root, env=environment, text=True,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    replies = queue.Queue()
    errors = deque(maxlen=40)

    def read_stdout():
        for line in process.stdout:
            try:
                replies.put(json.loads(line))
            except ValueError:
                pass

    def read_stderr():
        for line in process.stderr:
            errors.append(line)

    readers = [threading.Thread(target=read_stdout, daemon=True),
               threading.Thread(target=read_stderr, daemon=True)]
    for reader in readers:
        reader.start()

    def send(method, params, identity=None):
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        if identity is not None:
            message["id"] = identity
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
        if identity is None:
            return None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                reply = replies.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty as exc:
                raise TimeoutError(f"No {method} response within 20 seconds") from exc
            if reply.get("id") == identity:
                return reply
        raise TimeoutError(method)

    try:
        initialized = send("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                           "clientInfo": {"name": "synthetic-verifier", "version": "1"}}, 1)
        _require("result" in initialized, initialized)
        send("notifications/initialized", {})
        listed = send("tools/list", {}, 2)
        _require("result" in listed, listed)
        names = {tool["name"] for tool in listed["result"].get("tools", [])}
        _require({"read_file", "fetch_url"}.issubset(names), "Demo tools are missing")
        calls = {}
        scenarios = [("safe", "read_file", {"path": "/docs/readme.txt"}),
                     ("traversal", "read_file", {"path": "../../etc/passwd"}),
                     ("network", "fetch_url", {"url": "http://169.254.169.254/latest/meta-data/"})]
        for identity, (label, tool, params) in enumerate(scenarios, 3):
            calls[label] = send("tools/call", {"name": tool, "arguments": params}, identity)
        safe = calls["safe"]["result"]
        _require(not safe.get("isError"), safe)
        _require("secure MCP demo" in safe["content"][0]["text"], safe)
        for label in ("traversal", "network"):
            if guarded:
                error = calls[label]["error"]
                _require(error["code"] == -32001, error)
                _require(error.get("data", {}).get("blocked_by") == "McpVanguard", error)
            else:
                _require(calls[label]["result"].get("isError") is False, calls[label])
        return {"guarded": guarded, "passed": True, "calls": calls}
    except Exception as exc:
        raise RuntimeError(f"Demo verification failed: {exc}; {''.join(errors)[-2000:]}") from exc
    finally:
        try:
            process.stdin.close()
        except BrokenPipeError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        for reader in readers:
            reader.join(timeout=2)
        process.stdout.close()
        process.stderr.close()


def verify_demo() -> dict:
    with tempfile.TemporaryDirectory(prefix="mcpvanguard-demo-") as directory:
        root = Path(directory)
        (root / "rules").mkdir()
        for resource in resources.files("rules").iterdir():
            if resource.name.endswith(".yaml"):
                (root / "rules" / resource.name).write_bytes(resource.read_bytes())
        # Deliberately allow only the demo's in-memory docs; no real files are read.
        (root / "rules" / "safe_zones.yaml").write_text(
            '- tool: read_file\n  allowed_prefixes: ["/docs"]\n  recursive: true\n', encoding="utf-8",
        )
        return {"scope": "synthetic-only", "sessions": [_session(root, False), _session(root, True)]}


if __name__ == "__main__":
    print(json.dumps(verify_demo(), indent=2))
