"""
core/active_probing.py
Experimental operator-side active probing for explicitly low-risk MCP tools.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


MANIFEST_VERSION = 1
SUPPORTED_SAFETY_CLASSES = {"read_only_idempotent"}


@dataclass
class ActiveProbe:
    probe_id: str
    tool: str
    arguments: dict[str, Any]
    safety_class: str = "read_only_idempotent"
    expect_success: bool = True


@dataclass
class ActiveProbeResult:
    probe_id: str
    tool: str
    passed: bool
    reason: str
    tool_hints: dict[str, Any] = field(default_factory=dict)
    response_error: str | None = None


@dataclass
class ActiveProbeReport:
    passed: bool
    protocol_version: str | None
    tool_count: int
    results: list[ActiveProbeResult] = field(default_factory=list)


def load_probe_manifest(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    probes = payload.get("probes")
    if not isinstance(probes, list) or not probes:
        raise ValueError("Probe manifest must contain a non-empty `probes` list.")
    for index, probe in enumerate(probes):
        if not isinstance(probe, dict):
            raise ValueError(f"Probe entry {index} must be an object.")
        safety_class = probe.get("safety_class", "read_only_idempotent")
        if safety_class not in SUPPORTED_SAFETY_CLASSES:
            raise ValueError(f"Unsupported probe safety_class: {safety_class}")
        if not isinstance(probe.get("tool"), str) or not probe["tool"].strip():
            raise ValueError(f"Probe entry {index} is missing a valid `tool`.")
        if not isinstance(probe.get("arguments", {}), dict):
            raise ValueError(f"Probe entry {index} must define `arguments` as an object.")
    return payload


def parse_probe_manifest(payload: dict[str, Any]) -> tuple[str, list[ActiveProbe]]:
    protocol_version = str(payload.get("protocolVersion") or "2025-11-25")
    parsed: list[ActiveProbe] = []
    for index, entry in enumerate(payload.get("probes", []), start=1):
        parsed.append(
            ActiveProbe(
                probe_id=str(entry.get("probe_id") or f"probe-{index}"),
                tool=str(entry["tool"]),
                arguments=dict(entry.get("arguments", {})),
                safety_class=str(entry.get("safety_class", "read_only_idempotent")),
                expect_success=bool(entry.get("expect_success", True)),
            )
        )
    return protocol_version, parsed


async def run_active_probes(
    server_command: list[str],
    probe_manifest: dict[str, Any],
    *,
    timeout_secs: float = 5.0,
) -> ActiveProbeReport:
    if not server_command:
        raise ValueError("Server command cannot be empty.")

    protocol_version, probes = parse_probe_manifest(probe_manifest)
    proc = await asyncio.create_subprocess_exec(
        *server_command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        initialize_response = await _request(
            proc,
            {
                "jsonrpc": "2.0",
                "id": "probe-init",
                "method": "initialize",
                "params": {
                    "protocolVersion": protocol_version,
                    "capabilities": {},
                    "clientInfo": {"name": "McpVanguard Active Prober", "version": "1.0.0"},
                },
            },
            timeout_secs=timeout_secs,
        )
        await _notify(
            proc,
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            },
        )
        tools_response = await _request(
            proc,
            {
                "jsonrpc": "2.0",
                "id": "probe-tools",
                "method": "tools/list",
                "params": {},
            },
            timeout_secs=timeout_secs,
        )

        protocol = (((initialize_response.get("result") or {}).get("protocolVersion")))
        tools = (((tools_response.get("result") or {}).get("tools")) or [])
        tool_map = {
            str(tool.get("name")): tool
            for tool in tools
            if isinstance(tool, dict) and isinstance(tool.get("name"), str)
        }

        results: list[ActiveProbeResult] = []
        for probe in probes:
            tool = tool_map.get(probe.tool)
            if tool is None:
                results.append(
                    ActiveProbeResult(
                        probe_id=probe.probe_id,
                        tool=probe.tool,
                        passed=False,
                        reason=f"Tool '{probe.tool}' is not exposed by the upstream server.",
                    )
                )
                continue

            hints = extract_tool_hints(tool)
            safe_reason = validate_probe_safety(tool, probe.safety_class)
            if safe_reason is not None:
                results.append(
                    ActiveProbeResult(
                        probe_id=probe.probe_id,
                        tool=probe.tool,
                        passed=False,
                        reason=safe_reason,
                        tool_hints=hints,
                    )
                )
                continue

            response = await _request(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": f"probe-call:{probe.probe_id}",
                    "method": "tools/call",
                    "params": {
                        "name": probe.tool,
                        "arguments": probe.arguments,
                    },
                },
                timeout_secs=timeout_secs,
            )
            has_error = "error" in response
            passed = (not has_error) if probe.expect_success else has_error
            results.append(
                ActiveProbeResult(
                    probe_id=probe.probe_id,
                    tool=probe.tool,
                    passed=passed,
                    reason="Probe matched expected outcome." if passed else "Probe response did not match expected outcome.",
                    tool_hints=hints,
                    response_error=_extract_error_message(response),
                )
            )

        return ActiveProbeReport(
            passed=all(result.passed for result in results),
            protocol_version=protocol,
            tool_count=len(tool_map),
            results=results,
        )
    finally:
        await _shutdown_process(proc)


def extract_tool_hints(tool: dict[str, Any]) -> dict[str, Any]:
    annotations = tool.get("annotations")
    ann = annotations if isinstance(annotations, dict) else {}
    return {
        "readOnlyHint": tool.get("readOnlyHint", ann.get("readOnlyHint")),
        "idempotentHint": tool.get("idempotentHint", ann.get("idempotentHint")),
        "destructiveHint": tool.get("destructiveHint", ann.get("destructiveHint")),
        "openWorldHint": tool.get("openWorldHint", ann.get("openWorldHint")),
    }


def validate_probe_safety(tool: dict[str, Any], safety_class: str) -> str | None:
    hints = extract_tool_hints(tool)
    if safety_class == "read_only_idempotent":
        if hints.get("readOnlyHint") is not True:
            return "Probe safety check failed: tool is not explicitly marked readOnlyHint=true."
        if hints.get("idempotentHint") is not True:
            return "Probe safety check failed: tool is not explicitly marked idempotentHint=true."
        if hints.get("destructiveHint") is True:
            return "Probe safety check failed: tool is marked destructiveHint=true."
        if hints.get("openWorldHint") is True:
            return "Probe safety check failed: tool is marked openWorldHint=true."
        return None
    return f"Unsupported probe safety_class: {safety_class}"


async def _request(proc: asyncio.subprocess.Process, message: dict[str, Any], *, timeout_secs: float) -> dict[str, Any]:
    await _notify(proc, message)
    return await _read_json(proc, timeout_secs=timeout_secs)


async def _notify(proc: asyncio.subprocess.Process, message: dict[str, Any]) -> None:
    if proc.stdin is None:
        raise RuntimeError("Probe subprocess stdin is unavailable.")
    payload = (json.dumps(message) + "\n").encode("utf-8")
    proc.stdin.write(payload)
    await proc.stdin.drain()


async def _read_json(proc: asyncio.subprocess.Process, *, timeout_secs: float) -> dict[str, Any]:
    if proc.stdout is None:
        raise RuntimeError("Probe subprocess stdout is unavailable.")
    line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout_secs)
    if not line:
        stderr_text = ""
        if proc.stderr is not None:
            try:
                stderr_text = (await asyncio.wait_for(proc.stderr.read(), timeout=0.2)).decode("utf-8", errors="replace")
            except Exception:
                stderr_text = ""
        raise RuntimeError(f"Probe subprocess ended without a response. stderr={stderr_text!r}")
    return json.loads(line.decode("utf-8", errors="replace"))


def _extract_error_message(response: dict[str, Any]) -> str | None:
    error = response.get("error")
    if not isinstance(error, dict):
        return None
    message = error.get("message")
    return str(message) if message is not None else None


async def _shutdown_process(proc: asyncio.subprocess.Process) -> None:
    try:
        if proc.stdin is not None:
            try:
                proc.stdin.close()
                await asyncio.wait_for(proc.stdin.wait_closed(), timeout=0.5)
            except Exception:
                pass
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=1.5)
            except asyncio.TimeoutError:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=1.5)
    except ProcessLookupError:
        pass
