"""
core/conformance.py
Thin helpers for invoking the official MCP conformance CLI.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


DEFAULT_CONFORMANCE_PACKAGE = "@modelcontextprotocol/conformance"


@dataclass
class ConformanceResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def passed(self) -> bool:
        return self.returncode == 0


def build_conformance_server_command(
    url: str,
    *,
    scenario: Optional[str] = None,
    suite: str = "active",
    expected_failures: Optional[str | os.PathLike[str]] = None,
    verbose: bool = False,
    runner: str = "npx",
    package: str = DEFAULT_CONFORMANCE_PACKAGE,
) -> list[str]:
    _validate_url(url)

    command = [runner, package, "server", "--url", url]
    if scenario:
        command.extend(["--scenario", scenario])
    if suite:
        command.extend(["--suite", suite])
    if expected_failures:
        command.extend(["--expected-failures", str(expected_failures)])
    if verbose:
        command.append("--verbose")
    return command


def run_server_conformance(
    url: str,
    *,
    scenario: Optional[str] = None,
    suite: str = "active",
    expected_failures: Optional[str | os.PathLike[str]] = None,
    verbose: bool = False,
    runner: str = "npx",
    package: str = DEFAULT_CONFORMANCE_PACKAGE,
    cwd: Optional[str | os.PathLike[str]] = None,
) -> ConformanceResult:
    command = build_conformance_server_command(
        url,
        scenario=scenario,
        suite=suite,
        expected_failures=expected_failures,
        verbose=verbose,
        runner=runner,
        package=package,
    )
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    return ConformanceResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Conformance server URL must be a valid http:// or https:// URL.")
