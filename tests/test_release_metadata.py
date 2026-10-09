"""Prevent inconsistent package, runtime, bridge, and extension release identities."""

import json
import os
import tomllib
from pathlib import Path

from core import __version__


def test_release_versions_are_aligned():
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["version"] == __version__
    for filename in ("package.json", "manifest.json"):
        assert json.loads((root / filename).read_text(encoding="utf-8"))["version"] == __version__
    lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    package = next(package for package in lock["package"] if package["name"] == "mcp-vanguard")
    assert package["version"] == __version__
    if os.environ.get("GITHUB_REF_TYPE") == "tag":
        assert os.environ["GITHUB_REF_NAME"] == f"v{__version__}"
