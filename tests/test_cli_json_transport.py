"""Machine-readable output must not depend on terminal layout or Rich markup."""

import json

import pytest
from rich.console import Console
from typer.testing import CliRunner

from core import cli


@pytest.mark.parametrize("command", ["gpu-harden", "gpu-thresholds"])
@pytest.mark.parametrize("width", [20, 80, 200])
def test_gpu_json_output_survives_terminal_width(command, width, monkeypatch):
    monkeypatch.setattr(cli, "console", Console(width=width, force_terminal=False))
    result = CliRunner().invoke(cli.app, [command, "--json-output"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    expected_key = "thresholds" if command == "gpu-thresholds" else "summary"
    assert expected_key in payload


def test_threshold_json_preserves_long_markup_and_unicode(monkeypatch):
    marker = "[bold]" + "long-value-" * 30 + "\u00e9[/bold]"
    monkeypatch.setattr(cli, "console", Console(width=20, force_terminal=False))
    monkeypatch.setattr(cli.benchmarks, "threshold_sweep_report", lambda _: {"marker": marker})
    result = CliRunner().invoke(cli.app, ["gpu-thresholds", "--json-output"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["marker"] == marker
