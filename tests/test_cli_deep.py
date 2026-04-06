"""
tests/test_cli_deep.py
Testing CLI tools: init and configure-claude.
"""

import os
import json
import pytest
import shutil
from core.cli import app
from typer.testing import CliRunner
from unittest.mock import AsyncMock, patch

runner = CliRunner()

def test_vanguard_init_logic(tmp_path, monkeypatch):
    """Test that vanguard init creates the correct file structure."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert "Initializing McpVanguard Workspace" in result.stdout
    
    assert os.path.exists(".env")
    assert os.path.exists("rules/safe_zones.yaml")
    
    with open(".env", "r") as f:
        content = f.read()
        assert "VANGUARD_MODE=audit" in content
        
def test_vanguard_configure_claude_logic(tmp_path, monkeypatch):
    """Test Claude configuration injection."""
    # Create fake AppData structure
    fake_appdata = tmp_path / "AppData"
    claude_dir = fake_appdata / "Claude"
    claude_dir.mkdir(parents=True)
    config_file = claude_dir / "claude_desktop_config.json"
    
    initial_config = {
        "mcpServers": {
            "test-server": {
                "command": "node",
                "args": ["server.js"]
            }
        }
    }
    with open(config_file, "w") as f:
        json.dump(initial_config, f)
        
    # Mock APPDATA env var
    monkeypatch.setenv("APPDATA", str(fake_appdata))
    
    result = runner.invoke(app, ["configure-claude"])
    assert result.exit_code == 0
    assert "Wrapped 1 servers" in result.stdout
    
    with open(config_file, "r") as f:
        updated = json.load(f)
        server = updated["mcpServers"]["test-server"]
        assert server["command"] == "vanguard"
        assert server["args"] == ["start", "--server", "node server.js"]


def test_vanguard_start_semantic_flag_does_not_crash(monkeypatch):
    monkeypatch.setenv("VANGUARD_SEMANTIC_ENABLED", "false")

    with patch("core.cli.run_proxy") as mock_run_proxy, \
         patch("core.semantic.check_semantic_health", new=AsyncMock(return_value=True)):
        result = runner.invoke(app, ["start", "--server", "echo hello", "--semantic"])

    assert result.exit_code == 0
    mock_run_proxy.assert_called_once()


def test_vanguard_start_management_tools_flag_enables_surface():
    with patch("core.cli.run_proxy") as mock_run_proxy:
        result = runner.invoke(app, ["start", "--server", "echo hello", "--management-tools"])

    assert result.exit_code == 0
    mock_run_proxy.assert_called_once()
    config = mock_run_proxy.call_args.kwargs["config"]
    assert config.management_tools_enabled is True


def test_vanguard_sse_management_tools_flag_enables_surface():
    async def fake_run_sse_server(*, config, **kwargs):
        return config

    with patch("asyncio.run") as mock_asyncio_run, \
         patch("core.sse_server.run_sse_server", new=fake_run_sse_server):
        result = runner.invoke(app, ["sse", "--server", "echo hello", "--management-tools"])

    assert result.exit_code == 0
    mock_asyncio_run.assert_called_once()
    coroutine = mock_asyncio_run.call_args.args[0]
    config = coroutine.cr_frame.f_locals["config"]
    assert config.management_tools_enabled is True
    coroutine.close()
