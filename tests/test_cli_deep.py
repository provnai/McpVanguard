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
