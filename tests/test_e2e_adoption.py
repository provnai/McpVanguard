"""
tests/test_e2e_adoption.py
Deep E2E test for Shadow Mode + Dashboard integration.
"""

import os
import json
import time
import httpx
import pytest
import subprocess
import signal
from pathlib import Path

@pytest.fixture
def clean_env():
    """Ensure a clean audit log and rules for testing."""
    log_file = Path("test_e2e_audit.log")
    if log_file.exists():
        log_file.unlink()
    
    rules_dir = Path("test_rules")
    rules_dir.mkdir(exist_ok=True)
    
    # Simple rule to block 'rm'
    with open(rules_dir / "commands.yaml", "w") as f:
        f.write("- id: block-rm\n  pattern: 'rm .*'\n  action: BLOCK\n  severity: CRITICAL\n")
        
    return log_file, rules_dir

def test_shadow_mode_and_dashboard_integration(clean_env):
    log_file, rules_dir = clean_env
    
    # 1. Start proxy in SHADOW MODE (audit)
    # We'll use a dummy server (cat) to simple echo back
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path.cwd()) # Crucial for finding 'core'
    env["VANGUARD_MODE"] = "audit"
    env["VANGUARD_LOG_FILE"] = str(log_file)
    env["VANGUARD_RULES_DIR"] = str(rules_dir)
    env["VANGUARD_AUDIT_FORMAT"] = "json"
    
    # Start proxy in background
    # We piping to a dummy cat command
    proxy_proc = subprocess.Popen(
        ["python", "-m", "core.cli", "start", "--server", "cat", "--no-behavioral"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=1
    )
    
    try:
        # Give it a second to start
        time.sleep(2)
        
        # 2. Send a forbidden command (rm -rf /)
        forbidden_msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "execute_command", "arguments": {"command": "rm -rf /"}},
            "id": 101
        })
        proxy_proc.stdin.write(forbidden_msg + "\n")
        proxy_proc.stdin.flush()
        
        # 3. Read response from proxy (should be allowed because of audit mode)
        # Using a timeout to prevent infinite hangs
        response = None
        start_time = time.time()
        while time.time() - start_time < 10:
            line = proxy_proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith("{"):
                try:
                    msg = json.loads(line)
                    if msg.get("id") == 101:
                        response = msg
                        break
                except:
                    continue
            time.sleep(0.1)
        
        assert response, "Proxy should have forwarded the message (Shadow Mode) within 10s"
        assert "method" in response or "result" in response
        
        # 4. Verify log file reached shadow block
        time.sleep(1)
        assert log_file.exists()
        log_content = log_file.read_text()
        assert "SHADOW" in log_content or "audit_only" in log_content or "execute_command" in log_content
        
        # 5. Start Dashboard
        dash_proc = subprocess.Popen(
            ["python", "-m", "core.cli", "ui", "--port", "4041"],
            env=env
        )
        
        try:
            time.sleep(3) # Wait for FastAPI to boot
            
            # 6. Check Dashboard /logs fragment
            with httpx.Client() as client:
                resp = client.get("http://127.0.0.1:4041/logs")
                assert resp.status_code == 200
                assert "SHADOW-BLOCK" in resp.text
                assert "execute_command" in resp.text
                
        finally:
            dash_proc.terminate()
            
    finally:
        proxy_proc.terminate()
        if log_file.exists():
            log_file.unlink()
