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
    
    import sys
    import threading
    import queue

    # 1. Start proxy in SHADOW MODE (audit)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path.cwd())
    env["VANGUARD_MODE"] = "audit"
    env["VANGUARD_LOG_FILE"] = str(log_file)
    env["VANGUARD_RULES_DIR"] = str(rules_dir)
    env["VANGUARD_AUDIT_FORMAT"] = "json"
    
    # Use a pure-python echo server as the backend
    echo_server = f'"{sys.executable}" -u -c "import sys; [sys.stdout.buffer.write(line) or sys.stdout.buffer.flush() for line in sys.stdin.buffer]"'
    
    proxy_proc = subprocess.Popen(
        [sys.executable, "-m", "core.cli", "start", "--server", echo_server, "--no-behavioral"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=0
    )
    
    # Non-blocking reader thread
    q = queue.Queue()
    def enqueue_output(out, queue):
        for line in iter(out.readline, ''):
            queue.put(line)
        out.close()
    
    t = threading.Thread(target=enqueue_output, args=(proxy_proc.stdout, q))
    t.daemon = True
    t.start()

    try:
        # 2. Send a forbidden command (rm -rf /)
        time.sleep(4) # Give it plenty of time to boot
        
        forbidden_msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "execute_command", "arguments": {"command": "rm -rf /"}},
            "id": 101
        })
        proxy_proc.stdin.write(forbidden_msg + "\n")
        proxy_proc.stdin.flush()
        
        # Wait for proxy to process and write to log
        time.sleep(2)
        
        # 3. Read response from queue with timeout
        response = None
        start_time = time.time()
        while time.time() - start_time < 10:
            try:
                line = q.get_nowait()
                line = line.strip()
                if line.startswith("{"):
                    msg = json.loads(line)
                    if msg.get("id") == 101:
                        response = msg
                        break
            except queue.Empty:
                pass
            time.sleep(0.1)
        
        assert response, "Proxy should have forwarded the message (Shadow Mode) within 10s"
        
        # 4. Verify log file
        time.sleep(2)
        assert log_file.exists(), f"Log file {log_file} should have been created"
        log_content = log_file.read_text()
        assert "SHADOW" in log_content or "audit_only" in log_content
        
        # 5. Start Dashboard in a background thread (same process to avoid path issues)
        import uvicorn
        from core import dashboard as dash_mod
        
        # Sync the log file pointer for the dashboard thread
        dash_mod.LOG_FILE = str(log_file)
        
        test_port = 4850
        config = uvicorn.Config(dash_mod.app, host="127.0.0.1", port=test_port, log_level="warning")
        server = uvicorn.Server(config)
        
        # Override the server's install_signal_handlers if in a thread
        server.install_signal_handlers = lambda: None
        
        dash_thread = threading.Thread(target=server.run, daemon=True)
        dash_thread.start()
        
        try:
            # Robust retry loop for FastAPI startup (prevents WinError 10061)
            connected = False
            for _ in range(15):  # 15 second timeout
                time.sleep(1)
                try:
                    with httpx.Client() as client:
                        resp = client.get(f"http://127.0.0.1:{test_port}/logs", timeout=2)
                        if resp.status_code == 200:
                            assert "execute_command" in resp.text
                            connected = True
                            break
                except (httpx.ConnectError, httpx.RequestError):
                    continue
            
            if not connected:
                assert connected, f"Dashboard at {test_port} failed to become responsive within 15s"
        finally:
            server.should_exit = True
            dash_thread.join(timeout=5)
            
    finally:
        proxy_proc.terminate()
        proxy_proc.wait(timeout=5)
        if log_file.exists():
            try:
                log_file.unlink()
            except PermissionError:
                pass
