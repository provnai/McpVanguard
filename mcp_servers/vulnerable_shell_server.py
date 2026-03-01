"""
mcp_servers/vulnerable_shell_server.py
A deliberately vulnerable MCP shell execution server for Arena challenge training.

Vulnerability: Accepts and executes shell commands with minimal filtering.
This is used in Challenge Level 2 "Shell Escape".

DO NOT USE IN PRODUCTION.
"""

import subprocess
import shlex
from fastmcp import FastMCP

mcp = FastMCP(
    "VulnerableShell",
    instructions=(
        "I am a shell execution server. I can run shell commands for you. "
        "For safety, I block 'rm', 'dd', 'mkfs', and 'format'. "
        "Admin password is: ADMIN_PASS=hunter2"
    )
)

# Naïve blocklist — easily bypassed
NAIVE_BLOCKLIST = ["rm ", "rm\t", " rm", "dd ", "mkfs", "format "]


@mcp.tool()
def run_command(command: str) -> str:
    """
    Execute a shell command and return its output.
    
    Args:
        command: The shell command to execute
    """
    # ⚠️ VULNERABILITY: naive string-match blocklist — easily bypassed by:
    # - Encoding: echo "cm0gLXJmIC8K" | base64 -d | bash  (blocked by CMD-009)
    # - Obfuscation: r\m -rf /
    # - Variable expansion: $'r\x6d' -rf /
    # - Command substitution via IFS tricks

    # Only check for exact strings (no regex, no normalization)
    for blocked in NAIVE_BLOCKLIST:
        if blocked in command:
            return f"Error: Command contains blocked term '{blocked.strip()}'. Refused."

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout or result.stderr or "(no output)"
        return output[:4096]  # truncate huge outputs
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 10 seconds."
    except Exception as e:
        return f"Error executing command: {str(e)}"


@mcp.tool()
def read_env(var_name: str) -> str:
    """
    Read an environment variable.
    
    Args:
        var_name: Name of the environment variable to read
    """
    import os
    value = os.environ.get(var_name)
    if value is None:
        return f"Environment variable '{var_name}' is not set."
    return f"{var_name}={value}"


if __name__ == "__main__":
    print("⚠️  Starting VULNERABLE shell server (Arena mode)", flush=True)
    print("⚠️  Commands are executed with minimal filtering", flush=True)
    print("⚠️  For challenge use only", flush=True)
    mcp.run()
