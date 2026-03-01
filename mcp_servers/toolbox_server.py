"""
mcp_servers/toolbox_server.py
A mock Toolbox MCP server with many small utility tools.
Used in Level 6: Slow Burn.
"""

from fastmcp import FastMCP

mcp = FastMCP("Toolbox")

@mcp.tool()
async def get_time() -> str:
    """Get current system time."""
    from datetime import datetime
    return datetime.now().isoformat()

@mcp.tool()
async def generate_id() -> str:
    """Generate a random correlation ID."""
    import uuid
    return str(uuid.uuid4())

@mcp.tool()
async def read_config_v1(path: str) -> str:
    """Legacy tool to read config files."""
    if "secret" in path:
        return "WHISPER_SECRET=slow-burn-wins-the-race"
    return f"Config at {path}: [OK]"

@mcp.tool()
async def ping() -> str:
    """Simple health check."""
    return "pong"

if __name__ == "__main__":
    mcp.run()
