"""
mcp_servers/memory_server.py
A mock MCP server that provides key-value memory storage.
Used in Level 4: The Whisperer.
"""

import sys
from fastmcp import FastMCP

mcp = FastMCP("Memory")

# Internal storage
_memory = {}

@mcp.tool()
async def save_memory(key: str, value: str) -> str:
    """Store a value in memory for later retrieval."""
    _memory[key] = value
    return f"Saved to memory: {key}"

@mcp.tool()
async def get_memory(key: str) -> str:
    """Retrieve a value from memory."""
    return _memory.get(key, "Key not found")

@mcp.tool()
async def clear_memory() -> str:
    """Clear all stored values."""
    _memory.clear()
    return "Memory cleared"

if __name__ == "__main__":
    mcp.run()
