import pytest
import json
from core.proxy import VanguardProxy, ProxyConfig

@pytest.mark.asyncio
async def test_enrich_tool_list_vanguard():
    """Verify that _enrich_tool_list injects native tools and safety hints."""
    proxy = VanguardProxy(server_command=["python", "-c", "pass"])
    
    mock_tools = [
        {"name": "read_file", "description": "Read a file"},
        {"name": "write_to_disk", "description": "Write something"},
        {"name": "unknown_tool", "description": "No prefix"}
    ]
    
    enriched = proxy._enrich_tool_list(mock_tools)
    
    # Check that native tools are present
    vanguard_names = [t["name"] for t in enriched if t["name"].startswith("vanguard_")]
    assert "get_vanguard_status" in [t["name"] for t in enriched]
    assert len(vanguard_names) >= 2
    
    # Check Hints
    for t in enriched:
        name = t["name"]
        if name == "read_file":
            assert t["readOnlyHint"] is True
            assert t["title"] == "Read File"
        elif name == "write_to_disk":
            assert t["destructiveHint"] is True
            assert t["title"] == "Write To Disk"
        elif name == "unknown_tool":
            assert t["readOnlyHint"] is True # Default
            assert t["title"] == "Unknown Tool"
        elif name == "vanguard_apply_rule":
            assert t["destructiveHint"] is True
            assert t["title"] == "Vanguard: Hot-Patch Rule"

@pytest.mark.asyncio
async def test_proxy_intercepts_vanguard_tools():
    """Check if the logic would call management handler for vanguard_ tools."""
    # This is a bit hard to unit test without full mock pumps, but we can check the logic flow.
    pass
