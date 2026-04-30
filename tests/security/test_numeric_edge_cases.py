"""
tests/security/test_numeric_edge_cases.py
Verifies that McpVanguard rejects NaN and Infinity in JSON-RPC payloads
to prevent downstream crashes and spec-violation bypasses.
"""

import json
import pytest
import math
from core.proxy import VanguardProxy, ProxyConfig

@pytest.mark.asyncio
async def test_reject_nan_in_request():
    """Verify that NaN in a tool call parameter is rejected."""
    proxy = VanguardProxy(server_command=["mock"])
    
    # Payload with NaN
    malicious_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "calculate",
            "arguments": {"value": float("nan")}
        }
    }
    
    # Should raise ValueError during normalization
    with pytest.raises(ValueError) as excinfo:
        proxy._normalize_message(malicious_msg)
    
    assert "NaN/Infinity" in str(excinfo.value)

@pytest.mark.asyncio
async def test_reject_infinity_in_request():
    """Verify that Infinity in a tool call parameter is rejected."""
    proxy = VanguardProxy(server_command=["mock"])
    
    # Payload with Infinity
    malicious_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "calculate",
            "arguments": {"value": float("inf")}
        }
    }
    
    # Should raise ValueError during normalization
    with pytest.raises(ValueError) as excinfo:
        proxy._normalize_message(malicious_msg)
    
    assert "NaN/Infinity" in str(excinfo.value)

@pytest.mark.asyncio
async def test_allow_normal_numbers():
    """Verify that normal floats and ints still pass."""
    proxy = VanguardProxy(server_command=["mock"])
    
    valid_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "calculate",
            "arguments": {"value": 42.5, "count": 10}
        }
    }
    
    normalized = proxy._normalize_message(valid_msg)
    assert normalized["params"]["arguments"]["value"] == 42.5
    assert normalized["params"]["arguments"]["count"] == 10
