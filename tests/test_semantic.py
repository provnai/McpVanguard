"""
tests/test_semantic.py — Tests for Layer 2 semantic analysis using mocks.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from core import semantic

@pytest.fixture
def mock_ollama_client():
    with patch("httpx.Client") as mock_client:
        # Create a mock instance
        instance = MagicMock()
        mock_client.return_value.__enter__.return_value = instance
        yield instance

@pytest.fixture(autouse=True)
def enable_semantic():
    with patch("core.semantic.ENABLED", True):
        yield

def test_semantic_block_highly_malicious(mock_ollama_client):
    # Mock malicious response
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "message": {
            "content": json.dumps({"score": 0.95, "reason": "Clear exfiltration attempt"})
        }
    }
    mock_ollama_client.post.return_value = mock_resp
    
    import asyncio
    msg = {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/etc/shadow"}}
    }
    
    res = asyncio.run(semantic.score_intent(msg))
    
    assert res is not None
    assert res.action == "BLOCK"
    assert res.layer_triggered == 2
    assert res.semantic_score == 0.95
    assert "Clear exfiltration attempt" in res.block_reason

def test_semantic_warn_suspicious(mock_ollama_client):
    # Mock suspicious response
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "message": {
            "content": json.dumps({"score": 0.6, "reason": "Unusual file access"})
        }
    }
    mock_ollama_client.post.return_value = mock_resp
    
    import asyncio
    msg = {
        "method": "tools/call",
        "params": {"name": "list_directory", "arguments": {"path": "/Users/admin/Documents"}}
    }
    
    res = asyncio.run(semantic.score_intent(msg))
    
    assert res is not None
    assert res.action == "WARN"
    assert res.layer_triggered == 2
    assert res.semantic_score == 0.6

def test_semantic_allow_benign(mock_ollama_client):
    # Mock benign response
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "message": {
            "content": json.dumps({"score": 0.1, "reason": "Normal usage"})
        }
    }
    mock_ollama_client.post.return_value = mock_resp
    
    import asyncio
    msg = {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "README.md"}}
    }
    
    res = asyncio.run(semantic.score_intent(msg))
    
    assert res is None  # None means pass-through (allowed)

def test_semantic_ollama_offline(mock_ollama_client):
    # Mock connection error
    import httpx
    mock_ollama_client.post.side_effect = httpx.ConnectError("Connection refused")
    
    import asyncio
    msg = {
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "foo"}}
    }
    
    res = asyncio.run(semantic.score_intent(msg))
    
    assert res is None  # Should fail open (allowed)
