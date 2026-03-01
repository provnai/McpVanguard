"""
tests/test_proxy.py — Integration tests for the VanguardProxy.
Verifies orchestration of Layer 1 (Rules), Layer 2 (Semantic), and Layer 3 (Behavioral).
"""

import asyncio
import json
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from core.proxy import VanguardProxy, ProxyConfig
from core.models import InspectionResult, RuleMatch

@pytest.fixture
def mock_config():
    config = ProxyConfig()
    config.rules_dir = "rules"
    config.semantic_enabled = True
    config.behavioral_enabled = True
    return config

@pytest.fixture
def proxy(mock_config):
    p = VanguardProxy(server_command=["python", "-c", "print('hello')"], config=mock_config)
    # Set a dummy session for tests that need it (Layer 3)
    from core.session import SessionState
    p._session = SessionState(session_id="test-session")
    return p

@pytest.mark.asyncio
async def test_proxy_blocks_layer_1_rules(proxy):
    # Layer 1 should block path traversal immediately
    msg = {
        "jsonrpc": "2.0",
        "id": "123",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}
    }
    
    result = await proxy._inspect_message(msg)
    
    assert not result.allowed
    assert result.action == "BLOCK"
    # Layer 1 triggers first
    assert any(r.rule_id.startswith("FS-") or r.rule_id.startswith("PRIV-") for r in result.rule_matches)

@pytest.mark.asyncio
async def test_proxy_blocks_layer_2_semantic(proxy):
    # Mock Layer 1 to ALLOW
    # Mock Layer 2 to BLOCK
    malicious_result = InspectionResult(
        allowed=False,
        action="BLOCK",
        layer_triggered=2,
        rule_matches=[RuleMatch(rule_id="SEM-BLOCK", severity="HIGH")],
        semantic_score=0.9,
        block_reason="Semantic detection"
    )
    
    with patch("core.semantic.score_intent", new_callable=AsyncMock) as mock_sem:
        mock_sem.return_value = malicious_result
        
        msg = {
            "jsonrpc": "2.0",
            "id": "123",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "benign.txt"}}
        }
        
        # We need to ensure Layer 1 doesn't block it
        with patch.object(proxy.rules_engine, "check", return_value=InspectionResult.allow()):
            result = await proxy._inspect_message(msg)
            
            assert not result.allowed
            assert result.action == "BLOCK"
            assert result.layer_triggered == 2
            assert result.semantic_score == 0.9

@pytest.mark.asyncio
async def test_proxy_blocks_layer_3_behavioral(proxy):
    # Mock Layer 3 to BLOCK
    beh_result = InspectionResult(
        allowed=False,
        action="BLOCK",
        layer_triggered=3,
        rule_matches=[RuleMatch(rule_id="BEH-001", severity="HIGH")],
        block_reason="Behavioral detection"
    )
    
    with patch("core.behavioral.inspect_request") as mock_beh:
        mock_beh.return_value = beh_result
        
        msg = {
            "jsonrpc": "2.0",
            "id": "123",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "benign.txt"}}
        }
        
        with patch.object(proxy.rules_engine, "check", return_value=InspectionResult.allow()):
            result = await proxy._inspect_message(msg)
            
            assert not result.allowed
            assert result.action == "BLOCK"
            assert result.layer_triggered == 3

@pytest.mark.asyncio
async def test_proxy_allows_clean_request(proxy):
    # All layers return ALLOW/None
    msg = {
        "jsonrpc": "2.0",
        "id": "123",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "README.md"}}
    }
    
    with patch.object(proxy.rules_engine, "check", return_value=InspectionResult.allow()), \
         patch("core.behavioral.inspect_request", return_value=None), \
         patch("core.semantic.score_intent", new_callable=AsyncMock, return_value=None):
        
        result = await proxy._inspect_message(msg)
        assert result.allowed
        assert result.action == "ALLOW"
