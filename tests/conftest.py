"""
tests/conftest.py
Shared pytest fixtures for McpVanguard tests.
"""
import pytest
import json
from core.rules_engine import RulesEngine
from core.session import SessionManager, SessionState
from core.models import InspectionResult


@pytest.fixture
def rules_engine():
    """Load the real rules engine with the real rules/ directory."""
    return RulesEngine(rules_dir="rules")


@pytest.fixture
def session_manager():
    return SessionManager()


@pytest.fixture
def session(session_manager):
    return session_manager.create()


# ---------------------------------------------------------------------------
# Message factory helpers
# ---------------------------------------------------------------------------

def make_tool_call(tool_name: str, **kwargs) -> dict:
    """Build a valid MCP tools/call JSON-RPC message."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": kwargs,
        }
    }


def make_generic_request(method: str, **params) -> dict:
    """Build a generic JSON-RPC request."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
