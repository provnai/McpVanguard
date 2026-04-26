import os
import sys
import unittest
import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.rules_engine import RulesEngine, Rule
from core.models import RuleAction, RuleSeverity
from core.semantic import score_intent
from core.behavioral import inspect_request

class TestAuditRemediation(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.rules_engine = RulesEngine(rules_dir="rules")

    def test_redos_fail_closed(self):
        """Verify that a timeout in regex search triggers a fail-closed block."""
        # Create a rule with a simple regex
        rule_data = {
            "id": "REDOS-TEST",
            "description": "Fail-closed test",
            "severity": RuleSeverity.CRITICAL,
            "action": RuleAction.BLOCK,
            "match_fields": ["params.command"],
            "pattern": "test"
        }
        rule = Rule(rule_data, "test.yaml")
        rule.pattern = SimpleNamespace(backend="python", search=lambda value: None)
        
        # Patch the match pool's result to raise TimeoutError
        from concurrent.futures import TimeoutError as FuturesTimeoutError
        with patch("concurrent.futures.Future.result", side_effect=FuturesTimeoutError()):
            result = rule._safe_search("any text")
            self.assertTrue(result, "Fail-closed should return True (match found) on timeout")

    def test_network_bypass_remediation(self):
        """Verify NET-007, NET-009, NET-010, NET-011 now catch command-based bypasses."""
        bypass_payloads = [
            # NET-007 (Hex IP) in command
            {"method": "tools/call", "params": {"command": "curl 0xA9FEA9FE"}},
            # NET-009 (Integer IP) in command
            {"method": "tools/call", "params": {"command": "wget http://2852039166"}},
            # NET-010 (Octal IP) in command
            {"method": "tools/call", "params": {"command": "curl http://010.010.010.010"}},
            # NET-011 (Leading-zero IP) in command
            {"method": "tools/call", "params": {"command": "ping 010.1.1.1"}},
        ]
        
        for payload in bypass_payloads:
            result = self.rules_engine.check(payload)
            self.assertFalse(result.allowed, f"Payload should be blocked: {payload}")
            self.assertEqual(result.layer_triggered, 1)

    async def test_semantic_fail_closed(self):
        """Verify semantic fail-closed logic."""
        with patch.dict(os.environ, {"VANGUARD_SEMANTIC_ENABLED": "true", "VANGUARD_SEMANTIC_FAIL_CLOSED": "true"}):
            # We need to reload the module or re-patch the constants
            import core.semantic
            with patch("core.semantic.ENABLED", True), \
                 patch("core.semantic.ENABLE_FAIL_CLOSED", True), \
                 patch("httpx.Client.post", side_effect=Exception("API Down")):
                
                payload = {"method": "tools/call", "params": {"path": "/etc/passwd"}}
                result = await score_intent(payload)
                self.assertIsNotNone(result)
                self.assertFalse(result.allowed, "Should block on API error when fail-closed is enabled")
                self.assertEqual(result.action, "BLOCK")

    async def test_windows_sensitive_paths(self):
        """Verify behavioral layer detects Windows sensitive paths."""
        from core.behavioral import inspect_request, clear_state
        # Mock session ID
        session_id = "test-session-windows"
        clear_state(session_id)
        
        # Test paths
        windows_paths = [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Users\\Admin\\AppData\\Local\\Microsoft\\Credentials\\SomeFile",
            "D:\\Backup\\NTDS.DIT"
        ]
        
        for path in windows_paths:
            # First read (allowed, but marks session as 'had_sensitive_read')
            msg = {"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": path}}}
            await inspect_request(session_id, msg)
            
            # Second call: write (should block BEH-003)
            write_msg = {"method": "tools/call", "params": {"name": "write_file", "arguments": {"path": "tmp.txt"}}}
            result = await inspect_request(session_id, write_msg)
            self.assertIsNotNone(result, f"Write after reading sensitive Windows path {path} should be blocked")
            self.assertFalse(result.allowed)
            self.assertEqual(result.rule_matches[0].rule_id, "BEH-003")

if __name__ == "__main__":
    unittest.main()
