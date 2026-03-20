"""
tests/test_breakouts.py
Task 5: The Breakout Suite

These integration tests simulate an untrusted agent attempting to bypass
the L1 proxy using various path traversal, canonicalization, and payload attacks.
They verify that the RulesEngine correctly delegates to core/jail.py and behavioral.py.
"""

import unittest
from unittest.mock import patch
from core.rules_engine import RulesEngine
from core.models import SafeZone
import os

class TestBreakoutSuite(unittest.TestCase):
    def setUp(self):
        self.engine = RulesEngine(rules_dir="rules")
        # Ensure we have our test safe zones loaded
        self.engine.safe_zones = [
            SafeZone(tool="read_file", allowed_prefixes=["/safe/zone", "C:\\safe\\zone"]),
            SafeZone(tool="write_file", allowed_prefixes=["/safe/out", "C:\\safe\\out"])
        ]

    # --- 1. Path Traversal & Symlink Escapes (Linux/General) ---

    @patch("platform.system")
    def test_basic_traversal_blocked(self, mock_system):
        """Standard ../ traversal out of the safe zone should be blocked."""
        mock_system.return_value = "Windows"  # Uses standard fallback logic
        
        msg = {
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/safe/zone/../../etc/passwd"}
            }
        }
        res = self.engine.check(msg)
        self.assertFalse(res.allowed, "Path traversal should be blocked")

    @patch("os.path.exists")
    @patch("platform.system")
    @patch("core.jail._is_openat2_available")
    @patch("ctypes.CDLL")
    @patch("os.open")
    @patch("os.close")
    def test_linux_symlink_toctou_blocked(self, mock_close, mock_open, mock_cdll, mock_openat2, mock_system, mock_exists):
        """If openat2 fails due to a symlink escaping the dirfd, block it."""
        mock_exists.return_value = True
        mock_system.return_value = "Linux"
        mock_openat2.return_value = True
        mock_libc = mock_cdll.return_value
        mock_libc.syscall.return_value = -1  # openat2 triggers error (e.g. EXDEV)
        mock_open.return_value = 5

        msg = {
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/safe/zone/malicious_symlink"} # Symlink points to /etc/passwd
            }
        }
        res = self.engine.check(msg)
        
        # The syscall is attempted, fails, and the zone breach block occurs
        self.assertFalse(res.allowed)
        self.assertIn("SAFEZONE", res.rule_matches[0].rule_id)

    # --- 2. Windows-Specific Bypasses ---

    @patch("platform.system")
    def test_windows_dos_device_bypass_blocked(self, mock_system):
        """Attempts to bypass string checks using DOS device namespace."""
        mock_system.return_value = "Windows"
        
        msg = {
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "\\\\.\\C:\\Windows\\System32\\SAM"}
            }
        }
        res = self.engine.check(msg)
        self.assertFalse(res.allowed)
        self.assertIn("SAFEZONE", res.rule_matches[0].rule_id)

    @patch("platform.system")
    @patch("core.jail._get_final_path_windows")
    def test_windows_shortname_bypass_blocked(self, mock_final_path, mock_system):
        """Using 8.3 shortnames to bypass regex/string blocks."""
        mock_system.return_value = "Windows"
        
        # The agent asks for PROGRA~1, GetFinalPathNameByHandleW reveals it's Program Files which is OUTSIDE safe zone
        mock_final_path.side_effect = lambda p: "C:\\Program Files" if "PROGRA~1" in p else p
        
        msg = {
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "C:\\PROGRA~1\\secret.txt"}
            }
        }
        res = self.engine.check(msg)
        self.assertFalse(res.allowed)


    # --- 3. Missing Safe Zones (Safe fallback) ---
    
    @patch("platform.system")
    def test_unrestricted_tool_allowed(self, mock_system):
        """A tool with NO defined safe zone falls back to standard regex rules (L1 legacy)."""
        mock_system.return_value = "Windows"
        
        # 'echo' has no safe zone
        msg = {
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {"message": "hello"}
            }
        }
        res = self.engine.check(msg)
        self.assertTrue(res.allowed)


if __name__ == "__main__":
    unittest.main()
