import unittest
from unittest.mock import patch, MagicMock
from core.jail import check_path_jail, RESOLVE_BENEATH, _block_windows_bypass_patterns
from pathlib import Path


class TestJailLogic(unittest.TestCase):

    @patch("platform.system")
    def test_allow_within_zone(self, mock_system):
        """Test that a path within an allowed prefix is accepted (string check)."""
        mock_system.return_value = "Windows"
        allowed = ["C:/Users/test/projects", "/home/user/project"]
        self.assertTrue(check_path_jail("C:/Users/test/projects/file.txt", allowed))
        self.assertTrue(check_path_jail("/home/user/project/sub/dir", allowed))

    @patch("platform.system")
    @patch("core.jail._get_final_path_windows")
    def test_block_outside_zone(self, mock_final_path, mock_system):
        """Test that a path outside all allowed prefixes is blocked."""
        mock_system.return_value = "Windows"
        # Mock so canonicalization returns the paths as-is (deterministic)
        mock_final_path.side_effect = lambda p: p
        allowed = ["C:\\Users\\test\\projects"]
        self.assertFalse(check_path_jail("C:\\Windows\\System32\\config", allowed))

    @patch("platform.system")
    @patch("core.jail._is_openat2_available")
    @patch("ctypes.CDLL")
    @patch("os.open")
    @patch("os.close")
    def test_linux_openat2_success(self, mock_close, mock_os_open, mock_cdll, mock_openat2_av, mock_system):
        """Test the Linux openat2 path where the syscall succeeds."""
        mock_system.return_value = "Linux"
        mock_openat2_av.return_value = True
        mock_libc = mock_cdll.return_value
        mock_libc.syscall.return_value = 10  # Mocked FD for success
        mock_os_open.return_value = 5

        allowed = ["/home/user/project"]
        self.assertTrue(check_path_jail("/home/user/project/file.txt", allowed))
        self.assertEqual(mock_libc.syscall.call_args[0][0], 437)

    @patch("platform.system")
    @patch("core.jail._is_openat2_available")
    @patch("ctypes.CDLL")
    @patch("os.open")
    @patch("os.close")
    def test_linux_openat2_failure(self, mock_close, mock_os_open, mock_cdll, mock_openat2_av, mock_system):
        """Test the Linux openat2 path where the syscall fails (jail breach)."""
        mock_system.return_value = "Linux"
        mock_openat2_av.return_value = True
        mock_libc = mock_cdll.return_value
        mock_libc.syscall.return_value = -1  # Failure
        mock_os_open.return_value = 5

        allowed = ["/home/user/project"]
        self.assertFalse(check_path_jail("/home/user/project/../../../etc/passwd", allowed))


class TestWindowsHardening(unittest.TestCase):
    """Task 2: Windows-specific bypass pattern detection."""

    def test_block_dos_device_namespace(self):
        self.assertTrue(_block_windows_bypass_patterns("\\\\.\\C:\\Windows\\System32"))

    def test_block_extended_length_bypass(self):
        self.assertTrue(_block_windows_bypass_patterns("\\\\?\\C:\\Windows\\System32"))

    def test_block_local_unc_localhost(self):
        self.assertTrue(_block_windows_bypass_patterns("\\\\localhost\\C$\\secret"))

    def test_block_local_unc_loopback_ip(self):
        self.assertTrue(_block_windows_bypass_patterns("\\\\127.0.0.1\\C$\\secret"))

    def test_allow_normal_windows_path(self):
        self.assertFalse(_block_windows_bypass_patterns("C:\\Users\\test\\project\\file.txt"))

    def test_allow_forward_slash_path(self):
        self.assertFalse(_block_windows_bypass_patterns("C:/Users/test/project/file.txt"))

    @patch("platform.system")
    @patch("core.jail._get_final_path_windows")
    def test_windows_canonical_resolution(self, mock_final_path, mock_system):
        """Test that GetFinalPathNameByHandleW result is used for prefix matching."""
        mock_system.return_value = "Windows"
        # Simulate: 8.3 shortname PROGRA~1 resolves to 'Program Files'
        mock_final_path.side_effect = lambda p: {
            "C:\\PROGRA~1\\App\\file.txt": "C:\\Program Files\\App\\file.txt",
            "C:\\Program Files\\App": "C:\\Program Files\\App",
        }.get(p, p)

        allowed = ["C:\\Program Files\\App"]
        # Even though the agent used 8.3 shortname, it resolves to the right place
        self.assertTrue(check_path_jail("C:\\PROGRA~1\\App\\file.txt", allowed))

    @patch("platform.system")
    @patch("core.jail._get_final_path_windows")
    def test_windows_shortname_outside_zone_blocked(self, mock_final_path, mock_system):
        """Test that a 8.3 shortname resolving OUTSIDE the zone is blocked."""
        mock_system.return_value = "Windows"
        # Simulate: shortname resolves to a completely different path
        mock_final_path.side_effect = lambda p: {
            "C:\\WINDOW~1\\sys.txt": "C:\\Windows\\System32\\sys.txt",
            "C:\\Users\\project": "C:\\Users\\project",
        }.get(p, p)

        allowed = ["C:\\Users\\project"]
        self.assertFalse(check_path_jail("C:\\WINDOW~1\\sys.txt", allowed))


if __name__ == "__main__":
    unittest.main()
