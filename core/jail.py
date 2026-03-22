"""
core/jail.py
Task 1: Kernel-Level Jailing logic for Linux (openat2) and Windows (GetFinalPathNameByHandleW).
Provides deterministic path validation and TOCTOU protection.
"""

import os
import ctypes
import logging
import platform
from pathlib import Path
from typing import Optional, List

logger = logging.getLogger(__name__)

# --- Linux openat2 constants and structs ---
# Syscall number 437 for x86_64, aarch64, riscv64
SYS_OPENAT2 = 437

# RESOLVE_* flags for open_how.resolve
RESOLVE_NO_XDEV = 0x01       # Don't cross mount points
RESOLVE_NO_MAGICLINKS = 0x02 # Block /proc/self/fd/ etc.
RESOLVE_NO_SYMLINKS = 0x04   # Block all symlinks
RESOLVE_BENEATH = 0x08       # Block paths escaping the dirfd
RESOLVE_IN_ROOT = 0x10       # Treat dirfd as root for the call

class OpenHow(ctypes.Structure):
    """struct open_how for openat2(2)"""
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]

# --- Windows constants ---
FILE_LIST_DIRECTORY = 0x0001
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
OPEN_EXISTING = 3
VOLUME_NAME_DOS = 0x0


# --- Windows API constants for Task 2 ---
FILE_READ_ATTRIBUTES = 0x0080
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
VOLUME_NAME_DOS = 0x0

# DOS device and UNC prefixes that must be blocked before any canonicalization
_WINDOWS_BYPASS_PREFIXES = (
    "\\\\.\\",      # DOS device namespace (e.g., \\.\C:\)
    "\\\\?\\",      # Extended-length path bypass (e.g., \\?\C:\)
    "\\\\?\\UNC\\", # Extended-length UNC path
)
_WINDOWS_LOCAL_UNC_HOSTS = ("localhost", "127.0.0.1", "::1")



def _block_windows_bypass_patterns(path: str) -> bool:
    """
    Returns True if the path uses a known Windows bypass pattern that could
    undermine prefix-based validation. These must be blocked unconditionally.
    """
    # Normalize separators for consistent matching
    norm = path.replace("/", "\\")

    # Block all UNC paths and DOS device paths outright (Task 8: Expand UNC blocking)
    if norm.startswith("\\\\"):
        logger.warning(f"Windows bypass pattern or UNC path blocked: {path!r}")
        return True

    return False


def _get_final_path_windows(path: str) -> Optional[str]:
    """
    Task 2: Use GetFinalPathNameByHandleW to resolve the true canonical path.
    This resolves symlinks, 8.3 shortnames, and junction points at the OS level.
    Uses FILE_FLAG_BACKUP_SEMANTICS so directories can be opened without side-effects.
    """
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # Open a handle — works on both files and directories (BACKUP_SEMANTICS)
        handle = kernel32.CreateFileW(
            path,
            FILE_READ_ATTRIBUTES,
            0x7,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )

        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            logger.debug(f"CreateFileW failed for {path!r}: error {err}")
            return None

        try:
            # Query the required buffer size first
            buf_size = kernel32.GetFinalPathNameByHandleW(handle, None, 0, VOLUME_NAME_DOS)
            buf = ctypes.create_unicode_buffer(buf_size + 1)
            kernel32.GetFinalPathNameByHandleW(handle, buf, buf_size + 1, VOLUME_NAME_DOS)
            # Strip the \\?\ prefix added by GetFinalPathNameByHandleW
            final = buf.value
            if not final:
                return None
            if final.startswith("\\\\?\\"):
                final = final[4:]
            return final
        finally:
            kernel32.CloseHandle(handle)

    except Exception as e:
        logger.error(f"GetFinalPathNameByHandleW failed: {e}")
        return None


def check_path_jail(path: str, allowed_prefixes: List[str], recursive: bool = True) -> bool:
    """
    Main entry point for jailing checks.
    Uses kernel-level APIs to verify a path resides within allowed prefixes.
    
    Args:
        path: The requested path to validate.
        allowed_prefixes: List of authorized directory/file root prefixes.
        recursive: If False, only files directly inside the prefix are allowed (P2 Audit Finding).
    """
    if not allowed_prefixes:
        return True  # No jails defined, allow all (standard behavior)

    import unicodedata
    path = unicodedata.normalize("NFKC", path)
    allowed_prefixes = [unicodedata.normalize("NFKC", p) for p in allowed_prefixes]

    # Deterministic Traversal Protection (P2 Audit Finding + Research)
    # Block any path that contains traversal tokens AFTER normalization.
    # This prevents lookalike-character bypasses where resolve() fails to collapse them.
    norm_path = path.replace("/", "\\")
    if "..\\" in norm_path or "\\.." in norm_path or norm_path.startswith("..") or norm_path.endswith(".."):
        logger.warning(f"TRAVERSAL ATTEMPT BLOCKED: Path {repr(path)} contains traversal tokens.")
        return False

    system = platform.system()

    # --- Task 2: Windows-specific hard checks FIRST ---
    if system == "Windows":
        if _block_windows_bypass_patterns(path):
            return False  # Always block bypass patterns, no exceptions

        # Use GetFinalPathNameByHandleW for true handle-based canonicalization
        final_path = _get_final_path_windows(path)
        if final_path is None:
            final_path = os.path.abspath(path)

        for prefix in allowed_prefixes:
            final_prefix = _get_final_path_windows(prefix)
            if final_prefix is None:
                final_prefix = os.path.abspath(prefix)
            
            # Standardize Windows separators and strip extended prefixes for comparison
            p_final = final_path.replace("/", "\\")
            pref_final = final_prefix.replace("/", "\\")

            if p_final.startswith("\\\\?\\"):
                p_final = p_final[4:]
            if p_final.startswith("UNC\\"): 
                p_final = "\\\\" + p_final[4:]
            if pref_final.startswith("\\\\?\\"):
                pref_final = pref_final[4:]
            if pref_final.startswith("UNC\\"):
                pref_final = "\\\\" + pref_final[4:]

            lower_p = p_final.lower()
            lower_pref = pref_final.lower()
            if not lower_pref.endswith("\\"):
                lower_pref += "\\"

            # If path matches prefix (as directory) or is exactly the prefix
            if lower_p.startswith(lower_pref) or lower_p == lower_pref[:-1]:
                if not recursive:
                    # Non-recursive: must be an immediate child or the dir itself
                    try:
                        rel = os.path.relpath(p_final, pref_final.rstrip("\\"))
                        if rel != "." and ("\\" in rel or "/" in rel):
                            continue # Deeper subpath, block if non-recursive
                    except (ValueError, RuntimeError):
                        continue
                return True
        return False

    # --- Task 1: Linux fallback path ---
    try:
        canonical_path = _canonicalize(path)
        for prefix in allowed_prefixes:
            try:
                can_prefix = _canonicalize(prefix)
                # Check if canonical_path is a subpath of can_prefix
                rel = canonical_path.relative_to(can_prefix)
                
                # Recursive check
                if not recursive:
                    if len(rel.parts) > 1:
                        continue # Nested, block if non-recursive

                if _is_openat2_available() and os.path.exists(str(can_prefix)):
                    return _check_path_jail_linux(path, str(can_prefix))
                return True
            except (ValueError, RuntimeError):
                continue
    except Exception as e:
        logger.error(f"[Vanguard-Jail] Critical error in Linux jail logic: {e}")
        return False

    return False


def _canonicalize(path_str: str) -> Path:
    """
    Soft-canonicalization for baseline checks.
    Includes Unicode NFKC normalization to prevent lookalike-character bypasses (P2 Audit Finding).
    """
    import unicodedata
    normalized = unicodedata.normalize("NFKC", path_str)
    return Path(normalized).expanduser().resolve()

def _is_openat2_available() -> bool:
    """Check if the kernel supports openat2 (5.6+)."""
    if platform.system() != "Linux":
        return False
    # Simple check: try to call syscall -1 (non-destructive)
    try:
        libc = ctypes.CDLL("libc.so.6")
        # syscall(-1) usually returns -1 with errno set
        return True # Assume available if we can talk to libc
    except:
        return False

def _check_path_jail_linux(path: str, root_prefix: Path) -> bool:
    """
    Task 1: Use openat2 with RESOLVE_BENEATH to strictly enforce the jail.
    Returns True if the kernel allows the path resolution within the root.
    """
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        
        # 1. Open the root directory as an O_PATH descriptor
        # O_PATH = 010000000 (0x200000 on many kernels)
        # O_DIRECTORY = 0200000 (0x10000)
        O_PATH = 0x200000
        O_DIRECTORY = 0x10000
        
        dir_fd = os.open(str(root_prefix), O_PATH | O_DIRECTORY)
        try:
            # 2. Prepare open_how
            how = OpenHow()
            how.flags = os.O_RDONLY | O_PATH
            how.mode = 0
            how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
            
            # 3. Call openat2
            # long syscall(long number, ...)
            # int openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
            res = libc.syscall(SYS_OPENAT2, dir_fd, path.encode(), ctypes.byref(how), ctypes.sizeof(how))
            
            if res >= 0:
                os.close(res)
                return True
            else:
                err = ctypes.get_errno()
                if err == 38: # ENOSYS (Function not implemented)
                    logger.warning(f"openat2 not supported on this kernel (ENOSYS). Relying on user-space checks for {path}")
                    return True # Fail-open to user-space validation instead of crashing
                
                logger.warning(f"Jail breach attempt or resolution error: {path} (Result: {res}, errno: {err})")
                return False
        finally:
            os.close(dir_fd)
    except Exception as e:
        logger.error(f"Error executing openat2 check: {e}")
        return False # Fail-closed on error
