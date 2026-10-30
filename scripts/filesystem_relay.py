"""Relay to a separate probe owning the unchanged official server process."""
from pathlib import Path
import sys

from filesystem_probe import run_transport


if __name__ == "__main__":
    log, node, entry, *roots = sys.argv[1:]
    probe = Path(__file__).with_name("filesystem_probe.py")
    sys.exit(run_transport(log, [sys.executable, str(probe), log, node, entry, *roots], role="relay"))
