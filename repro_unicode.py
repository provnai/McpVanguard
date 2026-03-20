import os
import unicodedata
import logging
import sys
from pathlib import Path
from core import jail

# Configure logging to see jail debug output
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

def repro():
    safe_prefix = "C:/Users/test"
    # Test both Division Slash (U+2215) and Fullwidth Solidus (U+FF0F)
    # The latter IS normalized by NFKC, the former IS NOT.
    div_slash = "C:/Users/test/..／..／etc/passwd" # U+FF0F example
    
    norm = unicodedata.normalize("NFKC", div_slash)
    with open("repro_debug.txt", "w", encoding="utf-8") as f:
        f.write(f"Normalized: {norm}\n")
        
        # Path.resolve() usually converts normalized slashes
        res = Path(norm).resolve()
        f.write(f"Resolved:   {res}\n")
        
        # Redirect stdout to capture jail logs
        old_stdout = sys.stdout
        sys.stdout = f
        try:
            is_safe = jail.check_path_jail(div_slash, [safe_prefix])
        finally:
            sys.stdout = old_stdout
            
        f.write(f"Is Safe:    {is_safe}\n")
        
        if is_safe:
            f.write("FAILED: Path bypass detected!\n")
        else:
            f.write("SUCCESS: Path correctly blocked.\n")

if __name__ == "__main__":
    repro()
