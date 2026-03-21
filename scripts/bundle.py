import os
import zipfile
import shutil
from pathlib import Path

def bundle_mcpb():
    project_root = Path(__file__).parent.parent.absolute()
    bundle_name = "mcp-vanguard.mcpb"
    bundle_path = project_root / bundle_name
    
    print(f"Creating MCP Bundle: {bundle_name}...")
    
    # Files/Dirs to include
    include_patterns = [
        "core",
        "rules",
        "assets",
        "docs",
        "README.md",
        "CHANGELOG.md",
        "TESTING_GUIDE.md",
        "LICENSE",
        "PRIVACY.md",
        "manifest.json",
        "package.json",
        "index.js",
        "requirements.txt",
        "pyproject.toml",
    ]
    
    # Exclude patterns
    exclude_dirs = [".git", ".venv", ".pytest_cache", "__pycache__", "dist", "build"]
    exclude_files = [".env", "audit.log"]

    with zipfile.ZipFile(bundle_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # 1. Add explicitly included patterns
        for pattern in include_patterns:
            path = project_root / pattern
            if not path.exists():
                print(f"  Warning: {pattern} not found, skipping.")
                continue
                
            if path.is_file():
                zipf.write(path, arcname=pattern)
            else:
                for root, dirs, files in os.walk(path):
                    # Filter out excluded directories
                    dirs[:] = [d for d in dirs if d not in exclude_dirs and d != "__pycache__"]
                    
                    for file in files:
                        if file in exclude_files or file.endswith(('.pyc', '.pyo')):
                            continue
                        
                        file_path = Path(root) / file
                        rel_path = file_path.relative_to(project_root)
                        zipf.write(file_path, arcname=rel_path)
    
    size_kb = bundle_path.stat().st_size / 1024
    print(f"Success! Bundle created at {bundle_path} ({size_kb:.2f} KB)")

if __name__ == "__main__":
    bundle_mcpb()
