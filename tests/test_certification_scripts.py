from pathlib import Path

import pytest


CERTIFICATION_SCRIPTS = (
    Path(__file__).parent / "benchmarks" / "railway_certification.py",
    Path(__file__).parent / "benchmarks" / "railway_cloud_certification.py",
)


@pytest.mark.parametrize("script_path", CERTIFICATION_SCRIPTS, ids=lambda path: path.stem)
def test_certification_scripts_compile_on_supported_python(script_path: Path):
    source = script_path.read_text(encoding="utf-8")
    compile(source, str(script_path), "exec")
