import importlib
import importlib.util
import sys
import types

import pytest

from core import safe_regex


def test_safe_regex_forced_python_backend(monkeypatch):
    monkeypatch.setenv("VANGUARD_REGEX_ENGINE", "python")
    module = importlib.reload(safe_regex)
    try:
        assert module.backend_name() == "python"
    finally:
        monkeypatch.delenv("VANGUARD_REGEX_ENGINE", raising=False)
        importlib.reload(safe_regex)


def test_safe_regex_can_bind_fake_re2_backend(monkeypatch):
    fake_module = types.ModuleType("re2")

    class FakeCompiled:
        def __init__(self, pattern_text):
            self.pattern_text = pattern_text

        def search(self, value):
            return "needle" if "needle" in value else None

    fake_module.compile = lambda pattern: FakeCompiled(pattern)

    monkeypatch.setenv("VANGUARD_REGEX_ENGINE", "auto")
    monkeypatch.setitem(sys.modules, "re2", fake_module)
    module = importlib.reload(safe_regex)
    try:
        compiled = module.compile("needle", module.IGNORECASE)
        assert compiled.backend == "re2"
        assert compiled.pattern_text == "needle"
        assert compiled.search("hay needle stack") == "needle"
    finally:
        monkeypatch.delenv("VANGUARD_REGEX_ENGINE", raising=False)
        sys.modules.pop("re2", None)
        importlib.reload(safe_regex)


@pytest.mark.skipif(importlib.util.find_spec("re2") is None, reason="google-re2 not installed in test environment")
def test_safe_regex_uses_real_re2_backend_when_available(monkeypatch):
    monkeypatch.delenv("VANGUARD_REGEX_ENGINE", raising=False)
    module = importlib.reload(safe_regex)
    try:
        assert module.backend_name() == "re2"
        compiled = module.compile(r"\d+")
        assert compiled.backend == "re2"
        assert compiled.search("value 42")
    finally:
        importlib.reload(safe_regex)
