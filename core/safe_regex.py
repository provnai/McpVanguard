"""
Regex backend abstraction for McpVanguard.

Prefers Google's maintained RE2 bindings when available, while keeping an
explicit Python `re` fallback for environments that do not have the wheel.
"""

from __future__ import annotations

import importlib
import logging
import os
import re as _python_re
from dataclasses import dataclass
from types import ModuleType
from typing import Any

logger = logging.getLogger("vanguard.safe_regex")

IGNORECASE = _python_re.IGNORECASE
MULTILINE = _python_re.MULTILINE
DOTALL = _python_re.DOTALL

_SUPPORTED_INLINE_FLAGS = (
    (IGNORECASE, "i"),
    (MULTILINE, "m"),
    (DOTALL, "s"),
)
_UNICODE_ESCAPE_PATTERN = _python_re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})")


class RegexCompileError(Exception):
    """Raised when a pattern cannot be compiled by the selected backend."""


@dataclass
class CompiledPattern:
    backend: str
    pattern_text: str
    compiled: Any

    def search(self, value: str):
        return self.compiled.search(value)


def _normalize_backend_mode(value: str | None) -> str:
    raw = (value or "auto").strip().lower()
    if raw in {"auto", "re2", "python"}:
        return raw
    return "auto"


def _load_re2_module() -> ModuleType | None:
    try:
        return importlib.import_module("re2")
    except ImportError:
        return None


_BACKEND_MODE = _normalize_backend_mode(os.getenv("VANGUARD_REGEX_ENGINE"))
_RE2_MODULE = _load_re2_module()
_ACTIVE_BACKEND = "re2" if _BACKEND_MODE != "python" and _RE2_MODULE is not None else "python"


def backend_name() -> str:
    return _ACTIVE_BACKEND


def using_re2() -> bool:
    return _ACTIVE_BACKEND == "re2"


def is_re2_pattern(pattern: CompiledPattern) -> bool:
    return pattern.backend == "re2"


def _apply_inline_flags(pattern: str, flags: int) -> str:
    enabled = "".join(symbol for bit, symbol in _SUPPORTED_INLINE_FLAGS if flags & bit)
    if not enabled:
        return pattern
    return f"(?{enabled}){pattern}"


def _expand_unicode_escapes(pattern: str) -> str:
    def _replace(match: _python_re.Match[str]) -> str:
        codepoint = match.group(1) or match.group(2)
        return chr(int(codepoint, 16))

    return _UNICODE_ESCAPE_PATTERN.sub(_replace, pattern)


def compile(pattern: str, flags: int = 0) -> CompiledPattern:
    if using_re2():
        try:
            compiled = _RE2_MODULE.compile(_expand_unicode_escapes(_apply_inline_flags(pattern, flags)))
            return CompiledPattern(backend="re2", pattern_text=pattern, compiled=compiled)
        except Exception as exc:
            raise RegexCompileError(str(exc)) from exc

    try:
        compiled = _python_re.compile(pattern, flags)
        return CompiledPattern(backend="python", pattern_text=pattern, compiled=compiled)
    except _python_re.error as exc:
        raise RegexCompileError(str(exc)) from exc


def never_match_pattern() -> CompiledPattern:
    # RE2 does not support (?!) negative lookahead, so use a contradiction both
    # engines accept.
    return compile(r"\b\B")
