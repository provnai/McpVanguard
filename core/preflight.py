"""
core/preflight.py
Layer 0 Preflight normalization and anomaly detection.

This module normalizes incoming JSON-RPC messages to prevent encoding-based
bypasses (e.g., URL encoding, Unicode homoglyphs, invisible characters).
It also emits structured findings for any suspicious transformations or
trust-signal camouflage attempts.
"""

import math
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PreflightFinding:
    rule_id: str
    severity: str
    action: str
    field_path: str
    message: str
    evidence: str


@dataclass(frozen=True)
class PreflightResult:
    normalized_message: dict
    findings: list[PreflightFinding]


# ---------------------------------------------------------------------------
# Detectors & Regexes
# ---------------------------------------------------------------------------

# PRE-COMMENT-001: suspicious shell/comment trust suffix detected
_COMMENT_TRUST_REGEX = re.compile(
    r"(?i)(?:#|--|//|/\*)\s*(?:safe|harmless|approved|maintenance|test|pen-test|authorized|admin\s+approved)"
)

# PRE-INSTRUCT-001: scorer-targeting instruction detected in tool-call arguments
_SCORER_INSTRUCT_REGEX = re.compile(
    r"(?i)(?:rate\s+as\s+safe|score\s+this\s+as\s+1|business\s+says\s+1|you\s+are\s+model\s+[A-Za-z]|disregard\s+all\s+instructions)"
)

# Other trust labels (not necessarily in a comment) for PRE-TRUST-001
_TRUST_LABEL_REGEX = re.compile(
    r"(?i)(?:authorized\s+auditor|security\s+researcher|admin\s+verified|approved\s+by\s+admin)"
)

# Risky operations keywords (used if the tool isn't explicitly destructive, but arguments are risky)
_RISKY_OP_REGEX = re.compile(
    r"(?i)\b(?:rm\s+-|exec\s|bash\s|sh\s|systemctl\s|chmod\s|chown\s|curl\s|wget\s|powershell\s|cmd\.exe|sudo\s)\b"
)


def _is_mixed_script(s: str) -> bool:
    """Check if a string mixes Latin and Cyrillic/Greek characters (homoglyph attack)."""
    has_latin = False
    has_cyrillic_greek = False
    for ch in s:
        cp = ord(ch)
        if (0x41 <= cp <= 0x5a) or (0x61 <= cp <= 0x7a) or (0x00c0 <= cp <= 0x00ff) or (0x0100 <= cp <= 0x017f):
            has_latin = True
        elif (0x0400 <= cp <= 0x04ff) or (0x0500 <= cp <= 0x052f) or (0x0370 <= cp <= 0x03ff):
            has_cyrillic_greek = True
        if has_latin and has_cyrillic_greek:
            return True
    return False


def run_preflight(
    message: Any,
    max_string_len: int = 65536,
    is_destructive_tool_fn=None,
) -> PreflightResult:
    """
    Run Layer 0 preflight normalization and detection on the raw message.

    Returns a PreflightResult containing the normalized message and a list
    of findings. Raises ValueError for hard-fail blocks (oversize, deep nesting, NaN).
    """
    findings: list[PreflightFinding] = []

    # Determine if this tool call is a risky operation (helps with PRE-TRUST-001)
    is_risky_op = False
    if isinstance(message, dict) and message.get("method") == "tools/call":
        tool_name = message.get("params", {}).get("name", "")
        if is_destructive_tool_fn and is_destructive_tool_fn(tool_name):
            is_risky_op = True

    def _normalize(value: Any, path: str, depth: int) -> Any:
        nonlocal is_risky_op
        if depth > 50:
            raise ValueError("Message nesting depth exceeds limit (50 levels). Possible DoS payload.")

        if isinstance(value, dict):
            return {k: _normalize(v, f"{path}.{k}" if path else k, depth + 1) for k, v in value.items()}
        elif isinstance(value, list):
            return [_normalize(v, f"{path}[{i}]", depth + 1) for i, v in enumerate(value)]
        elif isinstance(value, str):
            original_value = value

            # Length safeguard (PRE-SIZE-001)
            if len(value) > max_string_len:
                raise ValueError(f"String length {len(value)} exceeds limit {max_string_len}")

            # 1. URL decoding loop
            passes = 0
            while passes < 20:
                decoded = urllib.parse.unquote(value)
                decoded = decoded.replace("%5c", "\\").replace("%5C", "\\")
                if decoded == value:
                    break
                value = decoded
                passes += 1
            if passes > 1:
                findings.append(PreflightFinding(
                    rule_id="PRE-URL-001",
                    severity="MEDIUM",
                    action="WARN",
                    field_path=path,
                    message="Multi-pass URL decoding occurred (possible evasion attempt).",
                    evidence=f"Decoded {passes} times",
                ))

            # 2. Unicode NFKC
            nfkc_value = unicodedata.normalize("NFKC", value)
            if nfkc_value != value:
                findings.append(PreflightFinding(
                    rule_id="PRE-UNICODE-001",
                    severity="LOW",
                    action="WARN",
                    field_path=path,
                    message="NFKC normalization changed the string value.",
                    evidence="String contained non-standard Unicode forms",
                ))
            value = nfkc_value

            # 3. Strip zero-width / invisible characters
            stripped_value = ''.join(ch for ch in value if unicodedata.category(ch) not in ('Cf',))
            if stripped_value != value:
                findings.append(PreflightFinding(
                    rule_id="PRE-UNICODE-002",
                    severity="MEDIUM",
                    action="WARN",
                    field_path=path,
                    message="Zero-width or format characters were present and stripped.",
                    evidence="String contained invisible format characters",
                ))
            value = stripped_value

            # 4. Mixed-script / confusable characters
            if _is_mixed_script(value):
                findings.append(PreflightFinding(
                    rule_id="PRE-UNICODE-003",
                    severity="HIGH",
                    action="WARN",
                    field_path=path,
                    message="Mixed-script/confusable characters detected (possible homoglyph attack).",
                    evidence="String mixes Latin and Cyrillic/Greek characters",
                ))

            # 5. Comment trust suffix
            if _COMMENT_TRUST_REGEX.search(value):
                findings.append(PreflightFinding(
                    rule_id="PRE-COMMENT-001",
                    severity="MEDIUM",
                    action="WARN",
                    field_path=path,
                    message="Suspicious shell/comment trust suffix detected.",
                    evidence="Trust-label comment found in payload",
                ))
                if is_risky_op:
                    findings.append(PreflightFinding(
                        rule_id="PRE-TRUST-001",
                        severity="HIGH",
                        action="BLOCK",  # Let profile composer decide, but annotate as block-worthy
                        field_path=path,
                        message="Trust label detected near risky operation.",
                        evidence="Comment trust label paired with destructive tool or risky command",
                    ))

            # 6. Authority laundering without comment
            elif _TRUST_LABEL_REGEX.search(value) and is_risky_op:
                findings.append(PreflightFinding(
                    rule_id="PRE-TRUST-001",
                    severity="HIGH",
                    action="BLOCK",
                    field_path=path,
                    message="Trust label detected near risky operation.",
                    evidence="Authority laundering label paired with destructive tool or risky command",
                ))

            # 7. Scorer-targeting instruction
            if _SCORER_INSTRUCT_REGEX.search(value):
                findings.append(PreflightFinding(
                    rule_id="PRE-INSTRUCT-001",
                    severity="HIGH",
                    action="WARN",
                    field_path=path,
                    message="Scorer-targeting instruction detected in tool-call arguments.",
                    evidence="Semantic camouflage attempting to manipulate scoring layer",
                ))

            return value

        elif isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                raise ValueError("NaN/Infinity values are not permitted in McpVanguard messages.")
        return value

    normalized = _normalize(message, "", 0)
    return PreflightResult(normalized_message=normalized, findings=findings)
