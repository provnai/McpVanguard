"""
core/camouflage.py
Layer 1.5: Trust-Signal and Semantic Camouflage Detector

Identifies cases where attacker-controlled text attempts to attach benign
authority to a risky operation, or manipulate downstream semantic scorers.
"""

import re
from dataclasses import dataclass
from typing import Any

from core.models import RuleSeverity, RuleAction

@dataclass(frozen=True)
class CamouflageFinding:
    rule_id: str
    category: str
    severity: str
    action: str
    message: str
    evidence: str


# ---------------------------------------------------------------------------
# Trust and instruction regexes used by the camouflage detector.
# ---------------------------------------------------------------------------

# Shell, Config, Python (#), C-style (//, /*), SQL (--), HTML (<!--)
_COMMENT_TRUST_REGEX = re.compile(
    r"(?i)(?:#|--|//|/\*|<!--)\s*(?:safe|harmless|approved|maintenance|test|pen-test|authorized|admin\s+approved|ignore\s+security)"
)

# Multilingual and extensible trust labels.
_MULTILINGUAL_TRUST_REGEX = re.compile(
    r"(?i)(?:#|--|//|/\*|<!--)\s*(?:s\u00e9curis\u00e9|seguro|sicher|\u5b89\u5168|\u0431\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u043e)"
)

# Scorer manipulation
_SCORER_INSTRUCT_REGEX = re.compile(
    r"(?i)(?:rate\s+as\s+safe|score\s+this\s+as\s+1|business\s+says\s+1|you\s+are\s+model\s+[A-Za-z]|disregard\s+all\s+instructions)"
)

# Authority laundering without explicitly using a comment
_AUTHORITY_LAUNDERING_REGEX = re.compile(
    r"(?i)(?:authorized\s+auditor|security\s+researcher|admin\s+verified|approved\s+by\s+admin)"
)


def detect_camouflage(
    normalized_message: Any,
    is_destructive: bool = False
) -> list[CamouflageFinding]:
    """
    Scan normalized JSON-RPC payload for semantic camouflage.
    Returns a list of CamouflageFinding objects.
    """
    findings: list[CamouflageFinding] = []

    def _scan(value: Any):
        if isinstance(value, dict):
            for v in value.values():
                _scan(v)
        elif isinstance(value, list):
            for v in value:
                _scan(v)
        elif isinstance(value, str):
            # 1. Comment trust suffix
            if _COMMENT_TRUST_REGEX.search(value) or _MULTILINGUAL_TRUST_REGEX.search(value):
                # Only escalate to BLOCK if the tool is destructive
                severity = RuleSeverity.HIGH if is_destructive else RuleSeverity.MEDIUM
                action = RuleAction.BLOCK if is_destructive else RuleAction.WARN
                findings.append(CamouflageFinding(
                    rule_id="CAMO-COMMENT-001",
                    category="comment_trust",
                    severity=severity,
                    action=action,
                    message="Trust-signal camouflage detected.",
                    evidence="Trust-label comment found in payload"
                ))
            
            # 2. Authority laundering
            elif _AUTHORITY_LAUNDERING_REGEX.search(value) and is_destructive:
                findings.append(CamouflageFinding(
                    rule_id="CAMO-TRUST-001",
                    category="authority_laundering",
                    severity=RuleSeverity.HIGH,
                    action=RuleAction.BLOCK,
                    message="Authority laundering detected near risky operation.",
                    evidence="Authority laundering label paired with destructive tool"
                ))

            # 3. Scorer-targeting instructions
            if _SCORER_INSTRUCT_REGEX.search(value):
                findings.append(CamouflageFinding(
                    rule_id="CAMO-INSTRUCT-001",
                    category="scorer_manipulation",
                    severity=RuleSeverity.HIGH,
                    action=RuleAction.WARN, # Typically WARN because L2 needs to know, but we don't hard block just for saying 'rate as safe' unless strict
                    message="Scorer-targeting instruction detected.",
                    evidence="Semantic camouflage attempting to manipulate scoring layer"
                ))

    _scan(normalized_message)
    
    # Deduplicate findings by rule_id
    unique_findings = []
    seen = set()
    for f in findings:
        if f.rule_id not in seen:
            unique_findings.append(f)
            seen.add(f.rule_id)
            
    return unique_findings
