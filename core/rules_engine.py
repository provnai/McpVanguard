"""
core/rules_engine.py
Layer 1: Static signature-based rule engine.
Loads YAML rule files from rules/ and matches against every MCP tool call.
"""

from __future__ import annotations
import re
import time
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import Optional
import yaml

from core.models import InspectionResult, RuleMatch, RuleAction, RuleSeverity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rule data class
# ---------------------------------------------------------------------------

class Rule:
    """A single loaded rule from a YAML file."""

    def __init__(self, data: dict, source_file: str):
        self.rule_id: str = data["id"]
        self.description: str = data.get("description", "")
        self.severity: str = data.get("severity", RuleSeverity.MEDIUM)
        self.action: str = data.get("action", RuleAction.BLOCK)
        self.message: str = data.get("message", f"Rule {self.rule_id} triggered")
        self.match_fields: list[str] = data.get("match_fields", ["params"])
        self.source_file: str = source_file

        # Compile the regex pattern for speed
        pattern_str = data.get("pattern", "")
        try:
            self.pattern: re.Pattern = re.compile(pattern_str, re.IGNORECASE)
        except re.error as e:
            logger.error(f"Invalid regex in rule {self.rule_id}: {e}")
            self.pattern = re.compile(r"(?!)")  # never matches

    # Shared thread-pool: runs regex matches with a timeout to prevent ReDoS
    _match_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vanguard-re")
    _REGEX_TIMEOUT_SECS = 0.1  # 100ms per pattern — catastrophic backtracking will abort

    def _safe_search(self, value: str) -> bool:
        """Run pattern.search in a thread with a timeout to guard against ReDoS."""
        try:
            future = Rule._match_pool.submit(self.pattern.search, value)
            result = future.result(timeout=Rule._REGEX_TIMEOUT_SECS)
            return result is not None
        except FuturesTimeoutError:
            logger.warning("ReDoS guard triggered for rule %s — aborting match", self.rule_id)
            return False
        except Exception:
            return False

    def check(self, message: dict) -> Optional[RuleMatch]:
        """
        Check if this rule matches any field in the message.
        Returns a RuleMatch if triggered, None otherwise.
        """
        for field_path in self.match_fields:
            value = self._extract_field(message, field_path)
            if value is None:
                continue
            str_value = str(value)
            if self._safe_search(str_value):
                return RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.description,
                    severity=self.severity,
                    action=self.action,
                    matched_field=field_path,
                    matched_value=str_value[:200],  # truncate long values
                    message=self.message,
                )
        return None

    def _extract_field(self, message: dict, field_path: str) -> Optional[str]:
        """
        Extract a value from a nested dict using dot-notation.
        e.g. "params.arguments.path" → message["params"]["arguments"]["path"]
        Special case: "params" returns the whole params dict as a string.
        """
        try:
            parts = field_path.split(".")
            current = message
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None
            return current
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Rules Engine
# ---------------------------------------------------------------------------

class RulesEngine:
    """
    Loads all YAML rules from a directory and checks messages against them.
    Rules are loaded once at startup and cached in memory.
    """

    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = Path(rules_dir)
        self.rules: list[Rule] = []
        self.load_rules()

    def load_rules(self) -> int:
        """Load (or reload) all YAML files from the rules directory."""
        self.rules.clear()
        loaded = 0

        if not self.rules_dir.exists():
            logger.warning(f"Rules directory '{self.rules_dir}' does not exist.")
            return 0

        for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not isinstance(data, list):
                    logger.warning(f"Skipping {yaml_file.name}: expected a list of rules")
                    continue

                for rule_data in data:
                    rule = Rule(rule_data, source_file=yaml_file.name)
                    self.rules.append(rule)
                    loaded += 1

            except Exception as e:
                logger.error(f"Failed to load {yaml_file.name}: {e}")

        # Sort: CRITICAL first, then HIGH, MEDIUM, LOW
        severity_order = {
            RuleSeverity.CRITICAL: 0,
            RuleSeverity.HIGH: 1,
            RuleSeverity.MEDIUM: 2,
            RuleSeverity.LOW: 3,
        }
        self.rules.sort(key=lambda r: severity_order.get(r.severity, 99))

        logger.info(f"Loaded {loaded} rules from {self.rules_dir}")
        return loaded

    def check(self, message: dict) -> InspectionResult:
        """
        Run all rules against a message.
        Returns the first BLOCK match, or accumulates WARNs.
        """
        t_start = time.monotonic()
        matches: list[RuleMatch] = []

        for rule in self.rules:
            match = rule.check(message)
            if match is None:
                continue

            matches.append(match)

            # BLOCK on the first CRITICAL or HIGH BLOCK rule
            if match.action == RuleAction.BLOCK and match.severity in (
                RuleSeverity.CRITICAL, RuleSeverity.HIGH
            ):
                _log_latency(t_start, "Layer 1 BLOCK")
                return InspectionResult.block(
                    reason=match.message,
                    layer=1,
                    rule_matches=matches,
                )

            # BLOCK on any BLOCK rule (MEDIUM/LOW) — but keep checking first
            if match.action == RuleAction.BLOCK:
                _log_latency(t_start, "Layer 1 BLOCK")
                return InspectionResult.block(
                    reason=match.message,
                    layer=1,
                    rule_matches=matches,
                )

        # If we have any WARN matches, return a warn
        if matches:
            _log_latency(t_start, "Layer 1 WARN")
            return InspectionResult.warn(
                reason=matches[0].message,
                layer=1,
                rule_matches=matches,
            )

        _log_latency(t_start, "Layer 1 ALLOW")
        return InspectionResult.allow()

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def get_rule_ids(self) -> list[str]:
        return [r.rule_id for r in self.rules]


def _log_latency(t_start: float, label: str):
    ms = (time.monotonic() - t_start) * 1000
    if ms > 2:
        logger.debug(f"{label} took {ms:.2f}ms")
