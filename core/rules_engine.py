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
import os
import yaml

from core.models import InspectionResult, RuleMatch, RuleAction, RuleSeverity, SafeZone
from core.jail import check_path_jail

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
    _match_pool = ThreadPoolExecutor(max_workers=12, thread_name_prefix="vanguard-re")
    _REGEX_TIMEOUT_SECS = 0.1  # 100ms per pattern — catastrophic backtracking will abort

    def _safe_search(self, value: str) -> bool:
        """Run pattern.search in a thread with a timeout to guard against ReDoS."""
        # Mitigation (P2 Audit Finding): Cap input string length to 100KB to prevent 
        # catastrophic backtracking on huge inputs that could exhaust the match pool.
        safe_value = value[:100000]
        
        try:
            future = Rule._match_pool.submit(self.pattern.search, safe_value)
            result = future.result(timeout=Rule._REGEX_TIMEOUT_SECS)
            return result is not None
        except FuturesTimeoutError:
            logger.warning("ReDoS guard triggered for rule %s — aborting match (FAIL-CLOSED)", self.rule_id)
            return True  # FAIL-CLOSED: Block on timeout
        except Exception as e:
            logger.error(f"Error in regex match for rule {self.rule_id}: {e}")
            return True  # FAIL-CLOSED: Block on unexpected errors

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
        self.safe_zones: list[SafeZone] = []
        self.load_rules()
        self.load_safe_zones()

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

                if yaml_file.name == "safe_zones.yaml":
                    continue

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

    def load_safe_zones(self) -> int:
        """Load safe zones configuration from safe_zones.yaml."""
        self.safe_zones.clear()
        config_file = self.rules_dir / "safe_zones.yaml"
        
        if not config_file.exists():
            logger.info("No safe_zones.yaml found — skipping Safe Zone enforcement.")
            return 0

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            if not isinstance(data, list):
                logger.warning(f"Invalid format in {config_file.name}: expected a list")
                return 0

            for entry in data:
                self.safe_zones.append(SafeZone(**entry))
            
            logger.info(f"Loaded {len(self.safe_zones)} Safe Zones from {config_file.name}")
            return len(self.safe_zones)
        except Exception as e:
            logger.error(f"Failed to load {config_file.name}: {e}")
            return 0

    def _check_safe_zones(self, message: dict) -> Optional[InspectionResult]:
        """
        Verify tool arguments against defined Safe Zones (Jails).
        Returns a BLOCK InspectionResult if a breach is detected.
        """
        # Identify tool calls regardless of strictly formatted "tools/call" method
        # CRIT-1 Fix: Support both standard and fallback tool call formats
        params = message.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        # Fallback for non-standard formats (e.g. from custom clients)
        if not tool_name:
            tool_name = message.get("name")
        if not args:
            args = message.get("arguments", {})

        # If it doesn't look like a tool call at all, skip safe zones
        if not tool_name or not isinstance(args, dict):
            return None

        # Find any safe zones for this tool
        relevant_zones = [z for z in self.safe_zones if z.tool == tool_name]
        if not relevant_zones:
            return None

        # Check for path-like arguments
        # We look for common path keys like 'path', 'filepath', 'dir', etc.
        path_keys = ["path", "filepath", "directory", "dir", "destination", "source"]
        
        for key in path_keys:
            if key in args:
                requested_path = str(args[key])
                allowed = False
                
                for zone in relevant_zones:
                    if check_path_jail(requested_path, zone.allowed_prefixes, recursive=zone.recursive):
                        # Task 2: Check entropy if restricted (P2 Audit Finding)
                        if zone.max_entropy:
                            content = args.get("content") or args.get("data")
                            if content:
                                from core.behavioral import compute_shannon_entropy
                                h = compute_shannon_entropy(str(content).encode())
                                if h > zone.max_entropy:
                                    logger.warning(f"ENTROPY BREACH: {tool_name} content entropy {h} > limit {zone.max_entropy}")
                                    return InspectionResult.block(
                                        reason=f"Policy Block: High-entropy content ({h:.2f}) exceeds Safe Zone limit ({zone.max_entropy}) for path '{requested_path}'.",
                                        layer=1,
                                    )
                        
                        allowed = True
                        break
                
                if not allowed:
                    logger.warning(f"SAFE ZONE BREACH: Tool '{tool_name}' attempted to access '{requested_path}' outside of allowed zones.")
                    return InspectionResult.block(
                        reason=f"Access denied: Path '{requested_path}' is outside the authorized Safe Zone for tool '{tool_name}'.",
                        layer=1,
                        rule_matches=[RuleMatch(
                            rule_id="VANGUARD-SAFEZONE-001",
                            rule_name="Safe Zone Violation",
                            severity=RuleSeverity.CRITICAL,
                            action=RuleAction.BLOCK,
                            message=f"Deterministic jail failure for {tool_name}"
                        )]
                    )
        
        return None

    def check(self, message: dict) -> InspectionResult:
        """
        Run all rules against a message.
        Returns the first BLOCK match, or accumulates WARNs.
        """
        t_start = time.monotonic()
        matches: list[RuleMatch] = []

        # 1. Deterministic Safe Zone Check (Fastest & Most Critical)
        jail_result = self._check_safe_zones(message)
        if jail_result:
            _log_latency(t_start, "Layer 1 SAFE-ZONE BLOCK")
            return jail_result

        # 2. Legacy Regex Rules
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

        # CRIT-2 Fix: Support VANGUARD_DEFAULT_POLICY=DENY
        default_policy = os.getenv("VANGUARD_DEFAULT_POLICY", "ALLOW").upper()
        if default_policy == "DENY":
            # Only deny if it actually looks like a tool call or restricted method
            method = message.get("method")
            if method in ("tools/call", "tools/list", "resources/read", "resources/list") or message.get("name"):
                logger.warning(f"DEFAULT-DENY: Blocking unmatched request for {method or message.get('name')}")
                return InspectionResult.block(
                    reason="Security Policy: Access denied by default (unrecognized or unauthorized tool/method).",
                    layer=1,
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
