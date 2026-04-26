"""
core/rules_engine.py
Layer 1: Static signature-based rule engine.
Loads YAML rule files from rules/ and matches against every MCP tool call.
"""

from __future__ import annotations
import re as stdlib_re
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import Optional, Any
import os
import yaml

from core.models import InspectionResult, RuleMatch, RuleAction, RuleSeverity, SafeZone
from core.jail import check_path_jail
from core.risk import RiskEngine
from core import safe_regex

logger = logging.getLogger(__name__)
_REPEATED_CHAR_BACKREF = stdlib_re.compile(r"^\(\.\)\\1\{(\d+),\}$")


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
        self.matcher: str = data.get("matcher", "regex")
        self.repeat_threshold: int = int(data.get("repeat_threshold", 200))
        self.pattern: Optional[Any] = None

        if self.matcher == "regex":
            pattern_str = data.get("pattern", "")
            repeated_threshold = self._extract_repeated_character_threshold(pattern_str)
            if repeated_threshold is not None:
                self.matcher = "repeated_char_run"
                self.repeat_threshold = repeated_threshold
                return
            try:
                self.pattern = safe_regex.compile(pattern_str, safe_regex.IGNORECASE)
            except safe_regex.RegexCompileError as e:
                logger.error(f"Invalid regex in rule {self.rule_id}: {e}")
                self.pattern = safe_regex.never_match_pattern()

    # Shared thread-pool: runs regex matches with a timeout to prevent ReDoS
    _match_pool = ThreadPoolExecutor(max_workers=12, thread_name_prefix="vanguard-re")
    _REGEX_TIMEOUT_SECS = 0.1  # 100ms per pattern — catastrophic backtracking will abort

    def _safe_search(self, value: str) -> bool:
        """Run pattern.search in a thread with a timeout to guard against ReDoS."""
        # Mitigation (P2 Audit Finding): Cap input string length to 100KB to prevent 
        # catastrophic backtracking on huge inputs that could exhaust the match pool.
        safe_value = value[:100000]

        if self.pattern is None:
            return False

        if safe_regex.is_re2_pattern(self.pattern):
            try:
                return self.pattern.search(safe_value) is not None
            except Exception as e:
                logger.error(f"Error in RE2 match for rule {self.rule_id}: {e}")
                return True  # FAIL-CLOSED: Block on unexpected errors
        
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
            matched = False
            if self.matcher == "repeated_char_run":
                matched = self._has_repeated_character_run(str_value)
            else:
                matched = self._safe_search(str_value)
            if matched:
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
        e.g. "params.arguments.path" -> message["params"]["arguments"]["path"]
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

    def _has_repeated_character_run(self, value: str) -> bool:
        """Detect N+1 consecutive identical characters without backreferences."""
        if not value:
            return False

        run_length = 1
        previous = value[0]
        for current in value[1:]:
            if current == previous:
                run_length += 1
                if run_length > self.repeat_threshold:
                    return True
            else:
                previous = current
                run_length = 1
        return False

    def _extract_repeated_character_threshold(self, pattern_str: str) -> Optional[int]:
        match = _REPEATED_CHAR_BACKREF.fullmatch(pattern_str)
        if not match:
            return None
        return int(match.group(1))


# ---------------------------------------------------------------------------
# Rules Engine
# ---------------------------------------------------------------------------

class RulesEngine:
    """
    Loads all YAML rules from a directory and checks messages against them.
    Implements a thread-safe Singleton pattern for global hot-reloading.
    """
    _instance: Optional[RulesEngine] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(RulesEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, rules_dir: str = "rules"):
        requested_rules_dir = Path(rules_dir)
        if getattr(self, "_initialized", False):
            if self.rules_dir != requested_rules_dir:
                self.rules_dir = requested_rules_dir
            # Explicit constructor calls should always resync from disk so callers
            # do not inherit mutated singleton state from earlier runtime/test code.
            self.reload()
            return
        
        self.rules_dir = requested_rules_dir
        self.rules: list[Rule] = []
        self.safe_zones: list[SafeZone] = []
        self._rules_lock = threading.Lock()
        
        self.reload()
        self._initialized = True

    @classmethod
    def get_instance(cls) -> RulesEngine:
        if cls._instance is None:
            return cls()
        return cls._instance

    def _sort_rule_list(self, rules: list[Rule]) -> None:
        severity_order = {
            RuleSeverity.CRITICAL: 0,
            RuleSeverity.HIGH: 1,
            RuleSeverity.MEDIUM: 2,
            RuleSeverity.LOW: 3,
        }
        rules.sort(key=lambda r: severity_order.get(r.severity, 99))

    def reload(self) -> int:
        """
        Atomically reload all rules and safe zones from the rules directory.
        This is non-destructive and safe to call during active sessions.
        """
        logger.info(f"Reloading rules from '{self.rules_dir}'...")
        new_rules: list[Rule] = []
        new_safe_zones: list[SafeZone] = []

        # 1. Load Rules into temp list
        if self.rules_dir.exists():
            for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
                try:
                    if yaml_file.name == "safe_zones.yaml":
                        continue
                        
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)

                    if not isinstance(data, list):
                        continue

                    for rule_data in data:
                        if isinstance(rule_data, dict) and "id" in rule_data and ("pattern" in rule_data or "matcher" in rule_data):
                            new_rules.append(Rule(rule_data, source_file=yaml_file.name))
                except Exception as e:
                    logger.error(f"Failed to load rules from {yaml_file.name}: {e}")

        # 2. Load Safe Zones into temp list
        config_file = self.rules_dir / "safe_zones.yaml"
        if config_file.exists():
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if isinstance(data, list):
                    for entry in data:
                        new_safe_zones.append(SafeZone(**entry))
            except Exception as e:
                logger.error(f"Failed to load safe zones: {e}")

        self._sort_rule_list(new_rules)

        # 3. Atomic swap
        with self._rules_lock:
            self.rules = new_rules
            self.safe_zones = new_safe_zones

        logger.info(f"RulesEngine: successfully reloaded {len(self.rules)} rules and {len(self.safe_zones)} safe zones.")
        return len(self.rules)

    def load_rules(self) -> int:
        """Deprecated: Use reload() for thread-safe updates."""
        return self.reload()

    def add_runtime_rules(self, yaml_text: str, source_file: str = "runtime") -> list[str]:
        """
        Parse one or more YAML rule definitions and append them to the active ruleset.
        Returns the inserted rule IDs.
        """
        data = yaml.safe_load(yaml_text)
        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list) or not data:
            raise ValueError("Runtime rule payload must be a YAML rule object or a non-empty list of rules.")

        added_ids: list[str] = []
        with self._rules_lock:
            existing_ids = {rule.rule_id for rule in self.rules}
            for rule_data in data:
                if not isinstance(rule_data, dict):
                    raise ValueError("Each runtime rule must be a YAML mapping.")
                if "allowed_prefixes" in rule_data or rule_data.get("tool"):
                    raise ValueError("Safe Zone definitions are not supported by vanguard_apply_rule.")

                rule = Rule(rule_data, source_file=source_file)
                if rule.rule_id in existing_ids:
                    raise ValueError(f"Rule ID '{rule.rule_id}' already exists.")
                # We need to create a NEW list to keep it atomic if others are iterating
                new_rules = list(self.rules)
                new_rules.append(rule)
                self._sort_rule_list(new_rules)
                self.rules = new_rules
                existing_ids.add(rule.rule_id)
                added_ids.append(rule.rule_id)

        return added_ids

    def load_safe_zones(self) -> int:
        """Deprecated: Use reload() for thread-safe updates."""
        self.reload()
        return len(self.safe_zones)

    def _check_safe_zones(self, message: dict) -> Optional[InspectionResult]:
        """Legacy wrapper for backward compatibility."""
        with self._rules_lock:
            return self._check_safe_zones_list(message, self.safe_zones)

    def _check_safe_zones_list(self, message: dict, zones: list[SafeZone]) -> Optional[InspectionResult]:
        """
        Verify tool arguments against defined Safe Zones (Jails).
        Returns a BLOCK InspectionResult if a breach is detected.
        """
        # Identify tool calls regardless of strictly formatted "tools/call" method
        params = message.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        tool_name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            args = {}

        # Fallback for non-standard formats (e.g. from custom clients)
        if not tool_name:
            tool_name = message.get("name")
        if not args:
            args = message.get("arguments") or {}
            if not isinstance(args, dict):
                args = {}

        # If it doesn't look like a tool call at all, skip safe zones
        if not tool_name or not isinstance(args, dict):
            return None

        # Find any safe zones for this tool
        relevant_zones = [z for z in zones if z.tool == tool_name]
        if not relevant_zones:
            return None

        # Check for path-like arguments
        path_keys = ["path", "filepath", "directory", "dir", "destination", "source"]
        
        for key in path_keys:
            if key in args:
                requested_path = str(args[key])
                allowed = False
                
                for zone in relevant_zones:
                    if check_path_jail(requested_path, zone.allowed_prefixes, recursive=zone.recursive):
                        # Entropy check if restricted
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
        with self._rules_lock:
            safe_zones = self.safe_zones
            rules = self.rules

        jail_result = self._check_safe_zones_list(message, safe_zones)
        if jail_result:
            _log_latency(t_start, "Layer 1 SAFE-ZONE BLOCK")
            return jail_result

        # 2. Legacy Regex Rules
        for rule in rules:
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

        # 3. Default Policy Check
        default_policy = os.getenv("VANGUARD_DEFAULT_POLICY", "ALLOW").upper()
        if default_policy == "DENY":
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
        with self._rules_lock:
            return len(self.rules)

    def get_rule_ids(self) -> list[str]:
        with self._rules_lock:
            return [r.rule_id for r in self.rules]


def _log_latency(t_start: float, label: str):
    ms = (time.monotonic() - t_start) * 1000
    if ms > 2:
        logger.debug(f"{label} took {ms:.2f}ms")
