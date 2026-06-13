"""
core/benchmarks.py
Shared MCP-38 benchmark loading and execution helpers.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from core import behavioral
from core.models import AuthPrincipal, InspectionResult
from core.metadata_inspection import inspect_initialize_payload, inspect_tool_list_payload
from core.proxy import ProxyConfig, VanguardProxy
from core.rules_engine import RulesEngine

KNOWN_HARNESSES = {
    "rules_engine",
    "metadata_initialize",
    "metadata_tool_list",
    "behavioral_request_sequence",
    "behavioral_response",
    "proxy_auth_policy",
    "behavioral_cross_server_sequence",
    "semantic_threshold",
}

ACTION_ORDER = ("ALLOW", "WARN", "BLOCK")


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    public_case_id: str
    source_corpus: str
    mcp38_id: str
    title: str
    harness: str
    expected_action: str
    input: dict[str, Any]
    expected_rule_id: str | None = None


@dataclass(frozen=True)
class BenchmarkEvaluation:
    case_id: str
    mcp38_id: str
    title: str
    expected_action: str
    actual_action: str
    passed: bool
    expected_rule_id: str | None = None
    actual_rule_id: str | None = None
    actual_layer: int | None = None
    actual_rule_family: str | None = None
    actual_capabilities: list[str] | None = None
    latency_ms: float | None = None
    details: str | None = None
    public_case_id: str | None = None
    source_corpus: str | None = None


def _rule_family(rule_id: str | None) -> str | None:
    """Coarse rule family used for benchmark breakdowns and false-positive triage."""
    if not rule_id:
        return None
    if rule_id.startswith("VANGUARD-SAFEZONE"):
        return "safe_zone"
    if rule_id.startswith("SEM"):
        return "semantic"
    if rule_id.startswith("BEH"):
        return "behavioral"
    if rule_id.startswith("CAMO"):
        return "camouflage"
    if rule_id.startswith("AUTH"):
        return "auth"
    if rule_id.startswith("VANGUARD-"):
        return "preflight"
    return rule_id.split("-", 1)[0].lower()


def _read_case_corpus(path: str | Path) -> str:
    candidate = Path(path)
    if candidate.exists():
        return candidate.read_text(encoding="utf-8")

    if candidate.parent.as_posix().replace("\\", "/") == "tests/benchmarks":
        resource_name = candidate.name
        return resources.files("core.benchmark_cases").joinpath(resource_name).read_text(encoding="utf-8")

    raise FileNotFoundError(f"Benchmark corpus not found: {path}")


def _public_corpus_name(path: str | Path) -> str:
    """Return a stable, non-sensitive corpus identifier for public reports."""
    return Path(path).stem.replace(" ", "_").lower()


def _public_case_id(path: str | Path, case_id: str) -> str:
    """Return a deterministic public-safe case ID scoped to its corpus."""
    safe_case_id = case_id.strip().replace(" ", "_")
    return f"mcpv:{_public_corpus_name(path)}:{safe_case_id}"


def load_cases(path: str | Path = "tests/benchmarks/mcp38_cases.yaml") -> list[BenchmarkCase]:
    payload = yaml.safe_load(_read_case_corpus(path))
    if not isinstance(payload, list):
        raise ValueError("Benchmark corpus must be a list of cases.")

    cases: list[BenchmarkCase] = []
    seen_ids: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("Each benchmark case must be a mapping.")

        case_id = str(item.get("case_id", "")).strip()
        if not case_id:
            raise ValueError("Benchmark case is missing case_id.")
        if case_id in seen_ids:
            raise ValueError(f"Duplicate benchmark case_id: {case_id}")

        harness = str(item.get("harness", "")).strip()
        if harness not in KNOWN_HARNESSES:
            raise ValueError(f"Unsupported benchmark harness: {harness}")

        expected_action = str(item.get("expected_action", "")).strip().upper()
        if expected_action not in {"ALLOW", "WARN", "BLOCK"}:
            raise ValueError(f"Unsupported expected_action for {case_id}: {expected_action}")

        input_payload = item.get("input")
        if not isinstance(input_payload, dict):
            raise ValueError(f"Benchmark case {case_id} input must be a mapping.")

        seen_ids.add(case_id)
        cases.append(
            BenchmarkCase(
                case_id=case_id,
                public_case_id=_public_case_id(path, case_id),
                source_corpus=_public_corpus_name(path),
                mcp38_id=str(item.get("mcp38_id", "")).strip().upper(),
                title=str(item.get("title", "")).strip(),
                harness=harness,
                expected_action=expected_action,
                input=input_payload,
                expected_rule_id=str(item["expected_rule_id"]).strip().upper() if item.get("expected_rule_id") else None,
            )
        )

    return cases


def run_case(case: BenchmarkCase):
    if case.harness == "rules_engine":
        engine = RulesEngine(rules_dir="rules")
        engine.safe_zones = []
        return engine.check(case.input)
    if case.harness == "metadata_initialize":
        return inspect_initialize_payload(case.input)
    if case.harness == "metadata_tool_list":
        return inspect_tool_list_payload(case.input)
    if case.harness == "behavioral_request_sequence":
        return asyncio.run(_run_behavioral_request_sequence(case))
    if case.harness == "behavioral_response":
        return asyncio.run(_run_behavioral_response(case))
    if case.harness == "proxy_auth_policy":
        return asyncio.run(_run_proxy_auth_policy(case))
    if case.harness == "behavioral_cross_server_sequence":
        return asyncio.run(_run_behavioral_cross_server_sequence(case))
    if case.harness == "semantic_threshold":
        return _run_semantic_threshold(case)

    raise AssertionError(f"Unsupported benchmark harness: {case.harness}")


def summarize_cases(cases: list[BenchmarkCase]) -> dict[str, int]:
    summary = {"ALLOW": 0, "WARN": 0, "BLOCK": 0, "total": len(cases)}
    for case in cases:
        summary[case.expected_action] += 1
    return summary


def evaluate_case(case: BenchmarkCase) -> BenchmarkEvaluation:
    t_start = time.perf_counter()
    result = run_case(case)
    latency_ms = (time.perf_counter() - t_start) * 1000
    actual_action = "ALLOW" if result is None else result.action
    actual_rule_id = None
    actual_layer = None
    if result is not None and result.rule_matches:
        actual_rule_id = result.rule_matches[0].rule_id
    if result is not None:
        actual_layer = result.layer_triggered

    passed = actual_action == case.expected_action
    details = None
    if not passed:
        details = f"expected action {case.expected_action}, got {actual_action}"
    elif case.expected_rule_id:
        passed = actual_rule_id == case.expected_rule_id
        if not passed:
            details = f"expected rule {case.expected_rule_id}, got {actual_rule_id or 'none'}"

    return BenchmarkEvaluation(
        case_id=case.case_id,
        public_case_id=case.public_case_id,
        source_corpus=case.source_corpus,
        mcp38_id=case.mcp38_id,
        title=case.title,
        expected_action=case.expected_action,
        actual_action=actual_action,
        passed=passed,
        expected_rule_id=case.expected_rule_id,
        actual_rule_id=actual_rule_id,
        actual_layer=actual_layer,
        actual_rule_family=_rule_family(actual_rule_id),
        actual_capabilities=result.tool_capabilities if result is not None else None,
        latency_ms=round(latency_ms, 3),
        details=details,
    )


def evaluate_cases(cases: list[BenchmarkCase]) -> list[BenchmarkEvaluation]:
    return [evaluate_case(case) for case in cases]


def _evaluation_from_action(
    case: BenchmarkCase,
    *,
    actual_action: str,
    actual_rule_id: str | None = None,
    actual_layer: int | None = None,
    actual_rule_family: str | None = None,
    latency_ms: float | None = None,
    details_prefix: str | None = None,
) -> BenchmarkEvaluation:
    passed = actual_action == case.expected_action
    details = None
    if not passed:
        prefix = f"{details_prefix}: " if details_prefix else ""
        details = f"{prefix}expected action {case.expected_action}, got {actual_action}"
    elif case.expected_rule_id:
        passed = actual_rule_id == case.expected_rule_id
        if not passed:
            prefix = f"{details_prefix}: " if details_prefix else ""
            details = f"{prefix}expected rule {case.expected_rule_id}, got {actual_rule_id or 'none'}"

    return BenchmarkEvaluation(
        case_id=case.case_id,
        public_case_id=case.public_case_id,
        source_corpus=case.source_corpus,
        mcp38_id=case.mcp38_id,
        title=case.title,
        expected_action=case.expected_action,
        actual_action=actual_action,
        passed=passed,
        expected_rule_id=case.expected_rule_id,
        actual_rule_id=actual_rule_id,
        actual_layer=actual_layer,
        actual_rule_family=actual_rule_family,
        latency_ms=latency_ms,
        details=details,
    )


def _evaluate_no_gateway_baseline(cases: list[BenchmarkCase]) -> list[BenchmarkEvaluation]:
    """Synthetic baseline: no gateway means every proposed request reaches upstream."""
    return [
        _evaluation_from_action(
            case,
            actual_action="ALLOW",
            latency_ms=0.0,
            details_prefix="no_gateway",
        )
        for case in cases
    ]


def _evaluate_l1_only_baseline(cases: list[BenchmarkCase]) -> list[BenchmarkEvaluation]:
    """Run only deterministic RulesEngine checks against each case input."""
    evaluations: list[BenchmarkEvaluation] = []
    engine = RulesEngine(rules_dir="rules")
    engine.safe_zones = []
    for case in cases:
        t_start = time.perf_counter()
        result = engine.check(case.input)
        latency_ms = (time.perf_counter() - t_start) * 1000
        actual_action = "ALLOW" if result is None else result.action
        actual_rule_id = result.rule_matches[0].rule_id if result is not None and result.rule_matches else None
        evaluations.append(
            _evaluation_from_action(
                case,
                actual_action=actual_action,
                actual_rule_id=actual_rule_id,
                actual_layer=result.layer_triggered if result is not None else None,
                actual_rule_family=_rule_family(actual_rule_id),
                latency_ms=round(latency_ms, 3),
                details_prefix="l1_only",
            )
        )
    return evaluations


def _evaluate_l2_threshold_only_baseline(cases: list[BenchmarkCase]) -> list[BenchmarkEvaluation]:
    """
    Synthetic L2-only baseline for public corpora.

    Only `semantic_threshold` harness cases carry a synthetic semantic score.
    Other cases are treated as ALLOW because no standalone L2 signal is present.
    """
    evaluations: list[BenchmarkEvaluation] = []
    for case in cases:
        t_start = time.perf_counter()
        if case.harness == "semantic_threshold":
            result = _run_semantic_threshold(case)
            actual_action = result.action
            actual_rule_id = result.rule_matches[0].rule_id if result.rule_matches else None
            actual_layer = result.layer_triggered
            actual_rule_family = _rule_family(actual_rule_id) or "semantic"
        else:
            actual_action = "ALLOW"
            actual_rule_id = None
            actual_layer = None
            actual_rule_family = None
        latency_ms = (time.perf_counter() - t_start) * 1000
        evaluations.append(
            _evaluation_from_action(
                case,
                actual_action=actual_action,
                actual_rule_id=actual_rule_id,
                actual_layer=actual_layer,
                actual_rule_family=actual_rule_family,
                latency_ms=round(latency_ms, 3),
                details_prefix="l2_threshold_only",
            )
        )
    return evaluations


def _summarize_baseline(name: str, evaluations: list[BenchmarkEvaluation]) -> dict[str, Any]:
    return {
        "name": name,
        "summary": summarize_evaluations(evaluations),
        "quality": summarize_benchmark_quality(evaluations),
        "breakdowns": summarize_benchmark_breakdowns(evaluations),
        "confusion": summarize_confusion_matrix(evaluations),
        "latency": summarize_latency(evaluations),
        "evaluations": evaluations,
    }


def baseline_comparison_report(
    corpus_paths: list[str | Path] | None = None,
) -> dict[str, Any]:
    """
    Compare public benchmark behavior against simple reproducible baselines.

    These baselines are diagnostic, not full product substitutes:
    - `no_gateway`: every request is allowed.
    - `l1_only`: deterministic rules engine only.
    - `l2_threshold_only`: synthetic semantic-threshold cases only; other cases allow.
    - `configured_harness`: current benchmark harness behavior for the corpus.
    """
    if corpus_paths is None:
        corpus_paths = ["tests/benchmarks/mcp38_cases.yaml"]

    cases: list[BenchmarkCase] = []
    for path in corpus_paths:
        cases.extend(load_cases(path))

    baselines = {
        "no_gateway": _evaluate_no_gateway_baseline(cases),
        "l1_only": _evaluate_l1_only_baseline(cases),
        "l2_threshold_only": _evaluate_l2_threshold_only_baseline(cases),
        "configured_harness": evaluate_cases(cases),
    }

    return {
        "corpus_paths": [str(path) for path in corpus_paths],
        "cases": cases,
        "baselines": {
            name: _summarize_baseline(name, evaluations)
            for name, evaluations in baselines.items()
        },
    }


def summarize_evaluations(evaluations: list[BenchmarkEvaluation]) -> dict[str, int]:
    summary = {
        "passed": 0,
        "failed": 0,
        "ALLOW": 0,
        "WARN": 0,
        "BLOCK": 0,
        "total": len(evaluations),
    }
    for evaluation in evaluations:
        if evaluation.passed:
            summary["passed"] += 1
        else:
            summary["failed"] += 1
        summary[evaluation.expected_action] += 1
    return summary


def summarize_benchmark_quality(evaluations: list[BenchmarkEvaluation]) -> dict[str, float]:
    """Summarize behavior in a way that is more useful for hardening decisions."""
    total = len(evaluations)
    if total == 0:
        return {
            "total": 0.0,
            "pass_rate": 0.0,
            "adversarial_block_rate": 0.0,
            "benign_allow_rate": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
        }

    expected_block = [e for e in evaluations if e.expected_action == "BLOCK"]
    expected_allow = [e for e in evaluations if e.expected_action == "ALLOW"]
    blocked_expected_block = sum(1 for e in expected_block if e.actual_action == "BLOCK")
    allowed_expected_allow = sum(1 for e in expected_allow if e.actual_action == "ALLOW")
    false_positives = sum(1 for e in expected_allow if e.actual_action != "ALLOW")
    false_negatives = sum(1 for e in expected_block if e.actual_action != "BLOCK")

    return {
        "total": float(total),
        "pass_rate": sum(1 for e in evaluations if e.passed) / total,
        "adversarial_block_rate": (blocked_expected_block / len(expected_block)) if expected_block else 0.0,
        "benign_allow_rate": (allowed_expected_allow / len(expected_allow)) if expected_allow else 0.0,
        "false_positive_rate": (false_positives / len(expected_allow)) if expected_allow else 0.0,
        "false_negative_rate": (false_negatives / len(expected_block)) if expected_block else 0.0,
    }


def summarize_benchmark_breakdowns(evaluations: list[BenchmarkEvaluation]) -> dict[str, dict[str, int]]:
    """Group false-positive/negative and block behavior by layer and rule family."""
    breakdowns: dict[str, dict[str, int]] = {
        "benign_blocks_by_layer": {},
        "benign_blocks_by_rule_family": {},
        "malicious_blocks_by_layer": {},
        "malicious_blocks_by_rule_family": {},
        "false_negatives_by_expected_rule": {},
    }

    def _bump(bucket: str, key: object) -> None:
        value = str(key if key is not None else "none")
        breakdowns[bucket][value] = breakdowns[bucket].get(value, 0) + 1

    for evaluation in evaluations:
        if evaluation.expected_action == "ALLOW" and evaluation.actual_action != "ALLOW":
            _bump("benign_blocks_by_layer", evaluation.actual_layer)
            _bump("benign_blocks_by_rule_family", evaluation.actual_rule_family)
        if evaluation.expected_action == "BLOCK" and evaluation.actual_action == "BLOCK":
            _bump("malicious_blocks_by_layer", evaluation.actual_layer)
            _bump("malicious_blocks_by_rule_family", evaluation.actual_rule_family)
        if evaluation.expected_action == "BLOCK" and evaluation.actual_action != "BLOCK":
            _bump("false_negatives_by_expected_rule", evaluation.expected_rule_id)

    return breakdowns


def summarize_latency(evaluations: list[BenchmarkEvaluation]) -> dict[str, float]:
    """Summarize benchmark harness latency in milliseconds."""
    values = sorted(
        evaluation.latency_ms
        for evaluation in evaluations
        if evaluation.latency_ms is not None
    )
    if not values:
        return {
            "count": 0.0,
            "mean_ms": 0.0,
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "max_ms": 0.0,
            "total_ms": 0.0,
        }

    def percentile(p: float) -> float:
        index = min(len(values) - 1, max(0, int(round((len(values) - 1) * p))))
        return values[index]

    total = sum(values)
    return {
        "count": float(len(values)),
        "mean_ms": round(total / len(values), 3),
        "p50_ms": round(percentile(0.50), 3),
        "p95_ms": round(percentile(0.95), 3),
        "max_ms": round(max(values), 3),
        "total_ms": round(total, 3),
    }


def summarize_confusion_matrix(evaluations: list[BenchmarkEvaluation]) -> dict[str, Any]:
    """
    Summarize expected-vs-actual actions for public benchmark reporting.

    Rows represent the expected action from the corpus; columns represent the
    action McpVanguard actually returned. The matrix is intentionally scoped to
    the evaluated corpus/profile and should not be presented as universal
    detection coverage.
    """
    matrix: dict[str, dict[str, int]] = {
        expected: {actual: 0 for actual in ACTION_ORDER}
        for expected in ACTION_ORDER
    }
    unexpected_actuals: set[str] = set()

    for evaluation in evaluations:
        expected = evaluation.expected_action
        actual = evaluation.actual_action
        if expected not in matrix:
            matrix[expected] = {action: 0 for action in ACTION_ORDER}
        if actual not in matrix[expected]:
            matrix[expected][actual] = 0
            unexpected_actuals.add(actual)
        matrix[expected][actual] += 1

    actual_actions = tuple(dict.fromkeys((*ACTION_ORDER, *sorted(unexpected_actuals))))
    per_action: dict[str, dict[str, float | int]] = {}
    for action in actual_actions:
        expected_total = sum(matrix.get(action, {}).values())
        actual_total = sum(row.get(action, 0) for row in matrix.values())
        matched = matrix.get(action, {}).get(action, 0)
        per_action[action] = {
            "expected": expected_total,
            "actual": actual_total,
            "matched": matched,
            "recall": (matched / expected_total) if expected_total else 0.0,
            "precision": (matched / actual_total) if actual_total else 0.0,
        }

    mismatches = [
        {
            "case_id": evaluation.case_id,
            "public_case_id": evaluation.public_case_id,
            "source_corpus": evaluation.source_corpus,
            "mcp38_id": evaluation.mcp38_id,
            "expected_action": evaluation.expected_action,
            "actual_action": evaluation.actual_action,
            "expected_rule_id": evaluation.expected_rule_id,
            "actual_rule_id": evaluation.actual_rule_id,
            "actual_layer": evaluation.actual_layer,
            "actual_rule_family": evaluation.actual_rule_family,
            "latency_ms": evaluation.latency_ms,
            "details": evaluation.details,
        }
        for evaluation in evaluations
        if evaluation.expected_action != evaluation.actual_action
    ]

    return {
        "actions": list(actual_actions),
        "matrix": matrix,
        "per_action": per_action,
        "mismatches": mismatches,
    }


def benchmark_report(
    corpus_paths: list[str | Path] | None = None,
) -> dict[str, Any]:
    """Load one or more benchmark corpora and return a combined evaluation report."""
    if corpus_paths is None:
        corpus_paths = ["tests/benchmarks/mcp38_cases.yaml"]

    corpora: list[dict[str, Any]] = []
    cases: list[BenchmarkCase] = []
    for path in corpus_paths:
        corpus_cases = load_cases(path)
        corpus_evaluations = evaluate_cases(corpus_cases)
        corpora.append(
            {
                "path": str(path),
                "cases": corpus_cases,
                "evaluations": corpus_evaluations,
                "summary": summarize_evaluations(corpus_evaluations),
                "quality": summarize_benchmark_quality(corpus_evaluations),
                "breakdowns": summarize_benchmark_breakdowns(corpus_evaluations),
                "confusion": summarize_confusion_matrix(corpus_evaluations),
                "latency": summarize_latency(corpus_evaluations),
            }
        )
        cases.extend(corpus_cases)

    evaluations = [evaluation for corpus in corpora for evaluation in corpus["evaluations"]]
    return {
        "cases": cases,
        "evaluations": evaluations,
        "summary": summarize_evaluations(evaluations),
        "quality": summarize_benchmark_quality(evaluations),
        "breakdowns": summarize_benchmark_breakdowns(evaluations),
        "confusion": summarize_confusion_matrix(evaluations),
        "latency": summarize_latency(evaluations),
        "corpora": corpora,
    }


def profile_matrix_report(
    corpus_paths: list[str | Path] | None = None,
    profiles: list[str] | None = None,
) -> dict[str, Any]:
    """
    Evaluate the same corpora under multiple named profiles.

    This report is intended for release/research comparison. It shows how
    `monitor`, `balanced`, and `strict` shift enforcement on the same cases
    without requiring operators to run several commands and merge JSON by hand.
    """
    if corpus_paths is None:
        corpus_paths = ["tests/benchmarks/layered_profile_matrix.yaml"]
    if profiles is None:
        profiles = ["monitor", "balanced", "strict"]

    original_profile = os.environ.get("VANGUARD_PROFILE")
    profile_reports: dict[str, dict[str, Any]] = {}
    try:
        for profile in profiles:
            normalized = profile.strip().lower()
            if normalized not in {"monitor", "balanced", "strict"}:
                raise ValueError(f"Unsupported benchmark profile: {profile}")
            os.environ["VANGUARD_PROFILE"] = normalized
            profile_reports[normalized] = benchmark_report(corpus_paths)
    finally:
        if original_profile is None:
            os.environ.pop("VANGUARD_PROFILE", None)
        else:
            os.environ["VANGUARD_PROFILE"] = original_profile

    case_index: dict[str, dict[str, Any]] = {}
    for profile, report in profile_reports.items():
        for evaluation in report["evaluations"]:
            entry = case_index.setdefault(
                evaluation.case_id,
                {
                    "case_id": evaluation.case_id,
                    "public_case_id": evaluation.public_case_id,
                    "source_corpus": evaluation.source_corpus,
                    "mcp38_id": evaluation.mcp38_id,
                    "title": evaluation.title,
                    "expected_action": evaluation.expected_action,
                    "expected_rule_id": evaluation.expected_rule_id,
                    "profiles": {},
                },
            )
            entry["profiles"][profile] = {
                "actual_action": evaluation.actual_action,
                "passed": evaluation.passed,
                "actual_rule_id": evaluation.actual_rule_id,
                "actual_layer": evaluation.actual_layer,
                "actual_rule_family": evaluation.actual_rule_family,
                "actual_capabilities": evaluation.actual_capabilities,
                "details": evaluation.details,
            }

    case_rows = list(case_index.values())
    profile_order = [profile.strip().lower() for profile in profiles]
    for row in case_rows:
        actions = {
            profile: row["profiles"].get(profile, {}).get("actual_action")
            for profile in profile_order
        }
        observed = {action for action in actions.values() if action is not None}
        row["action_by_profile"] = actions
        row["action_delta"] = len(observed) > 1

    return {
        "profiles": profile_order,
        "corpus_paths": [str(path) for path in corpus_paths],
        "profile_reports": {
            profile: {
                "summary": report["summary"],
                "quality": report["quality"],
                "breakdowns": report["breakdowns"],
                "confusion": report["confusion"],
                "latency": report["latency"],
            }
            for profile, report in profile_reports.items()
        },
        "cases": case_rows,
        "deltas": [row for row in case_rows if row["action_delta"]],
    }


def threshold_sweep_report(
    corpus_path: str | Path,
    thresholds: list[tuple[float, float]] | None = None,
) -> dict[str, Any]:
    """Evaluate semantic-threshold cases across multiple warn/block pairs."""
    if thresholds is None:
        thresholds = [(0.40, 0.70), (0.50, 0.80), (0.60, 0.85)]

    cases = load_cases(corpus_path)
    corpus_summary: list[dict[str, Any]] = []
    for warn_threshold, block_threshold in thresholds:
        evaluations = []
        for case in cases:
            result = run_case(case)
            evaluations.append(_evaluate_semantic_threshold_case(case, result, warn_threshold, block_threshold))
        corpus_summary.append(
            {
                "warn_threshold": warn_threshold,
                "block_threshold": block_threshold,
                "summary": summarize_evaluations(evaluations),
                "quality": summarize_benchmark_quality(evaluations),
                "evaluations": evaluations,
            }
        )

    return {
        "corpus_path": str(corpus_path),
        "cases": cases,
        "thresholds": corpus_summary,
    }


async def _run_behavioral_request_sequence(case: BenchmarkCase):
    input_payload = case.input
    session_id = str(input_payload.get("session_id", case.case_id))
    steps = input_payload.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"Behavioral benchmark case {case.case_id} requires a non-empty steps list.")

    behavioral.clear_state(session_id)
    result = None
    try:
        for step in steps:
            if not isinstance(step, dict):
                raise ValueError(f"Behavioral benchmark step in {case.case_id} must be a mapping.")
            message = step.get("message")
            repeat = int(step.get("repeat", 1))
            if not isinstance(message, dict):
                raise ValueError(f"Behavioral benchmark step in {case.case_id} is missing a message mapping.")
            for _ in range(repeat):
                result = await behavioral.inspect_request(
                    session_id,
                    message,
                    str(step.get("server_id", input_payload.get("server_id", "default"))),
                )
        return result
    finally:
        behavioral.clear_state(session_id)


async def _run_proxy_auth_policy(case: BenchmarkCase):
    input_payload = case.input
    config = ProxyConfig()
    config.semantic_enabled = False
    config.behavioral_enabled = False
    config.required_destructive_roles = list(input_payload.get("required_roles", []))
    config.required_destructive_scopes = list(input_payload.get("required_scopes", []))
    if "auth_warning_tool_policy" in input_payload:
        config.auth_warning_tool_policy = str(input_payload["auth_warning_tool_policy"])
    if "destructive_tool_auth_policy" in input_payload:
        config.destructive_tool_auth_policy = str(input_payload["destructive_tool_auth_policy"])

    principal_payload = input_payload.get("principal", {})
    principal = None
    if isinstance(principal_payload, dict) and principal_payload:
        principal = AuthPrincipal(
            principal_id=str(principal_payload.get("principal_id", "benchmark-principal")),
            auth_type=str(principal_payload.get("auth_type", "benchmark")),
            roles=list(principal_payload.get("roles", [])),
            attributes=dict(principal_payload.get("attributes", {})),
        )

    proxy = VanguardProxy(
        server_command=["python", "-c", "print('benchmark')"],
        config=config,
        principal=principal,
    )
    # Keep this harness focused on auth policy; safe-zone behavior is covered
    # separately by rules/jail benchmarks and can otherwise mask WARN cases.
    proxy.rules_engine.safe_zones = []
    message = input_payload.get("message")
    if not isinstance(message, dict):
        raise ValueError(f"Proxy auth benchmark case {case.case_id} is missing a message mapping.")
    return await proxy._inspect_message(message)


async def _run_behavioral_response(case: BenchmarkCase):
    input_payload = case.input
    session_id = str(input_payload.get("session_id", case.case_id))
    server_id = str(input_payload.get("server_id", "default"))
    response_body = input_payload.get("response_body")
    if not isinstance(response_body, str):
        chunk = input_payload.get("response_chunk")
        repeat = int(input_payload.get("repeat", 1))
        if not isinstance(chunk, str) or repeat < 1:
            raise ValueError(
                f"Behavioral response benchmark case {case.case_id} requires a response_body string "
                "or response_chunk plus repeat."
            )
        response_body = chunk * repeat

    behavioral.clear_state(session_id)
    try:
        return await behavioral.inspect_response(session_id, response_body, server_id=server_id)
    finally:
        behavioral.clear_state(session_id)


def _run_semantic_threshold(case: BenchmarkCase) -> InspectionResult:
    input_payload = case.input
    score = float(input_payload.get("score", 0.0))
    reason = str(input_payload.get("reason", "synthetic semantic benchmark"))
    threshold_warn = float(input_payload.get("threshold_warn", 0.5))
    threshold_block = float(input_payload.get("threshold_block", 0.8))

    if score >= threshold_block:
        return InspectionResult(
            allowed=False,
            action="BLOCK",
            layer_triggered=2,
            rule_matches=[],
            semantic_score=score,
            block_reason=f"Semantic intent score {score:.2f} >= {threshold_block:.2f} - {reason}",
        )
    if score >= threshold_warn:
        return InspectionResult(
            allowed=True,
            action="WARN",
            layer_triggered=2,
            rule_matches=[],
            semantic_score=score,
            block_reason=f"Semantic intent score {score:.2f} >= {threshold_warn:.2f} - {reason}",
        )
    return InspectionResult.allow()


def _evaluate_semantic_threshold_case(
    case: BenchmarkCase,
    result: InspectionResult,
    warn_threshold: float,
    block_threshold: float,
) -> BenchmarkEvaluation:
    expected_action = case.expected_action
    actual_action = result.action
    actual_rule_id = result.rule_matches[0].rule_id if result.rule_matches else None
    passed = actual_action == expected_action
    details = None
    if not passed:
        details = f"expected action {expected_action}, got {actual_action}"
    return BenchmarkEvaluation(
        case_id=f"{case.case_id}@warn={warn_threshold:.2f}/block={block_threshold:.2f}",
        public_case_id=f"{case.public_case_id}@warn={warn_threshold:.2f}/block={block_threshold:.2f}",
        source_corpus=case.source_corpus,
        mcp38_id=case.mcp38_id,
        title=case.title,
        expected_action=expected_action,
        actual_action=actual_action,
        passed=passed,
        expected_rule_id=case.expected_rule_id,
        actual_rule_id=actual_rule_id,
        details=details,
    )


async def _run_behavioral_cross_server_sequence(case: BenchmarkCase):
    input_payload = case.input
    session_id = str(input_payload.get("session_id", case.case_id))
    steps = input_payload.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"Cross-server behavioral benchmark case {case.case_id} requires a non-empty steps list.")

    behavioral.clear_state(session_id)
    result = None
    try:
        for step in steps:
            if not isinstance(step, dict):
                raise ValueError(f"Cross-server behavioral step in {case.case_id} must be a mapping.")
            message = step.get("message")
            repeat = int(step.get("repeat", 1))
            server_id = str(step.get("server_id", "default"))
            if not isinstance(message, dict):
                raise ValueError(f"Cross-server behavioral step in {case.case_id} is missing a message mapping.")
            for _ in range(repeat):
                result = await behavioral.inspect_request(session_id, message, server_id=server_id)
        return result
    finally:
        for step in steps:
            if isinstance(step, dict):
                behavioral.clear_state(session_id, str(step.get("server_id", "default")))
