"""
core/benchmarks.py
Shared MCP-38 benchmark loading and execution helpers.
"""

from __future__ import annotations

import asyncio
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


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
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
    details: str | None = None


def _read_case_corpus(path: str | Path) -> str:
    candidate = Path(path)
    if candidate.exists():
        return candidate.read_text(encoding="utf-8")

    if candidate.parent.as_posix().replace("\\", "/") == "tests/benchmarks":
        resource_name = candidate.name
        return resources.files("core.benchmark_cases").joinpath(resource_name).read_text(encoding="utf-8")

    raise FileNotFoundError(f"Benchmark corpus not found: {path}")


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
    result = run_case(case)
    actual_action = "ALLOW" if result is None else result.action
    actual_rule_id = None
    if result is not None and result.rule_matches:
        actual_rule_id = result.rule_matches[0].rule_id

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
        mcp38_id=case.mcp38_id,
        title=case.title,
        expected_action=case.expected_action,
        actual_action=actual_action,
        passed=passed,
        expected_rule_id=case.expected_rule_id,
        actual_rule_id=actual_rule_id,
        details=details,
    )


def evaluate_cases(cases: list[BenchmarkCase]) -> list[BenchmarkEvaluation]:
    return [evaluate_case(case) for case in cases]


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
            }
        )
        cases.extend(corpus_cases)

    evaluations = [evaluation for corpus in corpora for evaluation in corpus["evaluations"]]
    return {
        "cases": cases,
        "evaluations": evaluations,
        "summary": summarize_evaluations(evaluations),
        "quality": summarize_benchmark_quality(evaluations),
        "corpora": corpora,
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
