import os
from unittest.mock import patch

from core.benchmarks import evaluate_cases, load_cases, summarize_cases
from core.rules_engine import RulesEngine


def test_v213_encoded_boundary_cases_load_and_evaluate():
    cases = load_cases("tests/benchmarks/v213_encoded_boundary_cases.yaml")
    assert len(cases) == 10

    summary = summarize_cases(cases)
    assert summary["BLOCK"] == 7
    assert summary["WARN"] == 2
    assert summary["ALLOW"] == 1

    with patch.dict(os.environ, {"VANGUARD_PROFILE": "balanced"}):
        evaluations = evaluate_cases(cases)
    assert all(evaluation.passed for evaluation in evaluations), evaluations


def test_v213_strict_profile_preserves_blocks_and_allows_documented_escalation():
    cases = load_cases("tests/benchmarks/v213_encoded_boundary_cases.yaml")

    with patch.dict(os.environ, {"VANGUARD_PROFILE": "strict"}):
        evaluations = evaluate_cases(cases)

    by_case_id = {evaluation.case_id: evaluation for evaluation in evaluations}
    for case in cases:
        evaluation = by_case_id[case.case_id]
        if case.expected_action == "BLOCK":
            assert evaluation.actual_action == "BLOCK", evaluation
        elif case.expected_action == "WARN":
            assert evaluation.actual_action in {"WARN", "BLOCK"}, evaluation
        else:
            assert evaluation.actual_action == "ALLOW", evaluation

    for case_id in ("v213-url-04-encoded-loopback-warn", "v213-url-05-userinfo-loopback-warn"):
        evaluation = by_case_id[case_id]
        assert evaluation.actual_action == "BLOCK", evaluation
        assert evaluation.actual_rule_id == "STRICT-NET-001", evaluation


def test_v213_strict_profile_blocks_loopback_variants_that_balanced_warns_or_allows():
    urls = {
        "encoded_loopback": "http://127%2e0%2e0%2e1/admin",
        "localhost_trailing_dot": "http://localhost./admin",
        "userinfo_loopback": "http://safe.example@127.0.0.1/admin",
    }

    for url in urls.values():
        message = {"params": {"arguments": {"url": url}}}

        with patch.dict(os.environ, {"VANGUARD_PROFILE": "balanced"}):
            balanced = RulesEngine(rules_dir="rules")
            balanced.safe_zones = []
            balanced_result = balanced.check(message)

        with patch.dict(os.environ, {"VANGUARD_PROFILE": "strict"}):
            strict = RulesEngine(rules_dir="rules")
            strict.safe_zones = []
            strict_result = strict.check(message)

        assert balanced_result.action in {"ALLOW", "WARN"}
        assert strict_result.action == "BLOCK"
