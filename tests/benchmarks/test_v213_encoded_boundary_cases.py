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

    evaluations = evaluate_cases(cases)
    assert all(evaluation.passed for evaluation in evaluations), evaluations


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
