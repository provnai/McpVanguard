from __future__ import annotations

from core.benchmarks import (
    KNOWN_HARNESSES,
    evaluate_cases,
    load_cases,
    run_case,
    summarize_evaluations,
)


def test_mcp38_benchmark_corpus_is_well_formed():
    cases = load_cases()

    assert len(cases) >= 8
    assert len({case.case_id for case in cases}) == len(cases)
    assert {case.expected_action for case in cases}.issubset({"ALLOW", "WARN", "BLOCK"})
    assert {case.harness for case in cases}.issubset(KNOWN_HARNESSES)


def test_mcp38_benchmark_cases_match_expected_outcomes():
    cases = load_cases()

    for case in cases:
        result = run_case(case)
        expected_action = case.expected_action

        if expected_action == "ALLOW":
            if result is None:
                continue
            assert result.action == "ALLOW", case.case_id
            continue

        assert result is not None, case.case_id
        assert result.action == expected_action, case.case_id
        if case.expected_rule_id:
            assert result.rule_matches, case.case_id
            assert result.rule_matches[0].rule_id == case.expected_rule_id, case.case_id


def test_mcp38_benchmark_cases_reference_known_taxonomy_ids():
    cases = load_cases()
    known_ids = {f"MCP-{index:02d}" for index in range(1, 39)}

    assert all(case.mcp38_id in known_ids for case in cases)


def test_mcp38_benchmark_evaluations_pass_for_current_corpus():
    cases = load_cases()
    evaluations = evaluate_cases(cases)
    summary = summarize_evaluations(evaluations)

    assert summary["total"] == len(cases)
    assert summary["failed"] == 0
    assert summary["passed"] == len(cases)
