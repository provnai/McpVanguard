from core.benchmarks import evaluate_cases, load_cases, summarize_cases


def test_gpu_hardening_cases_load_and_evaluate():
    cases = load_cases("tests/benchmarks/gpu_hardening_cases.yaml")
    assert len(cases) >= 6

    summary = summarize_cases(cases)
    assert summary["total"] == len(cases)
    assert summary["BLOCK"] >= 2
    assert summary["ALLOW"] >= 2

    evaluations = evaluate_cases(cases)
    assert len(evaluations) == len(cases)
    assert any(case.case_id.startswith("gpu-meta-") for case in cases)
