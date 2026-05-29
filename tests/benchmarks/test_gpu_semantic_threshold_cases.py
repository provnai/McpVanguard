from core.benchmarks import evaluate_cases, load_cases, summarize_evaluations


def test_gpu_semantic_threshold_cases_are_classified():
    cases = load_cases("tests/benchmarks/gpu_semantic_threshold_cases.yaml")
    evaluations = evaluate_cases(cases)
    summary = summarize_evaluations(evaluations)

    assert summary["total"] == len(cases)
    assert summary["failed"] == 0
    assert summary["passed"] == len(cases)
    assert summary["ALLOW"] >= 1
    assert summary["WARN"] >= 1
    assert summary["BLOCK"] >= 1
