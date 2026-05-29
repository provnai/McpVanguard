from core.benchmarks import evaluate_cases, load_cases, summarize_evaluations, summarize_cases


def test_gpu_false_positive_cases_are_benign_and_stable():
    cases = load_cases("tests/benchmarks/gpu_false_positive_cases.yaml")
    assert len(cases) >= 5

    summary = summarize_cases(cases)
    assert summary["total"] == len(cases)
    assert summary["ALLOW"] == len(cases)

    evaluations = evaluate_cases(cases)
    summary_eval = summarize_evaluations(evaluations)
    assert summary_eval["total"] == len(cases)
    assert summary_eval["failed"] == 0
    assert summary_eval["passed"] == len(cases)
