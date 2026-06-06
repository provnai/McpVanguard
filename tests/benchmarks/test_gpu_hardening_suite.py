from core.benchmarks import benchmark_report, evaluate_cases, load_cases, summarize_evaluations


def test_gpu_hardening_suite_passes_as_a_pair():
    adversarial = load_cases("tests/benchmarks/gpu_hardening_cases.yaml")
    false_positive = load_cases("tests/benchmarks/gpu_false_positive_cases.yaml")

    all_cases = adversarial + false_positive
    evaluations = evaluate_cases(all_cases)
    summary = summarize_evaluations(evaluations)

    assert summary["total"] == len(all_cases)
    assert summary["failed"] == 0
    assert summary["passed"] == len(all_cases)
    assert summary["BLOCK"] >= 2
    assert summary["ALLOW"] >= 2


def test_packaged_benchmark_corpora_are_available_outside_repo_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    report = benchmark_report(["tests/benchmarks/gpu_hardening_cases.yaml"])

    assert report["summary"]["total"] > 0
    assert report["summary"]["failed"] == 0


def test_packaged_layered_benchmark_corpora_are_available_outside_repo_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VANGUARD_PROFILE", "strict")

    report = benchmark_report([
        "tests/benchmarks/layered_strict_adversarial_cases.yaml",
        "tests/benchmarks/layered_balanced_benign_cases.yaml",
        "tests/benchmarks/layered_behavioral_sequences.yaml",
        "tests/benchmarks/layered_profile_matrix.yaml",
    ])

    assert report["summary"]["total"] == 35
    assert report["summary"]["failed"] == 0


def test_layered_fallback_corpora_label_public_reconstruction_source():
    corpus_paths = [
        "tests/benchmarks/layered_strict_adversarial_cases.yaml",
        "tests/benchmarks/layered_balanced_benign_cases.yaml",
        "tests/benchmarks/layered_behavioral_sequences.yaml",
        "tests/benchmarks/layered_profile_matrix.yaml",
    ]

    for path in corpus_paths:
        cases = load_cases(path)
        assert cases, path
        raw = __import__("yaml").safe_load(__import__("pathlib").Path(path).read_text(encoding="utf-8"))
        assert all(item.get("source_artifact") == "public_reconstruction" for item in raw), path
