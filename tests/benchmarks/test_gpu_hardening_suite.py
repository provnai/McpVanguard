from core.benchmarks import (
    BenchmarkEvaluation,
    baseline_comparison_report,
    benchmark_report,
    evaluate_cases,
    load_cases,
    profile_matrix_report,
    summarize_benchmark_breakdowns,
    summarize_confusion_matrix,
    summarize_evaluations,
    summarize_latency,
)


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


def test_benchmark_breakdowns_expose_false_positive_triage_fields():
    cases = load_cases("tests/benchmarks/gpu_hardening_cases.yaml")
    evaluations = evaluate_cases(cases)
    breakdowns = summarize_benchmark_breakdowns(evaluations)

    assert "benign_blocks_by_layer" in breakdowns
    assert "benign_blocks_by_rule_family" in breakdowns
    assert "malicious_blocks_by_layer" in breakdowns
    assert "malicious_blocks_by_rule_family" in breakdowns
    assert any(e.actual_rule_family for e in evaluations if e.actual_rule_id)


def test_confusion_matrix_tracks_expected_vs_actual_actions():
    evaluations = [
        BenchmarkEvaluation(
            case_id="allow-ok",
            mcp38_id="MCP-TEST",
            title="allowed benign case",
            expected_action="ALLOW",
            actual_action="ALLOW",
            passed=True,
        ),
        BenchmarkEvaluation(
            case_id="allow-blocked",
            mcp38_id="MCP-TEST",
            title="blocked benign case",
            expected_action="ALLOW",
            actual_action="BLOCK",
            passed=False,
            actual_rule_id="VANGUARD-SAFEZONE-001",
            actual_layer=1,
            actual_rule_family="safe_zone",
            details="expected action ALLOW, got BLOCK",
        ),
        BenchmarkEvaluation(
            case_id="block-ok",
            mcp38_id="MCP-TEST",
            title="blocked malicious case",
            expected_action="BLOCK",
            actual_action="BLOCK",
            passed=True,
        ),
    ]

    confusion = summarize_confusion_matrix(evaluations)

    assert confusion["matrix"]["ALLOW"]["ALLOW"] == 1
    assert confusion["matrix"]["ALLOW"]["BLOCK"] == 1
    assert confusion["matrix"]["BLOCK"]["BLOCK"] == 1
    assert confusion["per_action"]["ALLOW"]["recall"] == 0.5
    assert confusion["per_action"]["BLOCK"]["precision"] == 0.5
    assert confusion["mismatches"][0]["case_id"] == "allow-blocked"


def test_latency_summary_reports_harness_timing():
    evaluations = [
        BenchmarkEvaluation(
            case_id="fast",
            mcp38_id="MCP-TEST",
            title="fast",
            expected_action="ALLOW",
            actual_action="ALLOW",
            passed=True,
            latency_ms=1.0,
        ),
        BenchmarkEvaluation(
            case_id="slow",
            mcp38_id="MCP-TEST",
            title="slow",
            expected_action="BLOCK",
            actual_action="BLOCK",
            passed=True,
            latency_ms=9.0,
        ),
    ]

    latency = summarize_latency(evaluations)

    assert latency["count"] == 2.0
    assert latency["mean_ms"] == 5.0
    assert latency["p50_ms"] in {1.0, 9.0}
    assert latency["p95_ms"] == 9.0
    assert latency["max_ms"] == 9.0


def test_packaged_benchmark_corpora_are_available_outside_repo_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    report = benchmark_report(["tests/benchmarks/gpu_hardening_cases.yaml"])

    assert report["summary"]["total"] > 0
    assert report["summary"]["failed"] == 0
    assert report["confusion"]["matrix"]["BLOCK"]["BLOCK"] >= 1
    assert report["latency"]["count"] == float(report["summary"]["total"])
    assert report["latency"]["max_ms"] >= 0.0
    assert all(case.public_case_id.startswith("mcpv:gpu_hardening_cases:") for case in report["cases"])
    assert all(evaluation.public_case_id for evaluation in report["evaluations"])


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


def test_profile_matrix_report_compares_actions_and_restores_env(monkeypatch):
    monkeypatch.setenv("VANGUARD_PROFILE", "balanced")

    report = profile_matrix_report(["tests/benchmarks/layered_profile_matrix.yaml"])

    assert report["profiles"] == ["monitor", "balanced", "strict"]
    assert report["profile_reports"]["strict"]["summary"]["total"] == 6
    assert report["profile_reports"]["strict"]["summary"]["failed"] == 0
    assert report["profile_reports"]["strict"]["latency"]["count"] == 6.0
    assert report["cases"]
    assert all(row["public_case_id"].startswith("mcpv:layered_profile_matrix:") for row in report["cases"])
    assert all(row["source_corpus"] == "layered_profile_matrix" for row in report["cases"])
    assert any(row["action_delta"] for row in report["cases"])
    assert all(
        set(row["action_by_profile"]) == {"monitor", "balanced", "strict"}
        for row in report["cases"]
    )
    assert __import__("os").environ["VANGUARD_PROFILE"] == "balanced"


def test_baseline_comparison_report_includes_diagnostic_baselines():
    report = baseline_comparison_report(["tests/benchmarks/gpu_semantic_threshold_cases.yaml"])

    assert set(report["baselines"]) == {
        "no_gateway",
        "l1_only",
        "l2_threshold_only",
        "configured_harness",
    }
    assert report["baselines"]["no_gateway"]["summary"]["total"] == 5
    assert report["baselines"]["no_gateway"]["summary"]["failed"] >= 1
    assert report["baselines"]["l2_threshold_only"]["summary"]["failed"] == 0
    assert report["baselines"]["configured_harness"]["latency"]["count"] == 5.0
