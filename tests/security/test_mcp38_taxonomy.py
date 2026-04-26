from core.taxonomy import EXPECTED_IDS, load_mcp38_coverage, summarize_coverage


def test_mcp38_coverage_file_is_complete_and_ordered():
    entries = load_mcp38_coverage()

    assert [entry.taxonomy_id for entry in entries] == EXPECTED_IDS
    assert len(entries) == 38


def test_mcp38_coverage_summary_matches_expected_totals():
    entries = load_mcp38_coverage()
    summary = summarize_coverage(entries)

    assert summary["total"] == 38
    assert summary["implemented"] > 0
    assert summary["partial"] > 0
    assert summary["gap"] > 0
