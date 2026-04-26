from core import conformance


def test_build_conformance_server_command_includes_expected_arguments(tmp_path):
    baseline = tmp_path / "baseline.yml"
    command = conformance.build_conformance_server_command(
        "http://127.0.0.1:8080/mcp",
        scenario="server-initialize",
        suite="all",
        expected_failures=baseline,
        verbose=True,
    )

    assert command == [
        "npx",
        "@modelcontextprotocol/conformance",
        "server",
        "--url",
        "http://127.0.0.1:8080/mcp",
        "--scenario",
        "server-initialize",
        "--suite",
        "all",
        "--expected-failures",
        str(baseline),
        "--verbose",
    ]


def test_build_conformance_server_command_rejects_invalid_url():
    try:
        conformance.build_conformance_server_command("not-a-url")
    except ValueError as exc:
        assert "valid http://" in str(exc)
    else:
        raise AssertionError("Expected invalid conformance URL to raise ValueError")
