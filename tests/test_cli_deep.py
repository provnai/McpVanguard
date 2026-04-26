import pathlib
"""
tests/test_cli_deep.py
Testing CLI tools: init and configure-claude.
"""

import os
import json
import pytest
import shutil
import sys
import base64
import datetime as dt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from core.cli import app
from core import capability_fingerprint, provenance
from core import server_integrity
from core import signing
from core import sigstore_bundle
from core import supplier_signatures
from core import conformance
from typer.testing import CliRunner
from unittest.mock import AsyncMock, patch

runner = CliRunner()

MOCK_PROBE_SERVER = """
import json
import sys

TOOLS = [
    {
        "name": "get_status",
        "description": "Return a static status payload.",
        "annotations": {
            "readOnlyHint": True,
            "idempotentHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
        "inputSchema": {"type": "object"},
    },
    {
        "name": "mutate_state",
        "description": "Pretend to mutate internal state.",
        "annotations": {
            "readOnlyHint": False,
            "idempotentHint": False,
            "destructiveHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {"type": "object"},
    },
]

for raw in sys.stdin:
    if not raw.strip():
        continue
    msg = json.loads(raw)
    method = msg.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "protocolVersion": msg["params"]["protocolVersion"],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mock-probe-server", "version": "1.0.0"},
            }
        }), flush=True)
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"tools": TOOLS},
        }), flush=True)
    elif method == "tools/call":
        name = msg["params"]["name"]
        if name == "get_status":
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {"content": [{"type": "text", "text": "ok"}]},
            }), flush=True)
        else:
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "result": {"content": [{"type": "text", "text": "mutated"}]},
            }), flush=True)
"""


def _write_mock_probe_server(tmp_path):
    script_path = tmp_path / "mock_probe_server.py"
    script_path.write_text(MOCK_PROBE_SERVER, encoding="utf-8")
    return script_path

def test_vanguard_init_logic(tmp_path, monkeypatch):
    """Test that vanguard init creates the correct file structure."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert "Initializing McpVanguard Workspace" in result.stdout
    
    assert os.path.exists(".env")
    assert os.path.exists("rules/safe_zones.yaml")
    
    with open(".env", "r") as f:
        content = f.read()
        assert "VANGUARD_MODE=audit" in content
        
def test_vanguard_configure_claude_logic(tmp_path, monkeypatch):
    """Test Claude configuration injection."""
    # Create fake AppData structure
    fake_appdata = tmp_path / "AppData"
    claude_dir = fake_appdata / "Claude"
    claude_dir.mkdir(parents=True)
    config_file = claude_dir / "claude_desktop_config.json"
    
    initial_config = {
        "mcpServers": {
            "test-server": {
                "command": "node",
                "args": ["server.js"]
            }
        }
    }
    with open(config_file, "w") as f:
        json.dump(initial_config, f)
        
    # Mock APPDATA env var
    monkeypatch.setenv("APPDATA", str(fake_appdata))
    
    result = runner.invoke(app, ["configure-claude"])
    assert result.exit_code == 0
    assert "Wrapped 1 servers" in result.stdout
    
    with open(config_file, "r") as f:
        updated = json.load(f)
        server = updated["mcpServers"]["test-server"]
        assert server["command"] == "vanguard"
        assert server["args"] == ["start", "--server", "node server.js"]


def test_vanguard_start_semantic_flag_does_not_crash(monkeypatch):
    monkeypatch.setenv("VANGUARD_SEMANTIC_ENABLED", "false")

    with patch("core.cli.run_proxy") as mock_run_proxy, \
         patch("core.semantic.check_semantic_health", new=AsyncMock(return_value=True)):
        result = runner.invoke(app, ["start", "--server", "echo hello", "--semantic"])

    assert result.exit_code == 0
    mock_run_proxy.assert_called_once()


def test_vanguard_start_management_tools_flag_enables_surface():
    with patch("core.cli.run_proxy") as mock_run_proxy:
        result = runner.invoke(app, ["start", "--server", "echo hello", "--management-tools"])

    assert result.exit_code == 0
    mock_run_proxy.assert_called_once()
    config = mock_run_proxy.call_args.kwargs["config"]
    assert config.management_tools_enabled is True


def test_vanguard_sse_management_tools_flag_enables_surface():
    async def fake_run_sse_server(*, config, **kwargs):
        return config

    with patch("asyncio.run") as mock_asyncio_run, \
         patch("core.sse_server.run_sse_server", new=fake_run_sse_server):
        result = runner.invoke(app, ["sse", "--server", "echo hello", "--management-tools"])

    assert result.exit_code == 0
    mock_asyncio_run.assert_called_once()
    coroutine = mock_asyncio_run.call_args.args[0]
    config = coroutine.cr_frame.f_locals["config"]
    assert config.management_tools_enabled is True
    coroutine.close()


def test_vanguard_taxonomy_coverage_reports_summary():
    result = runner.invoke(app, ["taxonomy-coverage"])

    assert result.exit_code == 0
    assert "MCP-38 Coverage" in result.stdout
    assert "Implemented:" in result.stdout
    assert "Partial:" in result.stdout
    assert "Gap:" in result.stdout
    assert "MCP-10" in result.stdout


def test_vanguard_benchmark_coverage_reports_summary():
    result = runner.invoke(app, ["benchmark-coverage"])

    assert result.exit_code == 0
    assert "MCP-38 Benchmark Coverage" in result.stdout
    assert "Allow:" in result.stdout
    assert "Warn:" in result.stdout
    assert "Block:" in result.stdout
    assert "Benchmark Corpus" in result.stdout
    assert "MCP-17" in result.stdout
    assert "Taxonomy IDs covered:" in result.stdout


def test_vanguard_benchmark_coverage_json_output_is_machine_readable():
    result = runner.invoke(app, ["benchmark-coverage", "--json-output"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["total"] >= 1
    assert "MCP-17" in payload["taxonomy_counts"]
    assert any(case["case_id"] == "bench-mcp09-cloud-metadata-ssrf" for case in payload["cases"])


def test_vanguard_benchmark_run_reports_pass_summary():
    result = runner.invoke(app, ["benchmark-run"])

    assert result.exit_code == 0
    assert "MCP-38 Benchmark Run" in result.stdout
    assert "Passed:" in result.stdout
    assert "Failed:" in result.stdout
    assert "Benchmark Results" in result.stdout
    assert "bench-mcp08-etc-passwd" in result.stdout
    assert "0" in result.stdout


def test_vanguard_benchmark_run_json_output_is_machine_readable():
    result = runner.invoke(app, ["benchmark-run", "--json-output"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["failed"] == 0
    assert payload["summary"]["passed"] == payload["summary"]["total"]
    assert any(evaluation["case_id"] == "bench-mcp24-large-response" for evaluation in payload["evaluations"])


def test_vanguard_server_manifest_writes_output(tmp_path):
    output = tmp_path / "server-manifest.json"

    result = runner.invoke(
        app,
        [
            "server-manifest",
            "--server",
            "python -m demo_server",
            "--output",
            str(output),
            "--approval-status",
            "approved",
            "--trust-level",
            "internal",
        ],
    )

    assert result.exit_code == 0
    assert output.exists()
    assert "Wrote server manifest" in result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["trust"]["approval_status"] == "approved"
    assert payload["trust"]["trust_level"] == "internal"


def test_vanguard_server_verify_detects_drift(tmp_path):
    manifest_path = tmp_path / "server-manifest.json"
    baseline = {
        "version": 1,
        "command": {
            "argv": ["python", "-m", "server_a"],
            "display": "python -m server_a",
            "fingerprint_sha256": "baseline",
        },
        "executable": {
            "name": "python",
            "resolved_path": None,
            "exists": False,
        },
        "runtime": {
            "cwd": str(tmp_path),
            "package_manager": "python",
            "package_identifier": "server_a",
            "package_version": None,
            "image_identifier": None,
        },
        "trust": {
            "approval_status": "unapproved",
            "trust_level": "unknown",
        },
    }
    manifest_path.write_text(json.dumps(baseline), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "server-verify",
            "--server",
            "python -m server_b",
            "--manifest-file",
            str(manifest_path),
        ],
    )

    assert result.exit_code == 1
    assert "DRIFT DETECTED" in result.stdout
    assert "command.argv" in result.stdout


def test_vanguard_server_sign_manifest_writes_signature(tmp_path):
    manifest_path = tmp_path / "server-manifest.json"
    signature_path = tmp_path / "server-manifest.sig.json"
    private_key_path = tmp_path / "server-key.pem"
    private_key_pem, signer_doc = signing.generate_signing_keypair("server-baseline-signer")
    manifest_path.write_text(
        json.dumps(
            {
                "version": 1,
                "command": {"argv": ["python", "-m", "server_a"], "display": "python -m server_a", "fingerprint_sha256": "x"},
                "executable": {"name": "python", "resolved_path": None, "exists": False},
                "runtime": {"cwd": str(tmp_path), "package_manager": "python", "package_identifier": "server_a", "package_version": None, "image_identifier": None},
                "trust": {"approval_status": "approved", "trust_level": "internal"},
            }
        ),
        encoding="utf-8",
    )
    private_key_path.write_bytes(private_key_pem)

    result = runner.invoke(
        app,
        [
            "server-sign-manifest",
            "--manifest-file",
            str(manifest_path),
            "--private-key",
            str(private_key_path),
            "--key-id",
            signer_doc["key_id"],
            "--output",
            str(signature_path),
        ],
    )

    assert result.exit_code == 0
    assert signature_path.exists()
    assert "Wrote server manifest signature" in result.stdout


def test_vanguard_server_verify_can_check_signature_and_trust(tmp_path):
    manifest_path = tmp_path / "server-manifest.json"
    signature_path = tmp_path / "server-manifest.sig.json"
    private_key_path = tmp_path / "server-key.pem"
    trust_key_path = tmp_path / "trusted-server-signer.json"
    private_key_pem, signer_doc = signing.generate_signing_keypair("server-baseline-signer")

    manifest_payload = server_integrity.build_server_manifest(
        ["python", "-m", "server_a"],
        approval_status="approved",
        trust_level="internal",
    )
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")
    private_key_path.write_bytes(private_key_pem)
    trust_key_path.write_text(json.dumps(signer_doc), encoding="utf-8")

    sign_result = runner.invoke(
        app,
        [
            "server-sign-manifest",
            "--manifest-file",
            str(manifest_path),
            "--private-key",
            str(private_key_path),
            "--key-id",
            signer_doc["key_id"],
            "--output",
            str(signature_path),
        ],
    )
    assert sign_result.exit_code == 0

    verify_result = runner.invoke(
        app,
        [
            "server-verify",
            "--server",
            "python -m server_a",
            "--manifest-file",
            str(manifest_path),
            "--signature-file",
            str(signature_path),
            "--trust-key-file",
            str(trust_key_path),
            "--check-trust",
        ],
    )

    assert verify_result.exit_code == 0
    assert "Signature:" in verify_result.stdout
    assert "verified" in verify_result.stdout
    assert "Trust state:" in verify_result.stdout


def test_vanguard_capability_manifest_writes_output(tmp_path):
    initialize_file = tmp_path / "initialize.json"
    output = tmp_path / "capability-manifest.json"
    initialize_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "init-1",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "demo", "version": "1.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "capability-manifest",
            "--initialize-file",
            str(initialize_file),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.exists()
    assert "Wrote capability manifest" in result.stdout


def test_vanguard_capability_verify_detects_drift(tmp_path):
    manifest_file = tmp_path / "capability-manifest.json"
    tools_file = tmp_path / "tools.json"
    manifest_file.write_text(
        json.dumps(
            {
                "version": 1,
                "initialize": None,
                "tools": {
                    "count": 1,
                    "tools": [
                        {
                            "name": "read_file",
                            "title": None,
                            "description_sha256": "old",
                            "annotations": {},
                            "inputSchema": {},
                            "inputSchema_sha256": "old-schema",
                        }
                    ],
                    "tools_sha256": "old-tools",
                },
            }
        ),
        encoding="utf-8",
    )
    tools_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "tools-1",
                "result": {
                    "tools": [
                        {"name": "write_file", "description": "Write a file."}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "capability-verify",
            "--manifest-file",
            str(manifest_file),
            "--tools-file",
            str(tools_file),
        ],
    )

    assert result.exit_code == 1
    assert "Capability Verification" in result.stdout
    assert "DRIFT DETECTED" in result.stdout
    assert "tools" in result.stdout


def test_vanguard_baseline_bundle_writes_all_outputs(tmp_path):
    initialize_file = tmp_path / "initialize.json"
    tools_file = tmp_path / "tools.json"
    output_dir = tmp_path / "bundle"
    initialize_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "init-1",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "demo", "version": "1.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    tools_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "tools-1",
                "result": {
                    "tools": [{"name": "read_file", "description": "Read a file."}]
                },
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "baseline-bundle",
            "--server",
            "python -m demo_server",
            "--output-dir",
            str(output_dir),
            "--initialize-file",
            str(initialize_file),
            "--tools-file",
            str(tools_file),
            "--approval-status",
            "approved",
            "--trust-level",
            "internal",
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / "server-manifest.json").exists()
    assert (output_dir / "capability-manifest.json").exists()
    assert (output_dir / "baseline-bundle.json").exists()
    index_payload = json.loads((output_dir / "baseline-bundle.json").read_text(encoding="utf-8"))
    assert index_payload["includes_initialize"] is True
    assert index_payload["includes_tools"] is True


def test_vanguard_baseline_bundle_can_sign_server_manifest(tmp_path):
    initialize_file = tmp_path / "initialize.json"
    tools_file = tmp_path / "tools.json"
    output_dir = tmp_path / "bundle"
    private_key_path = tmp_path / "server-key.pem"
    private_key_pem, signer_doc = signing.generate_signing_keypair("server-baseline-signer")
    initialize_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "init-1",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "demo", "version": "1.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    tools_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "tools-1",
                "result": {
                    "tools": [{"name": "read_file", "description": "Read a file."}]
                },
            }
        ),
        encoding="utf-8",
    )
    private_key_path.write_bytes(private_key_pem)

    result = runner.invoke(
        app,
        [
            "baseline-bundle",
            "--server",
            "python -m demo_server",
            "--output-dir",
            str(output_dir),
            "--initialize-file",
            str(initialize_file),
            "--tools-file",
            str(tools_file),
            "--approval-status",
            "approved",
            "--trust-level",
            "internal",
            "--private-key",
            str(private_key_path),
            "--key-id",
            signer_doc["key_id"],
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / "server-manifest.sig.json").exists()
    index_payload = json.loads((output_dir / "baseline-bundle.json").read_text(encoding="utf-8"))
    assert index_payload["server_manifest_signature"] == str(output_dir / "server-manifest.sig.json")


def test_vanguard_provenance_sign_writes_signature(tmp_path):
    provenance_path = tmp_path / "server-provenance.json"
    signature_path = tmp_path / "server-provenance.sig.json"
    private_key_path = tmp_path / "provenance-key.pem"
    private_key_pem, signer_doc = signing.generate_signing_keypair("provenance-signer")
    provenance_path.write_text(
        json.dumps(
            {
                "_type": provenance.PROVENANCE_STATEMENT_TYPE,
                "subject": [{"name": "demo-server", "digest": {"sha256": "e" * 64}}],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {"runDetails": {"builder": {"id": "https://builder.example/gha"}}},
            }
        ),
        encoding="utf-8",
    )
    private_key_path.write_bytes(private_key_pem)

    result = runner.invoke(
        app,
        [
            "provenance-sign",
            "--provenance-file",
            str(provenance_path),
            "--private-key",
            str(private_key_path),
            "--key-id",
            signer_doc["key_id"],
            "--output",
            str(signature_path),
        ],
    )

    assert result.exit_code == 0
    assert signature_path.exists()
    assert "Wrote provenance signature" in result.stdout


def test_vanguard_server_verify_can_check_provenance(tmp_path):
    manifest_path = tmp_path / "server-manifest.json"
    private_key_path = tmp_path / "provenance-key.pem"
    provenance_path = tmp_path / "server-provenance.json"
    provenance_signature_path = tmp_path / "server-provenance.sig.json"
    trust_key_path = tmp_path / "trusted-provenance-signer.json"
    private_key_pem, signer_doc = signing.generate_signing_keypair("provenance-signer")

    manifest_payload = server_integrity.build_server_manifest(
        ["python", "-m", "server_a"],
        approval_status="approved",
        trust_level="internal",
    )
    manifest_payload["executable"]["sha256"] = "f" * 64
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")

    provenance_payload = {
        "_type": provenance.PROVENANCE_STATEMENT_TYPE,
        "subject": [{"name": "server_a", "digest": {"sha256": "f" * 64}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"runDetails": {"builder": {"id": "https://builder.example/gha"}}},
    }
    provenance_path.write_text(json.dumps(provenance_payload), encoding="utf-8")
    private_key_path.write_bytes(private_key_pem)
    trust_key_path.write_text(json.dumps(signer_doc), encoding="utf-8")

    sign_result = runner.invoke(
        app,
        [
            "provenance-sign",
            "--provenance-file",
            str(provenance_path),
            "--private-key",
            str(private_key_path),
            "--key-id",
            signer_doc["key_id"],
            "--output",
            str(provenance_signature_path),
        ],
    )
    assert sign_result.exit_code == 0

    with patch("core.server_integrity.build_server_manifest", return_value=manifest_payload):
        verify_result = runner.invoke(
            app,
            [
                "server-verify",
                "--server",
                "python -m server_a",
                "--manifest-file",
                str(manifest_path),
                "--provenance-file",
                str(provenance_path),
                "--provenance-signature-file",
                str(provenance_signature_path),
                "--provenance-trust-key-file",
                str(trust_key_path),
                "--required-provenance-builder",
                "https://builder.example/gha",
            ],
        )

    assert verify_result.exit_code == 0
    assert "Provenance:" in verify_result.stdout
    assert "verified" in verify_result.stdout


def test_vanguard_baseline_bundle_can_include_provenance(tmp_path):
    initialize_file = tmp_path / "initialize.json"
    tools_file = tmp_path / "tools.json"
    output_dir = tmp_path / "bundle"
    provenance_path = tmp_path / "server-provenance.json"
    provenance_signature_path = tmp_path / "server-provenance.sig.json"
    initialize_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "init-1",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "demo", "version": "1.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    tools_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "tools-1",
                "result": {
                    "tools": [{"name": "read_file", "description": "Read a file."}]
                },
            }
        ),
        encoding="utf-8",
    )
    provenance_path.write_text(
        json.dumps(
            {
                "_type": provenance.PROVENANCE_STATEMENT_TYPE,
                "subject": [{"name": "demo-server", "digest": {"sha256": "f" * 64}}],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {"runDetails": {"builder": {"id": "https://builder.example/gha"}}},
            }
        ),
        encoding="utf-8",
    )
    provenance_signature_path.write_text(
        json.dumps(
            {
                "version": 1,
                "algorithm": "ed25519",
                "key_id": "provenance-signer",
                "payload_sha256": "placeholder",
                "signature": "c2lnbmF0dXJlLW5vdC12ZXJpZmllZC1oZXJl",
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "baseline-bundle",
            "--server",
            "python -m demo_server",
            "--output-dir",
            str(output_dir),
            "--initialize-file",
            str(initialize_file),
            "--tools-file",
            str(tools_file),
            "--provenance-file",
            str(provenance_path),
            "--provenance-signature-file",
            str(provenance_signature_path),
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / "server-provenance.json").exists()
    assert (output_dir / "server-provenance.sig.json").exists()
    index_payload = json.loads((output_dir / "baseline-bundle.json").read_text(encoding="utf-8"))
    assert index_payload["server_provenance"] == str(output_dir / "server-provenance.json")
    assert index_payload["server_provenance_signature"] == str(output_dir / "server-provenance.sig.json")


def test_vanguard_active_probe_reports_success(tmp_path):
    script_path = _write_mock_probe_server(tmp_path)
    probe_file = tmp_path / "probe-manifest.json"
    probe_file.write_text(
        json.dumps(
            {
                "version": 1,
                "protocolVersion": "2025-11-25",
                "probes": [
                    {
                        "probe_id": "status-probe",
                        "tool": "get_status",
                        "arguments": {},
                        "safety_class": "read_only_idempotent",
                        "expect_success": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "active-probe",
            "--server",
            f'"{pathlib.Path(sys.executable).as_posix()}" {script_path.as_posix()}',
            "--probe-file",
            str(probe_file),
        ],
    )

    assert result.exit_code == 0
    assert "Active Probe Report" in result.stdout
    assert "STATUS: PASS" in result.stdout


def test_vanguard_active_probe_json_output_reports_failure(tmp_path):
    script_path = _write_mock_probe_server(tmp_path)
    probe_file = tmp_path / "probe-manifest.json"
    probe_file.write_text(
        json.dumps(
            {
                "version": 1,
                "protocolVersion": "2025-11-25",
                "probes": [
                    {
                        "probe_id": "mutate-probe",
                        "tool": "mutate_state",
                        "arguments": {},
                        "safety_class": "read_only_idempotent",
                        "expect_success": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "active-probe",
            "--server",
            f'"{pathlib.Path(sys.executable).as_posix()}" {script_path.as_posix()}',
            "--probe-file",
            str(probe_file),
            "--json-output",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["passed"] is False
    assert payload["results"][0]["probe_id"] == "mutate-probe"


def test_vanguard_artifact_sign_writes_signature(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    signature_path = tmp_path / "server-artifact.sig.json"
    private_key_path = tmp_path / "supplier-key.pem"
    private_key_pem, signer_doc = signing.generate_signing_keypair("supplier-signer")
    private_key_path.write_bytes(private_key_pem)

    result = runner.invoke(
        app,
        [
            "artifact-sign",
            "--artifact-file",
            artifact_path.as_posix(),
            "--private-key",
            str(private_key_path),
            "--key-id",
            signer_doc["key_id"],
            "--supplier",
            "provnai",
            "--output",
            str(signature_path),
        ],
    )

    assert result.exit_code == 0
    assert signature_path.exists()
    payload = json.loads(signature_path.read_text(encoding="utf-8"))
    assert payload["supplier"] == "provnai"


def test_vanguard_server_verify_can_check_supplier_artifact_signature(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    artifact_signature_path = tmp_path / "server-artifact.sig.json"
    private_key_path = tmp_path / "supplier-key.pem"
    trust_key_path = tmp_path / "trusted-supplier-signer.json"
    private_key_pem, signer_doc = signing.generate_signing_keypair("supplier-signer")

    manifest_payload = server_integrity.build_server_manifest(
        [artifact_path.as_posix()],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")
    private_key_path.write_bytes(private_key_pem)
    trust_key_path.write_text(json.dumps({**signer_doc, "supplier": "provnai"}), encoding="utf-8")

    sign_result = runner.invoke(
        app,
        [
            "artifact-sign",
            "--artifact-file",
            artifact_path.as_posix(),
            "--private-key",
            str(private_key_path),
            "--key-id",
            signer_doc["key_id"],
            "--supplier",
            "provnai",
            "--output",
            str(artifact_signature_path),
        ],
    )
    assert sign_result.exit_code == 0

    verify_result = runner.invoke(
        app,
        [
            "server-verify",
            "--server",
            artifact_path.as_posix(),
            "--manifest-file",
            str(manifest_path),
            "--hash-executable",
            "--artifact-signature-file",
            str(artifact_signature_path),
            "--artifact-trust-key-file",
            str(trust_key_path),
            "--allowed-supplier-id",
            "provnai",
        ],
    )

    assert verify_result.exit_code == 0
    assert "Supplier artifact signature:" in verify_result.stdout


def test_vanguard_baseline_bundle_can_include_artifact_signature(tmp_path):
    initialize_file = tmp_path / "initialize.json"
    tools_file = tmp_path / "tools.json"
    artifact_signature_path = tmp_path / "server-artifact.sig.json"
    output_dir = tmp_path / "bundle"
    initialize_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "init-1",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "demo", "version": "1.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    tools_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "tools-1",
                "result": {
                    "tools": [{"name": "read_file", "description": "Read a file."}]
                },
            }
        ),
        encoding="utf-8",
    )
    artifact_signature_path.write_text(
        json.dumps(
            {
                "version": 1,
                "algorithm": "ed25519",
                "key_id": "supplier-signer",
                "file_name": "demo-server.bin",
                "artifact_sha256": "placeholder",
                "supplier": "provnai",
                "signature": "c2lnbmF0dXJlLW5vdC12ZXJpZmllZC1oZXJl",
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "baseline-bundle",
            "--server",
            "python -m demo_server",
            "--output-dir",
            str(output_dir),
            "--initialize-file",
            str(initialize_file),
            "--tools-file",
            str(tools_file),
            "--artifact-signature-file",
            str(artifact_signature_path),
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / supplier_signatures.SERVER_ARTIFACT_SIGNATURE).exists()
    index_payload = json.loads((output_dir / "baseline-bundle.json").read_text(encoding="utf-8"))
    assert index_payload["server_artifact_signature"] == str(output_dir / supplier_signatures.SERVER_ARTIFACT_SIGNATURE)


def test_vanguard_server_verify_can_check_sigstore_bundle(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE
    trust_key_path = tmp_path / "trusted-sigstore-hint-signer.json"
    private_key_pem, signer_doc = signing.generate_signing_keypair("sigstore-hint")
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())
    signature = private_key.sign(digest_bytes)

    manifest_payload = server_integrity.build_server_manifest(
        [artifact_path.as_posix()],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")
    trust_key_path.write_text(json.dumps(signer_doc), encoding="utf-8")
    bundle_path.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "publicKeyIdentifier": {"hint": signer_doc["key_id"]},
                },
                "messageSignature": {
                    "messageDigest": {
                        "algorithm": "SHA2_256",
                        "digest": base64.b64encode(digest_bytes).decode("ascii"),
                    },
                    "signature": base64.b64encode(signature).decode("ascii"),
                },
            }
        ),
        encoding="utf-8",
    )

    verify_result = runner.invoke(
        app,
        [
            "server-verify",
            "--server",
            artifact_path.as_posix(),
            "--manifest-file",
            str(manifest_path),
            "--hash-executable",
            "--sigstore-bundle-file",
            str(bundle_path),
            "--sigstore-hint-trust-key-file",
            str(trust_key_path),
        ],
    )

    assert verify_result.exit_code == 0
    assert "Sigstore bundle:" in verify_result.stdout


def test_vanguard_server_verify_can_check_sigstore_bundle_identity(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_sigstore_identity_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
    )
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))

    manifest_payload = server_integrity.build_server_manifest(
        [artifact_path.as_posix()],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")
    bundle_path.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
                    }
                },
                "messageSignature": {
                    "messageDigest": {
                        "algorithm": "SHA2_256",
                        "digest": base64.b64encode(digest_bytes).decode("ascii"),
                    },
                    "signature": base64.b64encode(signature).decode("ascii"),
                },
            }
        ),
        encoding="utf-8",
    )

    verify_result = runner.invoke(
        app,
        [
            "server-verify",
            "--server",
            artifact_path.as_posix(),
            "--manifest-file",
            str(manifest_path),
            "--hash-executable",
            "--sigstore-bundle-file",
            str(bundle_path),
            "--allowed-sigstore-cert-identity",
            "https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
            "--allowed-sigstore-oidc-issuer",
            "https://token.actions.githubusercontent.com",
        ],
    )

    assert verify_result.exit_code == 0
    assert "Sigstore bundle:" in verify_result.stdout


def test_vanguard_server_verify_can_require_sigstore_transparency_promise(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_sigstore_identity_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
    )
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))

    manifest_payload = server_integrity.build_server_manifest(
        [artifact_path.as_posix()],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")
    bundle_path.write_text(
        json.dumps(
            _build_sigstore_bundle_with_tlog(
                cert=cert,
                digest_bytes=digest_bytes,
                signature=signature,
                include_promise=True,
            )
        ),
        encoding="utf-8",
    )

    verify_result = runner.invoke(
        app,
        [
            "server-verify",
            "--server",
            artifact_path.as_posix(),
            "--manifest-file",
            str(manifest_path),
            "--hash-executable",
            "--sigstore-bundle-file",
            str(bundle_path),
            "--allowed-sigstore-cert-identity",
            "https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
            "--allowed-sigstore-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--sigstore-tlog-policy",
            "promise",
        ],
    )

    assert verify_result.exit_code == 0
    assert "Sigstore bundle:" in verify_result.stdout


def test_vanguard_server_verify_can_check_sigstore_fulcio_claims_and_tlog_key(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())
    tlog_key_id = base64.b64encode(b"trusted-rekor-key").decode("ascii")

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_sigstore_identity_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
        fulcio_claims={
            sigstore_bundle.FULCIO_BUILD_SIGNER_URI_OID: "https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
            sigstore_bundle.FULCIO_SOURCE_REPOSITORY_URI_OID: "https://github.com/provnai/McpVanguard",
            sigstore_bundle.FULCIO_SOURCE_REPOSITORY_REF_OID: "refs/heads/main",
            sigstore_bundle.FULCIO_SOURCE_REPOSITORY_DIGEST_OID: "sha1:abc123",
            sigstore_bundle.FULCIO_BUILD_TRIGGER_OID: "push",
        },
    )
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))

    manifest_payload = server_integrity.build_server_manifest(
        [artifact_path.as_posix()],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")
    bundle_path.write_text(
        json.dumps(
            _build_sigstore_bundle_with_tlog(
                cert=cert,
                digest_bytes=digest_bytes,
                signature=signature,
                include_promise=True,
                tlog_key_id=tlog_key_id,
            )
        ),
        encoding="utf-8",
    )

    verify_result = runner.invoke(
        app,
        [
            "server-verify",
            "--server",
            artifact_path.as_posix(),
            "--manifest-file",
            str(manifest_path),
            "--hash-executable",
            "--sigstore-bundle-file",
            str(bundle_path),
            "--allowed-sigstore-cert-identity",
            "https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
            "--allowed-sigstore-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--allowed-sigstore-build-signer-uri",
            "https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
            "--allowed-sigstore-source-repository",
            "https://github.com/provnai/McpVanguard",
            "--allowed-sigstore-source-ref",
            "refs/heads/main",
            "--allowed-sigstore-source-digest",
            "sha1:abc123",
            "--allowed-sigstore-build-trigger",
            "push",
            "--allowed-sigstore-tlog-key-id",
            tlog_key_id,
            "--sigstore-tlog-policy",
            "promise",
        ],
    )

    assert verify_result.exit_code == 0
    assert "Sigstore bundle:" in verify_result.stdout


def test_vanguard_server_verify_can_check_sigstore_github_claims(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_sigstore_identity_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
        fulcio_claims={
            sigstore_bundle.FULCIO_GITHUB_WORKFLOW_REPOSITORY_OID: "provnai/McpVanguard",
            sigstore_bundle.FULCIO_GITHUB_WORKFLOW_REF_OID: "refs/heads/main",
            sigstore_bundle.FULCIO_GITHUB_WORKFLOW_SHA_OID: "abc123",
            sigstore_bundle.FULCIO_GITHUB_WORKFLOW_TRIGGER_OID: "push",
            sigstore_bundle.FULCIO_GITHUB_WORKFLOW_NAME_OID: "release",
        },
    )
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))

    manifest_payload = server_integrity.build_server_manifest(
        [artifact_path.as_posix()],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")
    bundle_path.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
                    }
                },
                "messageSignature": {
                    "messageDigest": {
                        "algorithm": "SHA2_256",
                        "digest": base64.b64encode(digest_bytes).decode("ascii"),
                    },
                    "signature": base64.b64encode(signature).decode("ascii"),
                },
            }
        ),
        encoding="utf-8",
    )

    verify_result = runner.invoke(
        app,
        [
            "server-verify",
            "--server",
            artifact_path.as_posix(),
            "--manifest-file",
            str(manifest_path),
            "--hash-executable",
            "--sigstore-bundle-file",
            str(bundle_path),
            "--sigstore-github-repository",
            "provnai/McpVanguard",
            "--sigstore-github-ref",
            "refs/heads/main",
            "--sigstore-github-sha",
            "abc123",
            "--sigstore-github-trigger",
            "push",
            "--sigstore-github-workflow-name",
            "release",
        ],
    )

    assert verify_result.exit_code == 0
    assert "Sigstore bundle:" in verify_result.stdout


def test_vanguard_baseline_bundle_can_include_sigstore_bundle(tmp_path):
    initialize_file = tmp_path / "initialize.json"
    tools_file = tmp_path / "tools.json"
    sigstore_bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE
    output_dir = tmp_path / "bundle"
    initialize_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "init-1",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "demo", "version": "1.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    tools_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "tools-1",
                "result": {
                    "tools": [{"name": "read_file", "description": "Read a file."}]
                },
            }
        ),
        encoding="utf-8",
    )
    sigstore_bundle_path.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {"publicKeyIdentifier": {"hint": "sigstore-hint"}},
                "messageSignature": {
                    "messageDigest": {
                        "algorithm": "SHA2_256",
                        "digest": base64.b64encode(b"0" * 32).decode("ascii"),
                    },
                    "signature": base64.b64encode(b"1" * 64).decode("ascii"),
                },
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "baseline-bundle",
            "--server",
            "python -m demo_server",
            "--output-dir",
            str(output_dir),
            "--initialize-file",
            str(initialize_file),
            "--tools-file",
            str(tools_file),
            "--sigstore-bundle-file",
            str(sigstore_bundle_path),
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / sigstore_bundle.SERVER_SIGSTORE_BUNDLE).exists()
    index_payload = json.loads((output_dir / "baseline-bundle.json").read_text(encoding="utf-8"))
    assert index_payload["server_sigstore_bundle"] == str(output_dir / sigstore_bundle.SERVER_SIGSTORE_BUNDLE)


def test_vanguard_capability_sign_manifest_writes_signature(tmp_path):
    manifest_path = tmp_path / "capability-manifest.json"
    signature_path = tmp_path / "capability-manifest.sig.json"
    private_key_path = tmp_path / "capability-key.pem"
    private_key_pem, signer_doc = signing.generate_signing_keypair("capability-signer")
    manifest_path.write_text(
        json.dumps(
            capability_fingerprint.build_capability_manifest(
                tools_payload={
                    "jsonrpc": "2.0",
                    "id": "tools-1",
                    "result": {"tools": [{"name": "read_file", "description": "Read a file."}]},
                }
            )
        ),
        encoding="utf-8",
    )
    private_key_path.write_bytes(private_key_pem)

    result = runner.invoke(
        app,
        [
            "capability-sign-manifest",
            "--manifest-file",
            str(manifest_path),
            "--private-key",
            str(private_key_path),
            "--key-id",
            signer_doc["key_id"],
            "--output",
            str(signature_path),
        ],
    )

    assert result.exit_code == 0
    assert signature_path.exists()
    assert "Wrote capability manifest signature" in result.stdout


def test_vanguard_capability_verify_can_check_signature(tmp_path):
    manifest_path = tmp_path / "capability-manifest.json"
    signature_path = tmp_path / "capability-manifest.sig.json"
    trust_key_path = tmp_path / "trusted-capability-signer.json"
    private_key_pem, signer_doc = signing.generate_signing_keypair("capability-signer")

    manifest_payload = capability_fingerprint.build_capability_manifest(
        tools_payload={
            "jsonrpc": "2.0",
            "id": "tools-1",
            "result": {"tools": [{"name": "read_file", "description": "Read a file."}]},
        }
    )
    manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")
    signature_doc = capability_fingerprint.sign_capability_manifest(
        manifest_payload,
        private_key_pem,
        signer_doc["key_id"],
    )
    signature_path.write_text(json.dumps(signature_doc), encoding="utf-8")
    trust_key_path.write_text(json.dumps(signer_doc), encoding="utf-8")

    verify_result = runner.invoke(
        app,
        [
            "capability-verify",
            "--manifest-file",
            str(manifest_path),
            "--tools-file",
            str(_write_tools_payload(tmp_path, "read_file")),
            "--check-signature",
            "--signature-file",
            str(signature_path),
            "--trust-key-file",
            str(trust_key_path),
        ],
    )

    assert verify_result.exit_code == 0
    assert "Signature:" in verify_result.stdout
    assert "STATUS: MATCH" in verify_result.stdout


def test_vanguard_conformance_server_invokes_official_runner(tmp_path):
    fake_result = conformance.ConformanceResult(
        command=[
            "npx",
            "@modelcontextprotocol/conformance",
            "server",
            "--url",
            "http://127.0.0.1:8080/mcp",
            "--suite",
            "active",
        ],
        returncode=0,
        stdout="checks passed",
        stderr="",
    )

    with patch("core.cli.conformance.run_server_conformance", return_value=fake_result) as mocked:
        result = runner.invoke(
            app,
            [
                "conformance-server",
                "--url",
                "http://127.0.0.1:8080/mcp",
            ],
        )

    assert result.exit_code == 0
    assert "MCP Conformance Run" in result.stdout
    assert "checks passed" in result.stdout
    mocked.assert_called_once()


def test_vanguard_conformance_server_propagates_failures(tmp_path):
    fake_result = conformance.ConformanceResult(
        command=[
            "npx",
            "@modelcontextprotocol/conformance",
            "server",
            "--url",
            "http://127.0.0.1:8080/mcp",
            "--suite",
            "active",
        ],
        returncode=2,
        stdout="",
        stderr="failure output",
    )

    with patch("core.cli.conformance.run_server_conformance", return_value=fake_result):
        result = runner.invoke(
            app,
            [
                "conformance-server",
                "--url",
                "http://127.0.0.1:8080/mcp",
            ],
        )

    assert result.exit_code == 2
    assert "failure output" in result.stdout


def test_vanguard_baseline_bundle_can_sign_capability_manifest(tmp_path):
    initialize_file = tmp_path / "initialize.json"
    tools_file = tmp_path / "tools.json"
    output_dir = tmp_path / "bundle"
    private_key_path = tmp_path / "capability-key.pem"
    private_key_pem, signer_doc = signing.generate_signing_keypair("capability-signer")
    initialize_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "init-1",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "demo", "version": "1.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    tools_file.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "tools-1",
                "result": {"tools": [{"name": "read_file", "description": "Read a file."}]},
            }
        ),
        encoding="utf-8",
    )
    private_key_path.write_bytes(private_key_pem)

    result = runner.invoke(
        app,
        [
            "baseline-bundle",
            "--server",
            "python -m demo_server",
            "--output-dir",
            str(output_dir),
            "--initialize-file",
            str(initialize_file),
            "--tools-file",
            str(tools_file),
            "--capability-private-key",
            str(private_key_path),
            "--capability-key-id",
            signer_doc["key_id"],
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / capability_fingerprint.CAPABILITY_MANIFEST_SIGNATURE).exists()
    index_payload = json.loads((output_dir / "baseline-bundle.json").read_text(encoding="utf-8"))
    assert index_payload["capability_manifest_signature"] == str(output_dir / capability_fingerprint.CAPABILITY_MANIFEST_SIGNATURE)


def _sha256_bytes(payload: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(payload)
    return digest.finalize()


def _write_tools_payload(tmp_path, tool_name: str):
    tools_path = tmp_path / f"{tool_name}-tools.json"
    tools_path.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "tools-1",
                "result": {"tools": [{"name": tool_name, "description": "Read a file."}]},
            }
        ),
        encoding="utf-8",
    )
    return tools_path


def _build_sigstore_identity_cert(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    san_uri: str,
    oidc_issuer: str,
    fulcio_claims: dict[object, str] | None = None,
) -> x509.Certificate:
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-test")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-test-ca")]))
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]),
            critical=True,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                sigstore_bundle.FULCIO_OIDC_ISSUER_OID,
                _der_encode_utf8_string(oidc_issuer),
            ),
            critical=False,
        )
    )
    for oid, value in (fulcio_claims or {}).items():
        builder = builder.add_extension(
            x509.UnrecognizedExtension(oid, _der_encode_utf8_string(value)),
            critical=False,
        )
    return builder.sign(private_key, hashes.SHA256())


def _der_encode_utf8_string(value: str) -> bytes:
    payload = value.encode("utf-8")
    if len(payload) < 0x80:
        return bytes([0x0C, len(payload)]) + payload
    length_bytes = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0x0C, 0x80 | len(length_bytes)]) + length_bytes + payload


def _build_sigstore_bundle_with_tlog(
    *,
    cert: x509.Certificate,
    digest_bytes: bytes,
    signature: bytes,
    include_promise: bool = False,
    include_proof: bool = False,
    tlog_key_id: str | None = None,
) -> dict:
    canonicalized_body = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": digest_bytes.hex()}},
            "signature": {
                "content": base64.b64encode(signature).decode("ascii"),
                "publicKey": {"content": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")},
            },
        },
    }
    tlog_entry: dict[str, object] = {
        "logIndex": "123",
        "logId": {"keyId": tlog_key_id or base64.b64encode(b"rekor-log-key").decode("ascii")},
        "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
        "integratedTime": str(int(dt.datetime.now(dt.timezone.utc).timestamp())),
        "canonicalizedBody": base64.b64encode(
            json.dumps(canonicalized_body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii"),
    }
    if include_promise:
        tlog_entry["inclusionPromise"] = {
            "signedEntryTimestamp": base64.b64encode(b"set-bytes").decode("ascii")
        }
    if include_proof:
        tlog_entry["inclusionProof"] = {
            "logIndex": "1",
            "rootHash": base64.b64encode(b"root-hash").decode("ascii"),
            "treeSize": "2",
            "hashes": [base64.b64encode(b"proof-hash").decode("ascii")],
            "checkpoint": {"envelope": "rekor.sigstore.dev - test\n2\nroot\n\n-sig-\n"},
        }

    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")},
            "tlogEntries": [tlog_entry],
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(digest_bytes).decode("ascii"),
            },
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }
