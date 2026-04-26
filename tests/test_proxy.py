"""
tests/test_proxy.py — Integration tests for the VanguardProxy.
Verifies orchestration of Layer 1 (Rules), Layer 2 (Semantic), and Layer 3 (Behavioral).
"""

import asyncio
import base64
import datetime as dt
import json
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from core.models import AuthPrincipal
from core.proxy import VanguardProxy, ProxyConfig
from core.models import InspectionResult, RuleMatch
from core.risk import RiskEngine
from core import capability_fingerprint, provenance, server_integrity, signing, sigstore_bundle, supplier_signatures

@pytest.fixture
def mock_config():
    config = ProxyConfig()
    config.rules_dir = "rules"
    config.semantic_enabled = True
    config.behavioral_enabled = True
    return config

@pytest.fixture
def proxy(mock_config):
    p = VanguardProxy(server_command=["python", "-c", "print('hello')"], config=mock_config)
    # Set a dummy session for tests that need it (Layer 3)
    from core.session import SessionState
    p._session = SessionState(session_id="test-session")
    return p


@pytest.fixture(autouse=True)
def clear_risk_engine():
    engine = RiskEngine.get_instance()
    engine._states.clear()
    yield
    engine._states.clear()


def test_proxy_run_creates_session_with_principal(mock_config):
    principal = AuthPrincipal(principal_id="api_key:test", auth_type="api_key")
    proxy = VanguardProxy(
        server_command=["python", "-c", "print('hello')"],
        config=mock_config,
        principal=principal,
    )

    async def fake_shutdown():
        return None

    async def fake_stderr():
        return None

    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_subproc, \
         patch.object(proxy, "_pump_agent_to_server", new=AsyncMock(return_value=None)), \
         patch.object(proxy, "_pump_server_to_agent", new=AsyncMock(return_value=None)), \
         patch.object(proxy, "_pump_server_stderr", new=fake_stderr), \
         patch.object(proxy, "_shutdown", new=fake_shutdown):
        process = MagicMock()
        process.pid = 123
        process.stdin = None
        process.stdout = MagicMock()
        process.stderr = MagicMock()
        process.returncode = 0
        mock_subproc.return_value = process

        asyncio.run(proxy.run())

    assert proxy._session is not None
    assert proxy._session.principal is not None
    assert proxy._session.principal.principal_id == "api_key:test"

@pytest.mark.asyncio
async def test_proxy_blocks_layer_1_rules(proxy):
    # Layer 1 should block path traversal immediately
    msg = {
        "jsonrpc": "2.0",
        "id": "123",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}
    }
    
    result = await proxy._inspect_message(msg)
    
    assert not result.allowed
    assert result.action == "BLOCK"
    # Layer 1 triggers first (either via SafeZone or Regex rules)
    assert any(r.rule_id.startswith("FS-") or r.rule_id.startswith("PRIV-") or "SAFEZONE" in r.rule_id for r in result.rule_matches)

@pytest.mark.asyncio
async def test_proxy_blocks_layer_2_semantic(proxy):
    # Mock Layer 1 to ALLOW
    # Mock Layer 2 to BLOCK
    malicious_result = InspectionResult(
        allowed=False,
        action="BLOCK",
        layer_triggered=2,
        rule_matches=[RuleMatch(rule_id="SEM-BLOCK", severity="HIGH")],
        semantic_score=0.9,
        block_reason="Semantic detection"
    )
    
    with patch("core.semantic.score_intent", new_callable=AsyncMock) as mock_sem:
        mock_sem.return_value = malicious_result
        
        msg = {
            "jsonrpc": "2.0",
            "id": "123",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "benign.txt"}}
        }
        
        # We need to ensure Layer 1 doesn't block it
        with patch.object(proxy.rules_engine, "check", return_value=InspectionResult.allow()):
            result = await proxy._inspect_message(msg)
            
            assert not result.allowed
            assert result.action == "BLOCK"
            assert result.layer_triggered == 2
            assert result.semantic_score == 0.9

@pytest.mark.asyncio
async def test_proxy_blocks_layer_3_behavioral(proxy):
    # Mock Layer 3 to BLOCK
    beh_result = InspectionResult(
        allowed=False,
        action="BLOCK",
        layer_triggered=3,
        rule_matches=[RuleMatch(rule_id="BEH-001", severity="HIGH")],
        block_reason="Behavioral detection"
    )
    
    with patch("core.behavioral.inspect_request") as mock_beh:
        mock_beh.return_value = beh_result
        
        msg = {
            "jsonrpc": "2.0",
            "id": "123",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "benign.txt"}}
        }
        
        with patch.object(proxy.rules_engine, "check", return_value=InspectionResult.allow()):
            result = await proxy._inspect_message(msg)
            
            assert not result.allowed
            assert result.action == "BLOCK"
            assert result.layer_triggered == 3

@pytest.mark.asyncio
async def test_proxy_allows_clean_request(proxy):
    # All layers return ALLOW/None
    msg = {
        "jsonrpc": "2.0",
        "id": "123",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "README.md"}}
    }
    
    with patch.object(proxy.rules_engine, "check", return_value=InspectionResult.allow()), \
         patch("core.behavioral.inspect_request", return_value=None), \
         patch("core.semantic.score_intent", new_callable=AsyncMock, return_value=None):
        
        result = await proxy._inspect_message(msg)
        assert result.allowed
        assert result.action == "ALLOW"


@pytest.mark.asyncio
async def test_proxy_blocks_destructive_tool_without_required_role(mock_config):
    mock_config.required_destructive_roles = ["admin"]
    proxy = VanguardProxy(
        server_command=["python", "-c", "print('hello')"],
        config=mock_config,
        principal=AuthPrincipal(principal_id="api_key:test", auth_type="api_key", roles=["authenticated"]),
    )

    msg = {
        "jsonrpc": "2.0",
        "id": "123",
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes.txt", "content": "hi"}},
    }

    result = await proxy._inspect_message(msg)

    assert result.allowed is False
    assert result.action == "BLOCK"
    assert result.rule_matches[0].rule_id == "VANGUARD-AUTH-ROLE-001"


@pytest.mark.asyncio
async def test_proxy_allows_destructive_tool_with_required_scope(mock_config):
    mock_config.required_destructive_scopes = ["tools.write"]
    proxy = VanguardProxy(
        server_command=["python", "-c", "print('hello')"],
        config=mock_config,
        principal=AuthPrincipal(
            principal_id="bearer:user-123",
            auth_type="bearer",
            roles=["authenticated"],
            attributes={"token_scope": ["tools.read", "tools.write"]},
        ),
    )

    msg = {
        "jsonrpc": "2.0",
        "id": "123",
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes.txt", "content": "hi"}},
    }

    with patch.object(proxy.rules_engine, "check", return_value=InspectionResult.allow()), \
         patch("core.behavioral.inspect_request", return_value=None), \
         patch("core.semantic.score_intent", new_callable=AsyncMock, return_value=None):
        result = await proxy._inspect_message(msg)

    assert result.allowed is True
    assert result.action == "ALLOW"


@pytest.mark.asyncio
async def test_proxy_warns_on_destructive_tool_when_principal_has_auth_warnings(mock_config):
    mock_config.auth_warning_tool_policy = "warn"
    proxy = VanguardProxy(
        server_command=["python", "-c", "print('hello')"],
        config=mock_config,
        principal=AuthPrincipal(
            principal_id="bearer:user-123",
            auth_type="bearer",
            roles=["authenticated"],
            attributes={"auth_warnings": ["audience mismatch"]},
        ),
    )

    msg = {
        "jsonrpc": "2.0",
        "id": "123",
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "notes.txt", "content": "hi"}},
    }

    result = await proxy._inspect_message(msg)

    assert result.allowed is True
    assert result.action == "WARN"
    assert result.rule_matches[0].rule_id == "VANGUARD-AUTH-WARNING-001"


def test_proxy_warns_on_server_manifest_drift(tmp_path, mock_config):
    manifest_path = tmp_path / "server-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
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
                    "approval_status": "approved",
                    "trust_level": "internal",
                },
            }
        ),
        encoding="utf-8",
    )

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_policy = "warn"
    proxy = VanguardProxy(server_command=["python", "-m", "server_b"], config=mock_config)

    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with patch.object(proxy.audit, "info") as mock_audit:
        proxy._check_server_integrity_baseline()

    mock_audit.assert_called_once()
    assert "Upstream server drift detected before launch" in mock_audit.call_args.args[0]


def test_proxy_audit_includes_current_risk_context_in_json_logs(mock_config):
    mock_config.audit_format = "json"
    proxy = VanguardProxy(server_command=["python", "-m", "server_a"], config=mock_config)

    from core.session import SessionState

    proxy._session = SessionState(session_id="risk-audit-session", server_id=proxy._server_id)
    proxy.risk_engine.record_event(proxy._session.session_id, proxy._server_id, "RULE_BLOCK")

    with patch.object(proxy.audit, "info") as mock_audit:
        proxy._record_server_integrity_event(
            action="WARN",
            rule_id="VANGUARD-RISK-CHECK",
            reason="risk audit check",
        )

    mock_audit.assert_called_once()
    payload = json.loads(mock_audit.call_args.args[0])
    assert payload["risk_score"] == 80.0
    assert payload["risk_enforcement"] == "AUDIT"


def test_proxy_blocks_on_server_manifest_drift(tmp_path, mock_config):
    manifest_path = tmp_path / "server-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
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
                    "approval_status": "approved",
                    "trust_level": "internal",
                },
            }
        ),
        encoding="utf-8",
    )

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_policy = "block"
    proxy = VanguardProxy(server_command=["python", "-m", "server_b"], config=mock_config)

    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._check_server_integrity_baseline()

    assert "Upstream server drift detected before launch" in str(excinfo.value)


def test_proxy_blocks_on_unsigned_server_manifest_when_trust_policy_enabled(tmp_path, mock_config):
    manifest_path = tmp_path / "server-manifest.json"
    server_integrity.write_server_manifest(
        manifest_path,
        server_integrity.build_server_manifest(
            ["python", "-m", "server_a"],
            approval_status="approved",
            trust_level="internal",
        ),
    )

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_trust_policy = "block"
    proxy = VanguardProxy(server_command=["python", "-m", "server_a"], config=mock_config)

    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._check_server_integrity_baseline()

    assert "unsigned" in str(excinfo.value).lower()


def test_proxy_blocks_on_revoked_signed_server_manifest(tmp_path, mock_config, monkeypatch):
    manifest_path = tmp_path / "server-manifest.json"
    signature_path = tmp_path / "server-manifest.sig.json"

    manifest = server_integrity.build_server_manifest(
        ["python", "-m", "server_a"],
        approval_status="revoked",
        trust_level="third_party",
    )
    server_integrity.write_server_manifest(manifest_path, manifest)

    private_key_pem, signer_doc = signing.generate_signing_keypair("server-baseline-signer")
    signature_doc = server_integrity.sign_server_manifest(manifest, private_key_pem, "server-baseline-signer")
    server_integrity.write_server_manifest_signature(signature_path, signature_doc)

    trust_signer_file = tmp_path / "trusted-server-signer.json"
    trust_signer_file.write_text(json.dumps(signer_doc), encoding="utf-8")
    monkeypatch.setenv("VANGUARD_TRUSTED_SERVER_SIGNERS_FILE", str(trust_signer_file))

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_signature_file = str(signature_path)
    mock_config.server_trust_policy = "block"
    proxy = VanguardProxy(server_command=["python", "-m", "server_a"], config=mock_config)

    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._check_server_integrity_baseline()

    assert "revoked" in str(excinfo.value).lower()


def test_proxy_blocks_on_invalid_provenance_builder(tmp_path, mock_config, monkeypatch):
    manifest_path = tmp_path / "server-manifest.json"
    signature_path = tmp_path / "server-manifest.sig.json"
    provenance_path = tmp_path / "server-provenance.json"
    provenance_signature_path = tmp_path / "server-provenance.sig.json"

    manifest = server_integrity.build_server_manifest(
        ["python", "-m", "server_a"],
        approval_status="approved",
        trust_level="internal",
    )
    manifest["executable"]["sha256"] = "d" * 64
    server_integrity.write_server_manifest(manifest_path, manifest)

    server_private_key_pem, server_signer_doc = signing.generate_signing_keypair("server-baseline-signer")
    server_signature_doc = server_integrity.sign_server_manifest(manifest, server_private_key_pem, "server-baseline-signer")
    server_integrity.write_server_manifest_signature(signature_path, server_signature_doc)

    provenance_doc = {
        "_type": provenance.PROVENANCE_STATEMENT_TYPE,
        "subject": [{"name": "server_a", "digest": {"sha256": "d" * 64}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"runDetails": {"builder": {"id": "https://builder.example/untrusted"}}},
    }
    provenance_path.write_text(json.dumps(provenance_doc), encoding="utf-8")
    provenance_private_key_pem, provenance_signer_doc = signing.generate_signing_keypair("provenance-signer")
    provenance_signature_doc = provenance.sign_provenance(provenance_doc, provenance_private_key_pem, "provenance-signer")
    provenance.write_provenance_signature(provenance_signature_path, provenance_signature_doc)

    trust_signer_file = tmp_path / "trusted-server-signer.json"
    trust_signer_file.write_text(json.dumps(server_signer_doc), encoding="utf-8")
    provenance_signer_file = tmp_path / "trusted-provenance-signer.json"
    provenance_signer_file.write_text(json.dumps(provenance_signer_doc), encoding="utf-8")
    monkeypatch.setenv("VANGUARD_TRUSTED_SERVER_SIGNERS_FILE", str(trust_signer_file))
    monkeypatch.setenv("VANGUARD_TRUSTED_PROVENANCE_SIGNERS_FILE", str(provenance_signer_file))

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_signature_file = str(signature_path)
    mock_config.server_trust_policy = "block"
    mock_config.server_provenance_file = str(provenance_path)
    mock_config.server_provenance_signature_file = str(provenance_signature_path)
    mock_config.server_provenance_policy = "block"
    mock_config.required_provenance_builders = ["https://builder.example/gha"]
    proxy = VanguardProxy(server_command=["python", "-m", "server_a"], config=mock_config)

    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with patch("core.server_integrity.build_server_manifest", return_value=manifest):
        with pytest.raises(RuntimeError) as excinfo:
            proxy._check_server_integrity_baseline()

    assert "builder.id" in str(excinfo.value)


def test_proxy_blocks_on_disallowed_supplier_signature(tmp_path, mock_config, monkeypatch):
    executable_path = tmp_path / "demo-server.bin"
    executable_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    signature_path = tmp_path / "server-manifest.sig.json"
    artifact_signature_path = tmp_path / "server-artifact.sig.json"

    manifest = server_integrity.build_server_manifest(
        [str(executable_path)],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    server_integrity.write_server_manifest(manifest_path, manifest)

    server_private_key_pem, server_signer_doc = signing.generate_signing_keypair("server-baseline-signer")
    server_signature_doc = server_integrity.sign_server_manifest(manifest, server_private_key_pem, "server-baseline-signer")
    server_integrity.write_server_manifest_signature(signature_path, server_signature_doc)

    artifact_private_key_pem, artifact_signer_doc = signing.generate_signing_keypair("supplier-signer")
    artifact_signature_doc = supplier_signatures.sign_artifact(
        executable_path,
        artifact_private_key_pem,
        "supplier-signer",
        supplier="othercorp",
    )
    supplier_signatures.write_artifact_signature(artifact_signature_path, artifact_signature_doc)

    trust_signer_file = tmp_path / "trusted-server-signer.json"
    trust_signer_file.write_text(json.dumps(server_signer_doc), encoding="utf-8")
    artifact_signer_file = tmp_path / "trusted-supplier-signer.json"
    artifact_signer_file.write_text(json.dumps({**artifact_signer_doc, "supplier": "othercorp"}), encoding="utf-8")
    monkeypatch.setenv("VANGUARD_TRUSTED_SERVER_SIGNERS_FILE", str(trust_signer_file))
    monkeypatch.setenv("VANGUARD_TRUSTED_SUPPLIER_SIGNERS_FILE", str(artifact_signer_file))

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_signature_file = str(signature_path)
    mock_config.server_trust_policy = "block"
    mock_config.server_manifest_hash_executable = True
    mock_config.server_artifact_signature_file = str(artifact_signature_path)
    mock_config.server_artifact_policy = "block"
    mock_config.allowed_supplier_ids = ["provnai"]
    proxy = VanguardProxy(server_command=[str(executable_path)], config=mock_config)

    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._check_server_integrity_baseline()

    assert "allowed supplier set" in str(excinfo.value)


def test_proxy_blocks_on_invalid_sigstore_bundle(tmp_path, mock_config, monkeypatch):
    executable_path = tmp_path / "demo-server.bin"
    executable_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE

    manifest = server_integrity.build_server_manifest(
        [str(executable_path)],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    server_integrity.write_server_manifest(manifest_path, manifest)

    private_key = ec.generate_private_key(ec.SECP256R1())
    digest = hashes.Hash(hashes.SHA256())
    digest.update(executable_path.read_bytes())
    digest_bytes = digest.finalize()
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-test")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-test-ca")]))
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    bundle_path.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
                    },
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

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_hash_executable = True
    mock_config.server_sigstore_bundle_file = str(bundle_path)
    mock_config.server_sigstore_policy = "block"
    mock_config.allowed_sigstore_cert_fingerprints = ["00" * 32]

    proxy = VanguardProxy(server_command=[str(executable_path)], config=mock_config)

    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._check_server_integrity_baseline()

    assert "fingerprint" in str(excinfo.value).lower()


def test_proxy_blocks_on_sigstore_oidc_identity_mismatch(tmp_path, mock_config):
    executable_path = tmp_path / "demo-server.bin"
    executable_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE

    manifest = server_integrity.build_server_manifest(
        [str(executable_path)],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    server_integrity.write_server_manifest(manifest_path, manifest)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(executable_path.read_bytes())
    digest_bytes = digest.finalize()
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    cert = _build_sigstore_identity_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
    )
    bundle_path.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
                    },
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

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_hash_executable = True
    mock_config.server_sigstore_bundle_file = str(bundle_path)
    mock_config.server_sigstore_policy = "block"
    mock_config.allowed_sigstore_identities = [
        "https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main"
    ]
    mock_config.allowed_sigstore_oidc_issuers = ["https://github.com/login/oauth"]

    proxy = VanguardProxy(server_command=[str(executable_path)], config=mock_config)
    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._check_server_integrity_baseline()

    assert "oidc issuer" in str(excinfo.value).lower()


def test_proxy_blocks_on_missing_sigstore_tlog_when_required(tmp_path, mock_config):
    executable_path = tmp_path / "demo-server.bin"
    executable_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE

    manifest = server_integrity.build_server_manifest(
        [str(executable_path)],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    server_integrity.write_server_manifest(manifest_path, manifest)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(executable_path.read_bytes())
    digest_bytes = digest.finalize()
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    cert = _build_sigstore_identity_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
    )
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

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_hash_executable = True
    mock_config.server_sigstore_bundle_file = str(bundle_path)
    mock_config.server_sigstore_policy = "block"
    mock_config.allowed_sigstore_identities = [
        "https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main"
    ]
    mock_config.allowed_sigstore_oidc_issuers = ["https://token.actions.githubusercontent.com"]
    mock_config.sigstore_tlog_policy = "entry"

    proxy = VanguardProxy(server_command=[str(executable_path)], config=mock_config)
    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._check_server_integrity_baseline()

    assert "transparency log entries" in str(excinfo.value).lower()


def test_proxy_blocks_on_sigstore_fulcio_claim_mismatch(tmp_path, mock_config):
    executable_path = tmp_path / "demo-server.bin"
    executable_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE

    manifest = server_integrity.build_server_manifest(
        [str(executable_path)],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    server_integrity.write_server_manifest(manifest_path, manifest)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(executable_path.read_bytes())
    digest_bytes = digest.finalize()
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    cert = _build_sigstore_identity_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
        fulcio_claims={
            sigstore_bundle.FULCIO_SOURCE_REPOSITORY_URI_OID: "https://github.com/provnai/McpVanguard",
        },
    )
    bundle_path.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
                    },
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

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_hash_executable = True
    mock_config.server_sigstore_bundle_file = str(bundle_path)
    mock_config.server_sigstore_policy = "block"
    mock_config.allowed_sigstore_source_repositories = ["https://github.com/other/repo"]

    proxy = VanguardProxy(server_command=[str(executable_path)], config=mock_config)
    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._check_server_integrity_baseline()

    assert "source repository uri" in str(excinfo.value).lower()


def test_proxy_blocks_on_untrusted_sigstore_tlog_key_id(tmp_path, mock_config):
    executable_path = tmp_path / "demo-server.bin"
    executable_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE

    manifest = server_integrity.build_server_manifest(
        [str(executable_path)],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    server_integrity.write_server_manifest(manifest_path, manifest)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(executable_path.read_bytes())
    digest_bytes = digest.finalize()
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    cert = _build_sigstore_identity_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
    )
    tlog_key_id = base64.b64encode(b"unexpected-rekor-key").decode("ascii")
    bundle_path.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
                    },
                    "tlogEntries": [
                        {
                            "logIndex": "123",
                            "logId": {"keyId": tlog_key_id},
                            "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                            "integratedTime": str(int(dt.datetime.now(dt.timezone.utc).timestamp())),
                            "canonicalizedBody": base64.b64encode(
                                json.dumps(
                                    {
                                        "apiVersion": "0.0.1",
                                        "kind": "hashedrekord",
                                        "spec": {
                                            "data": {"hash": {"algorithm": "sha256", "value": digest_bytes.hex()}},
                                            "signature": {
                                                "content": base64.b64encode(signature).decode("ascii"),
                                                "publicKey": {
                                                    "content": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                                                },
                                            },
                                        },
                                    },
                                    separators=(",", ":"),
                                    sort_keys=True,
                                ).encode("utf-8")
                            ).decode("ascii"),
                        }
                    ],
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

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_hash_executable = True
    mock_config.server_sigstore_bundle_file = str(bundle_path)
    mock_config.server_sigstore_policy = "block"
    mock_config.sigstore_tlog_policy = "entry"
    mock_config.allowed_sigstore_tlog_key_ids = [base64.b64encode(b"trusted-rekor-key").decode("ascii")]

    proxy = VanguardProxy(server_command=[str(executable_path)], config=mock_config)
    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._check_server_integrity_baseline()

    assert "logid.keyid" in str(excinfo.value).lower()


def test_proxy_blocks_on_sigstore_github_claim_mismatch(tmp_path, mock_config):
    executable_path = tmp_path / "demo-server.bin"
    executable_path.write_bytes(b"demo-binary")
    manifest_path = tmp_path / "server-manifest.json"
    bundle_path = tmp_path / sigstore_bundle.SERVER_SIGSTORE_BUNDLE

    manifest = server_integrity.build_server_manifest(
        [str(executable_path)],
        hash_executable=True,
        approval_status="approved",
        trust_level="internal",
    )
    server_integrity.write_server_manifest(manifest_path, manifest)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(executable_path.read_bytes())
    digest_bytes = digest.finalize()
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    cert = _build_sigstore_identity_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
        fulcio_claims={
            sigstore_bundle.FULCIO_GITHUB_WORKFLOW_REPOSITORY_OID: "provnai/McpVanguard",
            sigstore_bundle.FULCIO_GITHUB_WORKFLOW_REF_OID: "refs/heads/main",
        },
    )
    bundle_path.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
                    },
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

    mock_config.server_manifest_file = str(manifest_path)
    mock_config.server_manifest_hash_executable = True
    mock_config.server_sigstore_bundle_file = str(bundle_path)
    mock_config.server_sigstore_policy = "block"
    mock_config.allowed_sigstore_github_repositories = ["other/repo"]

    proxy = VanguardProxy(server_command=[str(executable_path)], config=mock_config)
    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._check_server_integrity_baseline()

    assert "github repository" in str(excinfo.value).lower()


def test_proxy_blocks_on_invalid_capability_manifest_signature(tmp_path, mock_config, monkeypatch):
    manifest_path = tmp_path / "capability-manifest.json"
    signature_path = tmp_path / "capability-manifest.sig.json"
    private_key_pem, signer_doc = signing.generate_signing_keypair("capability-signer")
    manifest = capability_fingerprint.build_capability_manifest(
        tools_payload={
            "jsonrpc": "2.0",
            "id": "tools-1",
            "result": {"tools": [{"name": "read_file", "description": "Read a file."}]},
        }
    )
    capability_fingerprint.write_capability_manifest(manifest_path, manifest)
    signature_doc = capability_fingerprint.sign_capability_manifest(manifest, private_key_pem, signer_doc["key_id"])
    signature_doc["manifest_sha256"] = "0" * 64
    capability_fingerprint.write_capability_manifest_signature(signature_path, signature_doc)

    trust_signer_file = tmp_path / "trusted-capability-signer.json"
    trust_signer_file.write_text(json.dumps(signer_doc), encoding="utf-8")
    monkeypatch.setenv("VANGUARD_TRUSTED_CAPABILITY_SIGNERS_FILE", str(trust_signer_file))

    mock_config.capability_manifest_file = str(manifest_path)
    mock_config.capability_manifest_signature_file = str(signature_path)
    mock_config.capability_trust_policy = "block"

    proxy = VanguardProxy(server_command=["python", "-c", "print('hello')"], config=mock_config)
    from core.session import SessionState

    proxy._session = SessionState(session_id="test-session")
    with pytest.raises(RuntimeError) as excinfo:
        proxy._load_capability_manifest_baseline()

    assert "capability manifest signature verification failed" in str(excinfo.value).lower()


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
