import json

from core import server_integrity
from core import signing


def test_build_server_manifest_infers_npx_package():
    manifest = server_integrity.build_server_manifest(
        ["npx", "@modelcontextprotocol/server-filesystem@1.2.3", "."]
    )

    assert manifest["runtime"]["package_manager"] == "npx"
    assert manifest["runtime"]["package_identifier"] == "@modelcontextprotocol/server-filesystem"
    assert manifest["runtime"]["package_version"] == "1.2.3"
    assert manifest["command"]["argv"][0] == "npx"


def test_compare_server_manifests_detects_command_drift():
    expected = server_integrity.build_server_manifest(["python", "-m", "server_a"])
    actual = server_integrity.build_server_manifest(["python", "-m", "server_b"])

    drifts = server_integrity.compare_server_manifests(expected, actual)

    assert "command.argv" in drifts
    assert "runtime.package_identifier" in drifts


def test_write_and_load_server_manifest_round_trip(tmp_path):
    path = tmp_path / "server-manifest.json"
    manifest = server_integrity.build_server_manifest(["python", "-m", "demo_server"])

    server_integrity.write_server_manifest(path, manifest)
    loaded = server_integrity.load_server_manifest(path)

    assert loaded == manifest
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == manifest["version"]


def test_build_server_manifest_accepts_trust_metadata():
    manifest = server_integrity.build_server_manifest(
        ["python", "-m", "demo_server"],
        approval_status="approved",
        trust_level="internal",
    )

    assert manifest["trust"]["approval_status"] == "approved"
    assert manifest["trust"]["trust_level"] == "internal"


def test_sign_and_verify_server_manifest_round_trip():
    manifest = server_integrity.build_server_manifest(
        ["python", "-m", "demo_server"],
        approval_status="approved",
        trust_level="internal",
    )
    private_key_pem, signer_doc = signing.generate_signing_keypair("server-baseline-signer")
    signature_doc = server_integrity.sign_server_manifest(manifest, private_key_pem, "server-baseline-signer")
    trusted_signers = server_integrity.load_trusted_server_signers(extra_signers=[signer_doc])

    server_integrity.verify_server_manifest_signature(manifest, signature_doc, trusted_signers)


def test_evaluate_server_manifest_signature_detects_tampering():
    manifest = server_integrity.build_server_manifest(
        ["python", "-m", "demo_server"],
        approval_status="approved",
        trust_level="internal",
    )
    private_key_pem, signer_doc = signing.generate_signing_keypair("server-baseline-signer")
    signature_doc = server_integrity.sign_server_manifest(manifest, private_key_pem, "server-baseline-signer")
    trusted_signers = server_integrity.load_trusted_server_signers(extra_signers=[signer_doc])

    tampered = json.loads(json.dumps(manifest))
    tampered["command"]["argv"] = ["python", "-m", "other_server"]

    issues = server_integrity.evaluate_server_manifest_signature(
        tampered,
        signature_doc=signature_doc,
        trusted_signers=trusted_signers,
        require_signature=True,
    )

    assert issues
    assert "verification failed" in issues[0].lower()


def test_evaluate_server_manifest_approval_detects_revoked_state():
    manifest = server_integrity.build_server_manifest(
        ["python", "-m", "demo_server"],
        approval_status="revoked",
        trust_level="third_party",
    )

    issues = server_integrity.evaluate_server_manifest_approval(manifest)

    assert issues == ["Upstream server manifest trust state is revoked."]
