import base64
import hashlib
import json

from typer.testing import CliRunner

from core import signing
from core.cli import app


runner = CliRunner()


def _mock_client_factory(commit_sha, files, manifest, signature_doc=None):
    class MockResponse:
        def __init__(self, status_code=200, text="", json_data=None):
            self.status_code = status_code
            self.text = text
            self._json = json_data

        def raise_for_status(self):
            if self.status_code >= 400:
                import httpx

                raise httpx.HTTPStatusError("boom", request=None, response=self)

        def json(self):
            return self._json

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url, headers=None):
            if f"/commits/main" in url:
                return MockResponse(json_data={"sha": commit_sha})
            if url.endswith("/rules/manifest.json"):
                return MockResponse(text=json.dumps(manifest), json_data=manifest)
            if url.endswith("/rules/manifest.sig.json"):
                if signature_doc is None:
                    return MockResponse(status_code=404, text="missing")
                return MockResponse(text=json.dumps(signature_doc), json_data=signature_doc)
            for filename, content in files.items():
                if url.endswith(f"/rules/{filename}"):
                    return MockResponse(text=content)
            return MockResponse(status_code=404, text="missing")

    return MockClient


def _signed_bundle():
    key_id = "test-signer"
    private_pem, public_doc = signing.generate_signing_keypair(key_id)
    files = {
        "commands.yaml": "id: nope\n",
        "filesystem.yaml": "[]\n",
        "network.yaml": "[]\n",
        "privilege.yaml": "[]\n",
        "jailbreak.yaml": "[]\n",
    }
    manifest = {
        "version": 1,
        "rules": {
            name: {"sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}
            for name, content in files.items()
        },
    }
    signature_doc = signing.sign_manifest(manifest, private_pem, key_id)
    return files, manifest, signature_doc, public_doc


def test_update_requires_detached_signature_by_default(monkeypatch, tmp_path):
    rules_dir = tmp_path / "rules"
    commit_sha = "a" * 40
    files, manifest, _, public_doc = _signed_bundle()
    public_key_file = tmp_path / "trusted-signer.json"
    public_key_file.write_text(json.dumps(public_doc), encoding="utf-8")

    monkeypatch.setattr(
        "core.cli.httpx.Client",
        _mock_client_factory(commit_sha, files, manifest, signature_doc=None),
    )

    result = runner.invoke(
        app,
        [
            "update",
            "--repo",
            "provnai/McpVanguard",
            "--rules-dir",
            str(rules_dir),
            "--trust-key-file",
            str(public_key_file),
        ],
    )
    assert result.exit_code == 1
    assert "detached manifest signature" in result.stdout.lower()
    assert "missing" in result.stdout.lower()


def test_update_succeeds_with_signed_manifest(monkeypatch, tmp_path):
    rules_dir = tmp_path / "rules"
    commit_sha = "b" * 40
    files, manifest, signature_doc, public_doc = _signed_bundle()
    public_key_file = tmp_path / "trusted-signer.json"
    public_key_file.write_text(json.dumps(public_doc), encoding="utf-8")

    monkeypatch.setattr(
        "core.cli.httpx.Client",
        _mock_client_factory(commit_sha, files, manifest, signature_doc=signature_doc),
    )
    result = runner.invoke(
        app,
        [
            "update",
            "--repo",
            "provnai/McpVanguard",
            "--rules-dir",
            str(rules_dir),
            "--trust-key-file",
            str(public_key_file),
        ],
    )
    assert result.exit_code == 0
    assert (rules_dir / "commands.yaml").read_text(encoding="utf-8") == files["commands.yaml"]
    assert json.loads((rules_dir / "manifest.sig.json").read_text(encoding="utf-8"))["key_id"] == public_doc["key_id"]


def test_update_fails_on_bad_signature(monkeypatch, tmp_path):
    rules_dir = tmp_path / "rules"
    commit_sha = "c" * 40
    files, manifest, signature_doc, public_doc = _signed_bundle()
    public_key_file = tmp_path / "trusted-signer.json"
    public_key_file.write_text(json.dumps(public_doc), encoding="utf-8")
    signature_doc = dict(signature_doc)
    signature_doc["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")

    monkeypatch.setattr(
        "core.cli.httpx.Client",
        _mock_client_factory(commit_sha, files, manifest, signature_doc=signature_doc),
    )
    result = runner.invoke(
        app,
        [
            "update",
            "--repo",
            "provnai/McpVanguard",
            "--rules-dir",
            str(rules_dir),
            "--trust-key-file",
            str(public_key_file),
        ],
    )
    assert result.exit_code == 1
    assert "detached manifest signature" in result.stdout.lower()
    assert "verification failed" in result.stdout.lower()


def test_sign_rules_writes_manifest_and_signature(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    for filename, content in {
        "commands.yaml": "id: signed\n",
        "filesystem.yaml": "[]\n",
        "network.yaml": "[]\n",
        "privilege.yaml": "[]\n",
        "jailbreak.yaml": "[]\n",
    }.items():
        (rules_dir / filename).write_text(content, encoding="utf-8")

    key_id = "local-test"
    private_pem, public_doc = signing.generate_signing_keypair(key_id)
    private_key_path = tmp_path / "release-key.pem"
    private_key_path.write_bytes(private_pem)

    result = runner.invoke(
        app,
        [
            "sign-rules",
            "--key-id",
            key_id,
            "--private-key",
            str(private_key_path),
            "--rules-dir",
            str(rules_dir),
        ],
    )
    assert result.exit_code == 0
    manifest = json.loads((rules_dir / "manifest.json").read_text(encoding="utf-8"))
    signature_doc = json.loads((rules_dir / "manifest.sig.json").read_text(encoding="utf-8"))
    trusted = signing.load_trusted_signers(extra_signers=[public_doc])
    signing.verify_manifest_signature(manifest, signature_doc, trusted)
