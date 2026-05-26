import json

from core import signing, supplier_signatures


def test_sign_and_verify_artifact_round_trip(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    private_key_pem, signer_doc = signing.generate_signing_keypair("supplier-signer")
    signature_doc = supplier_signatures.sign_artifact(
        artifact_path,
        private_key_pem,
        "supplier-signer",
        supplier="provnai",
    )
    trusted_signers = supplier_signatures.load_trusted_supplier_signers(
        extra_signers=[{**signer_doc, "supplier": "provnai"}]
    )

    supplier_signatures.verify_artifact_signature(
        artifact_path,
        signature_doc,
        trusted_signers,
        allowed_suppliers={"provnai"},
    )


def test_evaluate_artifact_signature_detects_tampering(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    private_key_pem, signer_doc = signing.generate_signing_keypair("supplier-signer")
    signature_doc = supplier_signatures.sign_artifact(
        artifact_path,
        private_key_pem,
        "supplier-signer",
        supplier="provnai",
    )
    trusted_signers = supplier_signatures.load_trusted_supplier_signers(
        extra_signers=[{**signer_doc, "supplier": "provnai"}]
    )

    artifact_path.write_bytes(b"tampered-binary")
    issues = supplier_signatures.evaluate_artifact_signature(
        artifact_path,
        signature_doc=signature_doc,
        trusted_signers=trusted_signers,
        require_signature=True,
        allowed_suppliers={"provnai"},
    )

    assert issues
    assert "verification failed" in issues[0].lower() or "digest" in issues[0].lower()


def test_evaluate_artifact_signature_detects_disallowed_supplier(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    private_key_pem, signer_doc = signing.generate_signing_keypair("supplier-signer")
    signature_doc = supplier_signatures.sign_artifact(
        artifact_path,
        private_key_pem,
        "supplier-signer",
        supplier="othercorp",
    )
    trusted_signers = supplier_signatures.load_trusted_supplier_signers(
        extra_signers=[{**signer_doc, "supplier": "othercorp"}]
    )

    issues = supplier_signatures.evaluate_artifact_signature(
        artifact_path,
        signature_doc=signature_doc,
        trusted_signers=trusted_signers,
        require_signature=True,
        allowed_suppliers={"provnai"},
    )

    assert issues
    assert "allowed supplier set" in issues[0]


def test_verify_artifact_signature_requires_digest_field(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    private_key_pem, signer_doc = signing.generate_signing_keypair("supplier-signer")
    signature_doc = supplier_signatures.sign_artifact(
        artifact_path,
        private_key_pem,
        "supplier-signer",
        supplier="provnai",
    )
    signature_doc.pop("artifact_sha256", None)
    trusted_signers = supplier_signatures.load_trusted_supplier_signers(
        extra_signers=[{**signer_doc, "supplier": "provnai"}]
    )

    try:
        supplier_signatures.verify_artifact_signature(
            artifact_path,
            signature_doc,
            trusted_signers,
            allowed_suppliers={"provnai"},
        )
    except ValueError as exc:
        assert "artifact_sha256" in str(exc)
    else:
        raise AssertionError("verify_artifact_signature should require artifact_sha256")
