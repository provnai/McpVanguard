import json

from core import provenance, server_integrity, signing


def _sample_provenance(subject_sha256: str, builder_id: str = "https://builder.example/gha") -> dict:
    return {
        "_type": provenance.PROVENANCE_STATEMENT_TYPE,
        "subject": [
            {
                "name": "demo-server",
                "digest": {
                    "sha256": subject_sha256,
                },
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "runDetails": {
                "builder": {
                    "id": builder_id,
                }
            }
        },
    }


def test_sign_and_verify_provenance_round_trip():
    document = _sample_provenance("a" * 64)
    private_key_pem, signer_doc = signing.generate_signing_keypair("provenance-signer")
    signature_doc = provenance.sign_provenance(document, private_key_pem, "provenance-signer")
    trusted_signers = provenance.load_trusted_provenance_signers(extra_signers=[signer_doc])

    provenance.verify_provenance_signature(document, signature_doc, trusted_signers)


def test_evaluate_provenance_for_server_manifest_matches_executable_hash():
    manifest = server_integrity.build_server_manifest(["python", "-m", "demo_server"])
    manifest["executable"]["sha256"] = "b" * 64
    document = _sample_provenance("b" * 64)

    issues = provenance.evaluate_provenance_for_server_manifest(
        manifest,
        document,
        required_builder_ids={"https://builder.example/gha"},
    )

    assert issues == []


def test_evaluate_provenance_for_server_manifest_detects_builder_mismatch():
    manifest = server_integrity.build_server_manifest(["python", "-m", "demo_server"])
    manifest["executable"]["sha256"] = "b" * 64
    document = _sample_provenance("b" * 64, builder_id="https://builder.example/other")

    issues = provenance.evaluate_provenance_for_server_manifest(
        manifest,
        document,
        required_builder_ids={"https://builder.example/gha"},
    )

    assert issues
    assert "builder.id" in issues[0]


def test_evaluate_provenance_signature_detects_tampering():
    document = _sample_provenance("a" * 64)
    private_key_pem, signer_doc = signing.generate_signing_keypair("provenance-signer")
    signature_doc = provenance.sign_provenance(document, private_key_pem, "provenance-signer")
    trusted_signers = provenance.load_trusted_provenance_signers(extra_signers=[signer_doc])

    tampered = json.loads(json.dumps(document))
    tampered["subject"][0]["digest"]["sha256"] = "c" * 64

    issues = provenance.evaluate_provenance_signature(
        tampered,
        signature_doc=signature_doc,
        trusted_signers=trusted_signers,
        require_signature=True,
    )

    assert issues
    assert "verification failed" in issues[0].lower()
