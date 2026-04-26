import base64
import datetime as dt
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from core import signing, sigstore_bundle, supplier_signatures


def test_verify_sigstore_bundle_with_public_key_identifier(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")

    private_key_pem, signer_doc = signing.generate_signing_keypair("supplier-hint")
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(artifact_path.read_bytes())
    digest_bytes = digest.finalize()
    signature = private_key.sign(digest_bytes)

    bundle_doc = {
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

    trusted_signers = supplier_signatures.load_trusted_supplier_signers(extra_signers=[signer_doc])
    result = sigstore_bundle.verify_sigstore_bundle(
        artifact_path,
        bundle_doc,
        trusted_hint_signers=trusted_signers,
    )

    assert result["mode"] == "publicKeyIdentifier"
    assert result["hint"] == signer_doc["key_id"]


def test_verify_sigstore_bundle_with_certificate_fingerprint(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(private_key)
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    bundle_doc = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")}
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(digest_bytes).decode("ascii"),
            },
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }

    result = sigstore_bundle.verify_sigstore_bundle(
        artifact_path,
        bundle_doc,
        allowed_cert_fingerprints={fingerprint},
    )

    assert result["mode"] == "certificate"
    assert result["fingerprint_sha256"] == fingerprint


def test_verify_sigstore_bundle_with_certificate_identity_and_oidc_issuer(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
    )
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))

    bundle_doc = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")}
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(digest_bytes).decode("ascii"),
            },
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }

    result = sigstore_bundle.verify_sigstore_bundle(
        artifact_path,
        bundle_doc,
        allowed_identities={"https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main"},
        allowed_oidc_issuers={"https://token.actions.githubusercontent.com"},
    )

    assert result["mode"] == "certificate"
    assert result["oidc_issuer"] == "https://token.actions.githubusercontent.com"
    assert "https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main" in result["identities"]


def test_verify_sigstore_bundle_with_fulcio_claim_constraints(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(
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
    tlog_key_id = base64.b64encode(b"trusted-rekor-key").decode("ascii")

    bundle_doc = _build_bundle_doc(
        cert,
        digest_bytes,
        signature,
        tlog_entries=[
            _build_hashedrekord_tlog_entry(
                cert=cert,
                digest_bytes=digest_bytes,
                signature=signature,
                integrated_time=int(dt.datetime.now(dt.timezone.utc).timestamp()),
                include_promise=True,
                tlog_key_id=tlog_key_id,
            )
        ],
    )

    result = sigstore_bundle.verify_sigstore_bundle(
        artifact_path,
        bundle_doc,
        allowed_identities={"https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main"},
        allowed_oidc_issuers={"https://token.actions.githubusercontent.com"},
        allowed_build_signer_uris={"https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main"},
        allowed_source_repository_uris={"https://github.com/provnai/McpVanguard"},
        allowed_source_repository_refs={"refs/heads/main"},
        allowed_source_repository_digests={"sha1:abc123"},
        allowed_build_triggers={"push"},
        allowed_tlog_key_ids={tlog_key_id},
        tlog_policy="promise",
    )

    assert result["fulcio_claims"]["build_signer_uri"] == "https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main"
    assert result["fulcio_claims"]["source_repository_uri"] == "https://github.com/provnai/McpVanguard"
    assert result["tlog"]["log_id_key"] == tlog_key_id


def test_evaluate_sigstore_bundle_rejects_untrusted_certificate(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(private_key)
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))

    bundle_doc = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")}
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(digest_bytes).decode("ascii"),
            },
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }

    issues = sigstore_bundle.evaluate_sigstore_bundle(
        artifact_path,
        bundle_doc=bundle_doc,
        allowed_cert_fingerprints={"00" * 32},
    )

    assert issues
    assert "allowed set" in issues[0].lower()


def test_evaluate_sigstore_bundle_rejects_mismatched_identity(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
    )
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))

    bundle_doc = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")}
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(digest_bytes).decode("ascii"),
            },
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }

    issues = sigstore_bundle.evaluate_sigstore_bundle(
        artifact_path,
        bundle_doc=bundle_doc,
        allowed_identities={"https://github.com/other/repo/.github/workflows/release.yml@refs/heads/main"},
    )

    assert issues
    assert "identity is not in the allowed set" in issues[0].lower()


def test_evaluate_sigstore_bundle_rejects_missing_oidc_issuer(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
    )
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))

    bundle_doc = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")}
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(digest_bytes).decode("ascii"),
            },
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }

    issues = sigstore_bundle.evaluate_sigstore_bundle(
        artifact_path,
        bundle_doc=bundle_doc,
        allowed_oidc_issuers={"https://token.actions.githubusercontent.com"},
    )

    assert issues
    assert "missing the oidc issuer extension" in issues[0].lower()


def test_evaluate_sigstore_bundle_rejects_mismatched_fulcio_claim(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
        fulcio_claims={
            sigstore_bundle.FULCIO_SOURCE_REPOSITORY_URI_OID: "https://github.com/provnai/McpVanguard",
        },
    )
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))

    bundle_doc = _build_bundle_doc(cert, digest_bytes, signature)

    issues = sigstore_bundle.evaluate_sigstore_bundle(
        artifact_path,
        bundle_doc=bundle_doc,
        allowed_source_repository_uris={"https://github.com/other/repo"},
    )

    assert issues
    assert "source repository uri is not in the allowed set" in issues[0].lower()


def test_evaluate_sigstore_bundle_rejects_untrusted_tlog_key_id(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(private_key)
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    bundle_doc = _build_bundle_doc(
        cert,
        digest_bytes,
        signature,
        tlog_entries=[
            _build_hashedrekord_tlog_entry(
                cert=cert,
                digest_bytes=digest_bytes,
                signature=signature,
                integrated_time=int(dt.datetime.now(dt.timezone.utc).timestamp()),
                tlog_key_id=base64.b64encode(b"unexpected-rekor-key").decode("ascii"),
            )
        ],
    )

    issues = sigstore_bundle.evaluate_sigstore_bundle(
        artifact_path,
        bundle_doc=bundle_doc,
        allowed_tlog_key_ids={base64.b64encode(b"trusted-rekor-key").decode("ascii")},
        tlog_policy="entry",
    )

    assert issues
    assert "logid.keyid is not in the allowed set" in issues[0].lower()


def test_verify_sigstore_bundle_accepts_legacy_github_oid_claims(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(
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
    bundle_doc = _build_bundle_doc(cert, digest_bytes, signature)

    result = sigstore_bundle.verify_sigstore_bundle(
        artifact_path,
        bundle_doc,
        allowed_github_repositories={"provnai/McpVanguard"},
        allowed_github_refs={"refs/heads/main"},
        allowed_github_shas={"abc123"},
        allowed_github_triggers={"push"},
        allowed_github_workflow_names={"release"},
    )

    assert result["github_claims"]["repository"] == "provnai/McpVanguard"
    assert result["github_claims"]["workflow_name"] == "release"


def test_verify_sigstore_bundle_accepts_github_repository_slug_for_modern_url_claim(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
        fulcio_claims={
            sigstore_bundle.FULCIO_SOURCE_REPOSITORY_URI_OID: "https://github.com/provnai/McpVanguard",
            sigstore_bundle.FULCIO_SOURCE_REPOSITORY_REF_OID: "refs/heads/main",
            sigstore_bundle.FULCIO_SOURCE_REPOSITORY_DIGEST_OID: "sha1:abc123",
            sigstore_bundle.FULCIO_BUILD_TRIGGER_OID: "push",
        },
    )
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    bundle_doc = _build_bundle_doc(cert, digest_bytes, signature)

    result = sigstore_bundle.verify_sigstore_bundle(
        artifact_path,
        bundle_doc,
        allowed_github_repositories={"provnai/McpVanguard"},
        allowed_github_refs={"refs/heads/main"},
        allowed_github_shas={"abc123"},
        allowed_github_triggers={"push"},
    )

    assert result["github_claims"]["repository"] == "https://github.com/provnai/McpVanguard"


def test_verify_sigstore_bundle_with_transparency_promise(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(
        private_key,
        san_uri="https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main",
        oidc_issuer="https://token.actions.githubusercontent.com",
    )
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))

    bundle_doc = _build_bundle_doc(
        cert,
        digest_bytes,
        signature,
        tlog_entries=[
            _build_hashedrekord_tlog_entry(
                cert=cert,
                digest_bytes=digest_bytes,
                signature=signature,
                integrated_time=int(dt.datetime.now(dt.timezone.utc).timestamp()),
                include_promise=True,
            )
        ],
    )

    result = sigstore_bundle.verify_sigstore_bundle(
        artifact_path,
        bundle_doc,
        allowed_identities={"https://github.com/provnai/McpVanguard/.github/workflows/release.yml@refs/heads/main"},
        allowed_oidc_issuers={"https://token.actions.githubusercontent.com"},
        tlog_policy="promise",
    )

    assert result["tlog"]["policy"] == "promise"


def test_evaluate_sigstore_bundle_rejects_missing_tlog_entry(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(private_key)
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    bundle_doc = _build_bundle_doc(cert, digest_bytes, signature)

    issues = sigstore_bundle.evaluate_sigstore_bundle(
        artifact_path,
        bundle_doc=bundle_doc,
        tlog_policy="entry",
    )

    assert issues
    assert "missing required transparency log entries" in issues[0].lower()


def test_evaluate_sigstore_bundle_rejects_integrated_time_outside_cert_validity(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(private_key)
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    stale_time = int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)).timestamp())
    bundle_doc = _build_bundle_doc(
        cert,
        digest_bytes,
        signature,
        tlog_entries=[
            _build_hashedrekord_tlog_entry(
                cert=cert,
                digest_bytes=digest_bytes,
                signature=signature,
                integrated_time=stale_time,
                include_promise=True,
            )
        ],
    )

    issues = sigstore_bundle.evaluate_sigstore_bundle(
        artifact_path,
        bundle_doc=bundle_doc,
        tlog_policy="entry",
    )

    assert issues
    assert "integratedtime falls outside" in issues[0].lower()


def test_evaluate_sigstore_bundle_rejects_missing_inclusion_proof_when_required(tmp_path):
    artifact_path = tmp_path / "demo-server.bin"
    artifact_path.write_bytes(b"demo-binary")
    digest_bytes = _sha256_bytes(artifact_path.read_bytes())

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_self_signed_cert(private_key)
    signature = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
    bundle_doc = _build_bundle_doc(
        cert,
        digest_bytes,
        signature,
        tlog_entries=[
            _build_hashedrekord_tlog_entry(
                cert=cert,
                digest_bytes=digest_bytes,
                signature=signature,
                integrated_time=int(dt.datetime.now(dt.timezone.utc).timestamp()),
                include_promise=True,
                include_proof=False,
            )
        ],
    )

    issues = sigstore_bundle.evaluate_sigstore_bundle(
        artifact_path,
        bundle_doc=bundle_doc,
        tlog_policy="proof",
    )

    assert issues
    assert "missing inclusionproof" in issues[0].lower()


def _sha256_bytes(payload: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(payload)
    return digest.finalize()


def _build_self_signed_cert(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    san_uri: str | None = None,
    oidc_issuer: str | None = None,
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
    )
    if san_uri:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]),
            critical=True,
        )
    if oidc_issuer:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                sigstore_bundle.FULCIO_OIDC_ISSUER_OID,
                _der_encode_utf8_string(oidc_issuer),
            ),
            critical=False,
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


def _build_bundle_doc(
    cert: x509.Certificate,
    digest_bytes: bytes,
    signature: bytes,
    *,
    tlog_entries: list[dict] | None = None,
) -> dict:
    verification_material: dict[str, object] = {
        "certificate": {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")}
    }
    if tlog_entries is not None:
        verification_material["tlogEntries"] = tlog_entries

    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": verification_material,
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(digest_bytes).decode("ascii"),
            },
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }


def _build_hashedrekord_tlog_entry(
    *,
    cert: x509.Certificate,
    digest_bytes: bytes,
    signature: bytes,
    integrated_time: int,
    include_promise: bool = False,
    include_proof: bool = False,
    tlog_key_id: str | None = None,
) -> dict:
    canonicalized_body = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": digest_bytes.hex(),
                }
            },
            "signature": {
                "content": base64.b64encode(signature).decode("ascii"),
                "publicKey": {
                    "content": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                },
            },
        },
    }

    entry = {
        "logIndex": "123",
        "logId": {"keyId": tlog_key_id or base64.b64encode(b"rekor-log-key").decode("ascii")},
        "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
        "integratedTime": str(integrated_time),
        "canonicalizedBody": base64.b64encode(
            json.dumps(canonicalized_body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii"),
    }

    if include_promise:
        entry["inclusionPromise"] = {
            "signedEntryTimestamp": base64.b64encode(b"set-bytes").decode("ascii")
        }

    if include_proof:
        entry["inclusionProof"] = {
            "logIndex": "1",
            "rootHash": base64.b64encode(b"root-hash").decode("ascii"),
            "treeSize": "2",
            "hashes": [base64.b64encode(b"proof-hash").decode("ascii")],
            "checkpoint": {"envelope": "rekor.sigstore.dev - test\n2\nroot\n\n-sig-\n"},
        }

    return entry
