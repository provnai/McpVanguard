"""
core/sigstore_bundle.py
Bounded local verification helpers for Sigstore message-signature bundles.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

from core import supplier_signatures


SERVER_SIGSTORE_BUNDLE = "server-artifact.sigstore.json"
SIGSTORE_MEDIA_PREFIX = "application/vnd.dev.sigstore.bundle."
SUPPORTED_DIGEST_ALGORITHMS = {"SHA2_256", "SHA256"}
FULCIO_OIDC_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.8")
FULCIO_BUILD_SIGNER_URI_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.9")
FULCIO_BUILD_SIGNER_DIGEST_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.10")
FULCIO_SOURCE_REPOSITORY_URI_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.12")
FULCIO_SOURCE_REPOSITORY_DIGEST_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.13")
FULCIO_SOURCE_REPOSITORY_REF_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.14")
FULCIO_BUILD_TRIGGER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.20")
FULCIO_GITHUB_WORKFLOW_TRIGGER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.2")
FULCIO_GITHUB_WORKFLOW_SHA_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.3")
FULCIO_GITHUB_WORKFLOW_NAME_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.4")
FULCIO_GITHUB_WORKFLOW_REPOSITORY_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.5")
FULCIO_GITHUB_WORKFLOW_REF_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.6")
SIGSTORE_TLOG_POLICIES = {"off", "entry", "promise", "proof"}


def load_sigstore_bundle(path: str | os.PathLike[str]) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def default_sigstore_bundle_path(executable_path: str | os.PathLike[str]) -> Path:
    path = Path(executable_path)
    return path.with_name(f"{path.name}.sigstore.json")


def load_allowed_sigstore_cert_fingerprints(
    extra_fingerprints: Optional[list[str]] = None,
) -> set[str]:
    fingerprints = {_normalize_fingerprint(value) for value in extra_fingerprints or [] if value}
    for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_CERT_FINGERPRINTS", "").split(","):
        value = value.strip()
        if value:
            fingerprints.add(_normalize_fingerprint(value))
    return fingerprints


def load_allowed_sigstore_identities(extra_identities: Optional[list[str]] = None) -> set[str]:
    identities = {value.strip() for value in extra_identities or [] if value and value.strip()}
    for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_IDENTITIES", "").split(","):
        value = value.strip()
        if value:
            identities.add(value)
    return identities


def load_allowed_sigstore_oidc_issuers(extra_issuers: Optional[list[str]] = None) -> set[str]:
    issuers = {value.strip() for value in extra_issuers or [] if value and value.strip()}
    for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_OIDC_ISSUERS", "").split(","):
        value = value.strip()
        if value:
            issuers.add(value)
    return issuers


def load_allowed_sigstore_build_signer_uris(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_BUILD_SIGNER_URIS")


def load_allowed_sigstore_source_repository_uris(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_SOURCE_REPOSITORIES")


def load_allowed_sigstore_source_repository_refs(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_SOURCE_REFS")


def load_allowed_sigstore_source_repository_digests(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_SOURCE_DIGESTS")


def load_allowed_sigstore_build_triggers(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_BUILD_TRIGGERS")


def load_allowed_sigstore_tlog_key_ids(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_TLOG_KEY_IDS")


def load_allowed_sigstore_github_repositories(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_GITHUB_REPOSITORIES")


def load_allowed_sigstore_github_refs(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_GITHUB_REFS")


def load_allowed_sigstore_github_shas(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_GITHUB_SHAS")


def load_allowed_sigstore_github_triggers(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_GITHUB_TRIGGERS")


def load_allowed_sigstore_github_workflow_names(extra_values: Optional[list[str]] = None) -> set[str]:
    return _load_string_allowlist(extra_values, "VANGUARD_ALLOWED_SIGSTORE_GITHUB_WORKFLOW_NAMES")


def normalize_sigstore_tlog_policy(value: str | None) -> str:
    policy = str(value or "off").strip().lower()
    if policy not in SIGSTORE_TLOG_POLICIES:
        raise ValueError(
            f"Unsupported Sigstore transparency policy: {value}. Expected one of {sorted(SIGSTORE_TLOG_POLICIES)}."
        )
    return policy


def verify_sigstore_bundle(
    artifact_path: str | os.PathLike[str],
    bundle_doc: dict[str, Any],
    *,
    trusted_hint_signers: dict[str, dict[str, str]] | None = None,
    allowed_cert_fingerprints: set[str] | None = None,
    allowed_identities: set[str] | None = None,
    allowed_oidc_issuers: set[str] | None = None,
    allowed_build_signer_uris: set[str] | None = None,
    allowed_source_repository_uris: set[str] | None = None,
    allowed_source_repository_refs: set[str] | None = None,
    allowed_source_repository_digests: set[str] | None = None,
    allowed_build_triggers: set[str] | None = None,
    allowed_tlog_key_ids: set[str] | None = None,
    allowed_github_repositories: set[str] | None = None,
    allowed_github_refs: set[str] | None = None,
    allowed_github_shas: set[str] | None = None,
    allowed_github_triggers: set[str] | None = None,
    allowed_github_workflow_names: set[str] | None = None,
    tlog_policy: str = "off",
) -> dict[str, Any]:
    tlog_policy = normalize_sigstore_tlog_policy(tlog_policy)
    if not isinstance(bundle_doc, dict):
        raise ValueError("Sigstore bundle document is invalid.")

    media_type = str(bundle_doc.get("mediaType") or "")
    if not media_type.startswith(SIGSTORE_MEDIA_PREFIX):
        raise ValueError(f"Unsupported Sigstore bundle mediaType: {media_type or '<missing>'}.")

    message_signature = bundle_doc.get("messageSignature")
    if not isinstance(message_signature, dict):
        raise ValueError("Sigstore bundle must contain a messageSignature payload.")

    message_digest = message_signature.get("messageDigest")
    if not isinstance(message_digest, dict):
        raise ValueError("Sigstore messageSignature is missing messageDigest.")

    algorithm = str(message_digest.get("algorithm") or "")
    if algorithm not in SUPPORTED_DIGEST_ALGORITHMS:
        raise ValueError(f"Unsupported Sigstore messageDigest algorithm: {algorithm or '<missing>'}.")

    digest_b64 = str(message_digest.get("digest") or "")
    expected_digest = _decode_b64(digest_b64, "Sigstore messageDigest.digest")
    actual_digest = hashlib.sha256(Path(artifact_path).read_bytes()).digest()
    if expected_digest != actual_digest:
        raise ValueError("Sigstore messageDigest does not match the current artifact SHA-256.")

    signature = _decode_b64(str(message_signature.get("signature") or ""), "Sigstore messageSignature.signature")
    verification_material = bundle_doc.get("verificationMaterial")
    if not isinstance(verification_material, dict):
        raise ValueError("Sigstore bundle is missing verificationMaterial.")

    public_key_identifier = verification_material.get("publicKeyIdentifier")
    if isinstance(public_key_identifier, dict) and public_key_identifier.get("hint"):
        if allowed_identities or allowed_oidc_issuers:
            raise ValueError(
                "Sigstore certificate identity and OIDC issuer verification require a certificate-backed bundle."
            )
        hint = str(public_key_identifier.get("hint"))
        signer = (trusted_hint_signers or {}).get(hint)
        if signer is None:
            raise ValueError(f"Sigstore publicKeyIdentifier hint '{hint}' is not trusted.")
        _verify_signature_with_hint_signer(signature, actual_digest, hint, signer)
        tlog_summary = _verify_tlog_entries(
            bundle_doc,
            actual_digest=actual_digest,
            signature=signature,
            cert=None,
            tlog_policy=tlog_policy,
            allowed_tlog_key_ids=allowed_tlog_key_ids,
        )
        return {"mode": "publicKeyIdentifier", "hint": hint, "tlog": tlog_summary}

    cert = _extract_bundle_certificate(verification_material)
    if cert is None:
        raise ValueError("Sigstore bundle must include either publicKeyIdentifier.hint or a certificate.")

    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    if allowed_cert_fingerprints and fingerprint not in allowed_cert_fingerprints:
        raise ValueError(
            "Sigstore certificate fingerprint is not in the allowed set: "
            f"{sorted(allowed_cert_fingerprints)}."
        )

    _verify_signature_with_certificate(cert, signature, actual_digest)
    identities = _extract_certificate_identities(cert)
    oidc_issuer = _extract_certificate_oidc_issuer(cert)
    fulcio_claims = _extract_fulcio_claims(cert)
    github_claims = _extract_github_claims(cert, fulcio_claims)

    if allowed_identities and not set(identities).intersection(allowed_identities):
        raise ValueError(
            "Sigstore certificate identity is not in the allowed set: "
            f"{sorted(allowed_identities)}."
        )

    if allowed_oidc_issuers:
        if not oidc_issuer:
            raise ValueError("Sigstore certificate is missing the OIDC issuer extension.")
        if oidc_issuer not in allowed_oidc_issuers:
            raise ValueError(
                "Sigstore certificate OIDC issuer is not in the allowed set: "
                f"{sorted(allowed_oidc_issuers)}."
            )

    _validate_fulcio_claim_allowlist(
        label="Build Signer URI",
        claim_value=fulcio_claims.get("build_signer_uri"),
        allowed_values=allowed_build_signer_uris,
    )
    _validate_fulcio_claim_allowlist(
        label="Source Repository URI",
        claim_value=fulcio_claims.get("source_repository_uri"),
        allowed_values=allowed_source_repository_uris,
    )
    _validate_fulcio_claim_allowlist(
        label="Source Repository Ref",
        claim_value=fulcio_claims.get("source_repository_ref"),
        allowed_values=allowed_source_repository_refs,
    )
    _validate_fulcio_claim_allowlist(
        label="Source Repository Digest",
        claim_value=fulcio_claims.get("source_repository_digest"),
        allowed_values=allowed_source_repository_digests,
    )
    _validate_fulcio_claim_allowlist(
        label="Build Trigger",
        claim_value=fulcio_claims.get("build_trigger"),
        allowed_values=allowed_build_triggers,
    )
    _validate_github_claim_allowlists(
        github_claims=github_claims,
        allowed_repositories=allowed_github_repositories,
        allowed_refs=allowed_github_refs,
        allowed_shas=allowed_github_shas,
        allowed_triggers=allowed_github_triggers,
        allowed_workflow_names=allowed_github_workflow_names,
    )

    tlog_summary = _verify_tlog_entries(
        bundle_doc,
        actual_digest=actual_digest,
        signature=signature,
        cert=cert,
        tlog_policy=tlog_policy,
        allowed_tlog_key_ids=allowed_tlog_key_ids,
    )

    return {
        "mode": "certificate",
        "fingerprint_sha256": fingerprint,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "identities": identities,
        "oidc_issuer": oidc_issuer,
        "fulcio_claims": fulcio_claims,
        "github_claims": github_claims,
        "tlog": tlog_summary,
    }


def evaluate_sigstore_bundle(
    artifact_path: str | os.PathLike[str] | None,
    *,
    bundle_doc: dict[str, Any] | None,
    trusted_hint_signers: dict[str, dict[str, str]] | None = None,
    require_bundle: bool = True,
    allowed_cert_fingerprints: set[str] | None = None,
    allowed_identities: set[str] | None = None,
    allowed_oidc_issuers: set[str] | None = None,
    allowed_build_signer_uris: set[str] | None = None,
    allowed_source_repository_uris: set[str] | None = None,
    allowed_source_repository_refs: set[str] | None = None,
    allowed_source_repository_digests: set[str] | None = None,
    allowed_build_triggers: set[str] | None = None,
    allowed_tlog_key_ids: set[str] | None = None,
    allowed_github_repositories: set[str] | None = None,
    allowed_github_refs: set[str] | None = None,
    allowed_github_shas: set[str] | None = None,
    allowed_github_triggers: set[str] | None = None,
    allowed_github_workflow_names: set[str] | None = None,
    tlog_policy: str = "off",
) -> list[str]:
    if artifact_path is None:
        return ["Sigstore bundle verification requires a local resolved executable path."]
    if bundle_doc is None:
        return ["Resolved executable is missing a Sigstore bundle."] if require_bundle else []

    try:
        verify_sigstore_bundle(
            artifact_path,
            bundle_doc,
            trusted_hint_signers=trusted_hint_signers,
            allowed_cert_fingerprints=allowed_cert_fingerprints,
            allowed_identities=allowed_identities,
            allowed_oidc_issuers=allowed_oidc_issuers,
            allowed_build_signer_uris=allowed_build_signer_uris,
            allowed_source_repository_uris=allowed_source_repository_uris,
            allowed_source_repository_refs=allowed_source_repository_refs,
            allowed_source_repository_digests=allowed_source_repository_digests,
            allowed_build_triggers=allowed_build_triggers,
            allowed_tlog_key_ids=allowed_tlog_key_ids,
            allowed_github_repositories=allowed_github_repositories,
            allowed_github_refs=allowed_github_refs,
            allowed_github_shas=allowed_github_shas,
            allowed_github_triggers=allowed_github_triggers,
            allowed_github_workflow_names=allowed_github_workflow_names,
            tlog_policy=tlog_policy,
        )
    except Exception as exc:
        return [f"Sigstore bundle verification failed: {exc}"]
    return []


def _extract_bundle_certificate(verification_material: dict[str, Any]) -> x509.Certificate | None:
    certificate_block = verification_material.get("certificate")
    if isinstance(certificate_block, dict) and certificate_block.get("rawBytes"):
        return x509.load_der_x509_certificate(
            _decode_b64(str(certificate_block["rawBytes"]), "Sigstore verificationMaterial.certificate.rawBytes")
        )

    chain_block = verification_material.get("x509CertificateChain")
    if isinstance(chain_block, dict):
        certificates = chain_block.get("certificates")
        if isinstance(certificates, list) and certificates:
            first = certificates[0]
            if isinstance(first, dict) and first.get("rawBytes"):
                return x509.load_der_x509_certificate(
                    _decode_b64(str(first["rawBytes"]), "Sigstore x509CertificateChain.certificates[0].rawBytes")
                )
    return None


def _verify_tlog_entries(
    bundle_doc: dict[str, Any],
    *,
    actual_digest: bytes,
    signature: bytes,
    cert: x509.Certificate | None,
    tlog_policy: str,
    allowed_tlog_key_ids: set[str] | None,
) -> dict[str, Any] | None:
    if tlog_policy == "off":
        return None

    verification_material = bundle_doc.get("verificationMaterial")
    tlog_entries = verification_material.get("tlogEntries") if isinstance(verification_material, dict) else None
    if not isinstance(tlog_entries, list) or not tlog_entries:
        raise ValueError("Sigstore bundle is missing required transparency log entries.")

    errors: list[str] = []
    for entry in tlog_entries:
        try:
            return _validate_single_tlog_entry(
                entry,
                actual_digest=actual_digest,
                signature=signature,
                cert=cert,
                tlog_policy=tlog_policy,
                allowed_tlog_key_ids=allowed_tlog_key_ids,
            )
        except ValueError as exc:
            errors.append(str(exc))

    raise ValueError(
        "Sigstore transparency-log verification failed: "
        + "; ".join(errors)
    )


def _validate_single_tlog_entry(
    entry: dict[str, Any],
    *,
    actual_digest: bytes,
    signature: bytes,
    cert: x509.Certificate | None,
    tlog_policy: str,
    allowed_tlog_key_ids: set[str] | None,
) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise ValueError("Transparency log entry is invalid.")

    kind_version = entry.get("kindVersion")
    if not isinstance(kind_version, dict):
        raise ValueError("Transparency log entry is missing kindVersion.")
    kind = str(kind_version.get("kind") or "")
    version = str(kind_version.get("version") or "")
    if kind != "hashedrekord":
        raise ValueError(f"Unsupported transparency log entry kind: {kind or '<missing>'}.")
    if version not in {"0.0.1", "0.0.2"}:
        raise ValueError(f"Unsupported transparency log entry version: {version or '<missing>'}.")

    log_id_block = entry.get("logId")
    log_id_key = None
    if isinstance(log_id_block, dict):
        value = str(log_id_block.get("keyId") or "").strip()
        if value:
            log_id_key = value
    if allowed_tlog_key_ids:
        if not log_id_key:
            raise ValueError("Transparency log entry is missing logId.keyId.")
        if log_id_key not in allowed_tlog_key_ids:
            raise ValueError(
                "Transparency log entry logId.keyId is not in the allowed set: "
                f"{sorted(allowed_tlog_key_ids)}."
            )

    integrated_time = _parse_integrated_time(entry.get("integratedTime"))
    if cert is not None:
        signing_time = dt.datetime.fromtimestamp(integrated_time, tz=dt.timezone.utc)
        not_before = _certificate_not_before(cert)
        not_after = _certificate_not_after(cert)
        if signing_time < not_before or signing_time > not_after:
            raise ValueError("Sigstore integratedTime falls outside the signing certificate validity window.")

    if tlog_policy in {"promise", "proof"}:
        inclusion_promise = entry.get("inclusionPromise")
        if not isinstance(inclusion_promise, dict):
            raise ValueError("Transparency log entry is missing inclusionPromise.")
        _decode_b64(str(inclusion_promise.get("signedEntryTimestamp") or ""), "Sigstore inclusionPromise.signedEntryTimestamp")

    if tlog_policy == "proof":
        inclusion_proof = entry.get("inclusionProof")
        if not isinstance(inclusion_proof, dict):
            raise ValueError("Transparency log entry is missing inclusionProof.")
        _decode_b64(str(inclusion_proof.get("rootHash") or ""), "Sigstore inclusionProof.rootHash")
        hashes = inclusion_proof.get("hashes")
        if not isinstance(hashes, list):
            raise ValueError("Transparency log entry inclusionProof.hashes is invalid.")
        for index, value in enumerate(hashes):
            _decode_b64(str(value or ""), f"Sigstore inclusionProof.hashes[{index}]")
        checkpoint = inclusion_proof.get("checkpoint")
        if not isinstance(checkpoint, dict) or not str(checkpoint.get("envelope") or "").strip():
            raise ValueError("Transparency log entry is missing checkpoint envelope.")

    body = _parse_canonicalized_body(entry.get("canonicalizedBody"))
    _validate_hashedrekord_body(body, actual_digest=actual_digest, signature=signature, cert=cert)

    return {
        "kind": kind,
        "version": version,
        "integrated_time": integrated_time,
        "log_index": entry.get("logIndex"),
        "log_id_key": log_id_key,
        "policy": tlog_policy,
    }


def _parse_integrated_time(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise ValueError("Transparency log entry integratedTime is invalid.")


def _parse_canonicalized_body(value: Any) -> dict[str, Any]:
    raw = _decode_b64(str(value or ""), "Sigstore canonicalizedBody")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Sigstore canonicalizedBody is not valid JSON.") from exc
    if not isinstance(body, dict):
        raise ValueError("Sigstore canonicalizedBody is not a JSON object.")
    return body


def _validate_hashedrekord_body(
    body: dict[str, Any],
    *,
    actual_digest: bytes,
    signature: bytes,
    cert: x509.Certificate | None,
) -> None:
    kind = str(body.get("kind") or "")
    if kind != "hashedrekord":
        raise ValueError(f"Sigstore canonicalizedBody kind is unsupported: {kind or '<missing>'}.")

    spec = body.get("spec")
    if not isinstance(spec, dict):
        raise ValueError("Sigstore canonicalizedBody is missing spec.")

    data = spec.get("data")
    if not isinstance(data, dict):
        raise ValueError("Sigstore canonicalizedBody is missing spec.data.")
    hash_block = data.get("hash")
    if not isinstance(hash_block, dict):
        raise ValueError("Sigstore canonicalizedBody is missing spec.data.hash.")

    algorithm = str(hash_block.get("algorithm") or "").lower()
    if algorithm != "sha256":
        raise ValueError(f"Sigstore canonicalizedBody hash algorithm is unsupported: {algorithm or '<missing>'}.")
    expected_hash = str(hash_block.get("value") or "").lower()
    if expected_hash != actual_digest.hex():
        raise ValueError("Sigstore canonicalizedBody hash does not match the artifact digest.")

    signature_block = spec.get("signature")
    if not isinstance(signature_block, dict):
        raise ValueError("Sigstore canonicalizedBody is missing spec.signature.")
    signature_content = _decode_b64(str(signature_block.get("content") or ""), "Sigstore canonicalizedBody.spec.signature.content")
    if signature_content != signature:
        raise ValueError("Sigstore canonicalizedBody signature does not match the bundle signature.")

    if cert is not None:
        public_key_block = signature_block.get("publicKey")
        if not isinstance(public_key_block, dict):
            raise ValueError("Sigstore canonicalizedBody is missing spec.signature.publicKey.")
        pem_content = str(public_key_block.get("content") or "")
        if not pem_content.strip():
            raise ValueError("Sigstore canonicalizedBody public key content is empty.")
        try:
            body_cert = x509.load_pem_x509_certificate(pem_content.encode("utf-8"))
        except ValueError as exc:
            raise ValueError("Sigstore canonicalizedBody public key content is not a PEM certificate.") from exc
        if body_cert.public_bytes(serialization.Encoding.DER) != cert.public_bytes(serialization.Encoding.DER):
            raise ValueError("Sigstore canonicalizedBody certificate does not match the bundle certificate.")


def _extract_certificate_identities(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return []

    identities: list[str] = []
    identities.extend(san.get_values_for_type(x509.RFC822Name))
    identities.extend(san.get_values_for_type(x509.UniformResourceIdentifier))
    identities.extend(san.get_values_for_type(x509.DNSName))
    identities.extend(str(value) for value in san.get_values_for_type(x509.IPAddress))
    return identities


def _extract_certificate_oidc_issuer(cert: x509.Certificate) -> str | None:
    try:
        extension = cert.extensions.get_extension_for_oid(FULCIO_OIDC_ISSUER_OID)
    except x509.ExtensionNotFound:
        return None

    value = extension.value
    if not isinstance(value, x509.UnrecognizedExtension):
        raw = getattr(value, "value", b"")
    else:
        raw = value.value
    return _decode_der_utf8_string(raw)


def _extract_fulcio_claims(cert: x509.Certificate) -> dict[str, str | None]:
    return {
        "build_signer_uri": _extract_der_extension_value(cert, FULCIO_BUILD_SIGNER_URI_OID),
        "build_signer_digest": _extract_der_extension_value(cert, FULCIO_BUILD_SIGNER_DIGEST_OID),
        "source_repository_uri": _extract_der_extension_value(cert, FULCIO_SOURCE_REPOSITORY_URI_OID),
        "source_repository_digest": _extract_der_extension_value(cert, FULCIO_SOURCE_REPOSITORY_DIGEST_OID),
        "source_repository_ref": _extract_der_extension_value(cert, FULCIO_SOURCE_REPOSITORY_REF_OID),
        "build_trigger": _extract_der_extension_value(cert, FULCIO_BUILD_TRIGGER_OID),
    }


def _extract_github_claims(
    cert: x509.Certificate,
    fulcio_claims: dict[str, str | None],
) -> dict[str, str | None]:
    return {
        "repository": fulcio_claims.get("source_repository_uri")
        or _extract_der_extension_value(cert, FULCIO_GITHUB_WORKFLOW_REPOSITORY_OID),
        "ref": fulcio_claims.get("source_repository_ref")
        or _extract_der_extension_value(cert, FULCIO_GITHUB_WORKFLOW_REF_OID),
        "sha": fulcio_claims.get("source_repository_digest")
        or _extract_der_extension_value(cert, FULCIO_GITHUB_WORKFLOW_SHA_OID),
        "trigger": fulcio_claims.get("build_trigger")
        or _extract_der_extension_value(cert, FULCIO_GITHUB_WORKFLOW_TRIGGER_OID),
        "workflow_name": _extract_der_extension_value(cert, FULCIO_GITHUB_WORKFLOW_NAME_OID),
    }


def _extract_der_extension_value(cert: x509.Certificate, oid: ObjectIdentifier) -> str | None:
    try:
        extension = cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None

    value = extension.value
    raw = value.value if isinstance(value, x509.UnrecognizedExtension) else getattr(value, "value", b"")
    return _decode_der_utf8_string(raw)


def _validate_fulcio_claim_allowlist(
    *,
    label: str,
    claim_value: str | None,
    allowed_values: set[str] | None,
) -> None:
    if not allowed_values:
        return
    if not claim_value:
        raise ValueError(f"Sigstore certificate is missing the Fulcio {label} extension.")
    if claim_value not in allowed_values:
        raise ValueError(
            f"Sigstore certificate {label} is not in the allowed set: {sorted(allowed_values)}."
        )


def _validate_github_claim_allowlists(
    *,
    github_claims: dict[str, str | None],
    allowed_repositories: set[str] | None,
    allowed_refs: set[str] | None,
    allowed_shas: set[str] | None,
    allowed_triggers: set[str] | None,
    allowed_workflow_names: set[str] | None,
) -> None:
    _validate_github_repository_allowlist(github_claims.get("repository"), allowed_repositories)
    _validate_github_string_allowlist(
        label="Ref",
        claim_value=github_claims.get("ref"),
        allowed_values=allowed_refs,
    )
    _validate_github_sha_allowlist(github_claims.get("sha"), allowed_shas)
    _validate_github_string_allowlist(
        label="Trigger",
        claim_value=github_claims.get("trigger"),
        allowed_values=allowed_triggers,
    )
    _validate_github_string_allowlist(
        label="Workflow Name",
        claim_value=github_claims.get("workflow_name"),
        allowed_values=allowed_workflow_names,
    )


def _validate_github_repository_allowlist(
    claim_value: str | None,
    allowed_values: set[str] | None,
) -> None:
    if not allowed_values:
        return
    if not claim_value:
        raise ValueError("Sigstore certificate is missing the GitHub Repository claim.")
    normalized_claim = _normalize_github_repository_value(claim_value)
    normalized_allowed = {_normalize_github_repository_value(value) for value in allowed_values}
    if normalized_claim not in normalized_allowed:
        raise ValueError(
            "Sigstore certificate GitHub Repository is not in the allowed set: "
            f"{sorted(allowed_values)}."
        )


def _validate_github_sha_allowlist(
    claim_value: str | None,
    allowed_values: set[str] | None,
) -> None:
    if not allowed_values:
        return
    if not claim_value:
        raise ValueError("Sigstore certificate is missing the GitHub SHA claim.")
    normalized_claim = _normalize_github_sha(claim_value)
    normalized_allowed = {_normalize_github_sha(value) for value in allowed_values}
    if normalized_claim not in normalized_allowed:
        raise ValueError(
            "Sigstore certificate GitHub SHA is not in the allowed set: "
            f"{sorted(allowed_values)}."
        )


def _validate_github_string_allowlist(
    *,
    label: str,
    claim_value: str | None,
    allowed_values: set[str] | None,
) -> None:
    if not allowed_values:
        return
    if not claim_value:
        raise ValueError(f"Sigstore certificate is missing the GitHub {label} claim.")
    if claim_value not in allowed_values:
        raise ValueError(
            f"Sigstore certificate GitHub {label} is not in the allowed set: {sorted(allowed_values)}."
        )


def _verify_signature_with_certificate(cert: x509.Certificate, signature: bytes, digest: bytes) -> None:
    public_key = cert.public_key()

    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, digest)
            return
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, digest, padding.PKCS1v15(), hashes.SHA256())
            return
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, digest, ec.ECDSA(hashes.SHA256()))
            return
    except InvalidSignature as exc:
        raise ValueError("Sigstore bundle signature verification failed.") from exc

    raise ValueError(f"Unsupported Sigstore certificate public-key type: {type(public_key).__name__}.")


def _verify_signature_with_hint_signer(
    signature: bytes,
    digest: bytes,
    hint: str,
    signer: dict[str, str],
) -> None:
    algorithm = signer.get("algorithm", "ed25519")
    if algorithm != "ed25519":
        raise ValueError(f"Unsupported Sigstore publicKeyIdentifier algorithm: {algorithm}.")

    public_key_bytes = supplier_signatures._decode_public_key(signer["public_key"])
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature, digest)
    except InvalidSignature as exc:
        raise ValueError(
            f"Sigstore publicKeyIdentifier signature verification failed for trusted hint '{hint}'."
        ) from exc


def _decode_b64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{label} is not valid base64.") from exc


def _normalize_fingerprint(value: str) -> str:
    normalized = value.strip().lower().replace(":", "")
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise ValueError("Sigstore certificate fingerprints must be 64 hex characters (optionally colon-delimited).")
    return normalized


def _load_string_allowlist(extra_values: Optional[list[str]], env_name: str) -> set[str]:
    values = {value.strip() for value in extra_values or [] if value and value.strip()}
    for value in os.getenv(env_name, "").split(","):
        value = value.strip()
        if value:
            values.add(value)
    return values


def _normalize_github_repository_value(value: str) -> str:
    normalized = value.strip().rstrip("/")
    if "://" not in normalized:
        return normalized.lower()
    try:
        from urllib.parse import urlparse

        parsed = urlparse(normalized)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}".lower()
    except Exception:
        pass
    return normalized.lower()


def _normalize_github_sha(value: str) -> str:
    normalized = value.strip().lower()
    if ":" in normalized:
        normalized = normalized.split(":", 1)[1]
    return normalized


def _certificate_not_before(cert: x509.Certificate) -> dt.datetime:
    value = getattr(cert, "not_valid_before_utc", None)
    if value is not None:
        return value
    return cert.not_valid_before.replace(tzinfo=dt.timezone.utc)


def _certificate_not_after(cert: x509.Certificate) -> dt.datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert.not_valid_after.replace(tzinfo=dt.timezone.utc)


def _decode_der_utf8_string(raw: bytes) -> str:
    if not raw:
        raise ValueError("Sigstore OIDC issuer extension is empty.")
    if raw[0] != 0x0C:
        raise ValueError("Sigstore OIDC issuer extension is not a DER-encoded UTF8String.")

    length, offset = _decode_der_length(raw, 1)
    end = offset + length
    if end != len(raw):
        raise ValueError("Sigstore OIDC issuer extension contains trailing bytes.")
    try:
        return raw[offset:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Sigstore OIDC issuer extension is not valid UTF-8.") from exc


def _decode_der_length(raw: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(raw):
        raise ValueError("Invalid DER payload.")
    first = raw[offset]
    offset += 1
    if first < 0x80:
        return first, offset

    num_octets = first & 0x7F
    if num_octets == 0 or num_octets > 4:
        raise ValueError("Unsupported DER length encoding.")
    if offset + num_octets > len(raw):
        raise ValueError("Invalid DER length payload.")

    length = 0
    for byte in raw[offset : offset + num_octets]:
        length = (length << 8) | byte
    return length, offset + num_octets
