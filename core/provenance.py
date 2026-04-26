"""
core/provenance.py
Minimal provenance verification helpers for upstream server baselines.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core import signing


PROVENANCE_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_PREFIX = "https://slsa.dev/provenance/"


def load_provenance(path: str | os.PathLike[str]) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def default_provenance_signature_path(path: str | os.PathLike[str]) -> Path:
    provenance_path = Path(path)
    return provenance_path.with_name(f"{provenance_path.stem}.sig.json")


def write_provenance_signature(path: str | os.PathLike[str], signature_doc: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(signature_doc, indent=2) + "\n", encoding="utf-8", newline="\n")


def load_provenance_signature(path: str | os.PathLike[str]) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def canonicalize_provenance(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def provenance_sha256(document: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize_provenance(document)).hexdigest()


def load_trusted_provenance_signers(extra_signers: Optional[list[dict[str, str]]] = None) -> dict[str, dict[str, str]]:
    signers: dict[str, dict[str, str]] = {}

    env_path = os.getenv("VANGUARD_TRUSTED_PROVENANCE_SIGNERS_FILE")
    if env_path:
        extra_signers = list(extra_signers or []) + [signing.load_signer_file(env_path)]

    env_inline = os.getenv("VANGUARD_TRUSTED_PROVENANCE_SIGNER")
    if env_inline:
        try:
            inline_entry = json.loads(env_inline)
        except json.JSONDecodeError as exc:
            raise ValueError("VANGUARD_TRUSTED_PROVENANCE_SIGNER must contain a JSON signer document.") from exc
        extra_signers = list(extra_signers or []) + [inline_entry]

    for entry in extra_signers or []:
        key_id = entry.get("key_id")
        algorithm = entry.get("algorithm", signing.SIGNATURE_ALGORITHM)
        public_key = entry.get("public_key")
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("Trusted provenance signer entry is missing key_id.")
        if algorithm != signing.SIGNATURE_ALGORITHM:
            raise ValueError(f"Unsupported trusted provenance signer algorithm: {algorithm}.")
        if not isinstance(public_key, str) or not public_key.strip():
            raise ValueError(f"Trusted provenance signer '{key_id}' is missing a public_key.")
        signers[key_id] = {
            "algorithm": algorithm,
            "public_key": public_key,
        }

    return signers


def sign_provenance(document: dict[str, Any], private_key_pem: bytes, key_id: str) -> dict[str, Any]:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Signing key must be an Ed25519 private key in PEM PKCS8 format.")

    payload = canonicalize_provenance(document)
    signature = private_key.sign(payload)
    return {
        "version": signing.SIGNATURE_VERSION,
        "algorithm": signing.SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_provenance_signature(
    document: dict[str, Any],
    signature_doc: dict[str, Any],
    trusted_signers: dict[str, dict[str, str]],
) -> None:
    if not isinstance(signature_doc, dict):
        raise ValueError("Provenance signature document is invalid.")

    algorithm = signature_doc.get("algorithm")
    if algorithm != signing.SIGNATURE_ALGORITHM:
        raise ValueError(f"Unsupported provenance signature algorithm: {algorithm}.")

    key_id = signature_doc.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("Provenance signature is missing key_id.")

    signer = trusted_signers.get(key_id)
    if signer is None:
        raise ValueError(f"Provenance signer '{key_id}' is not trusted by this McpVanguard build.")

    expected_digest = signature_doc.get("payload_sha256")
    actual_digest = provenance_sha256(document)
    if expected_digest and expected_digest != actual_digest:
        raise ValueError("Provenance signature metadata does not match the provenance digest.")

    public_key_bytes = _decode_public_key(signer["public_key"])
    signature_bytes = _decode_signature(signature_doc.get("signature", ""))
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    try:
        public_key.verify(signature_bytes, canonicalize_provenance(document))
    except InvalidSignature as exc:
        raise ValueError("Detached provenance signature verification failed.") from exc


def evaluate_provenance_signature(
    document: dict[str, Any],
    *,
    signature_doc: dict[str, Any] | None,
    trusted_signers: dict[str, dict[str, str]],
    require_signature: bool = True,
) -> list[str]:
    if signature_doc is None:
        return ["Upstream provenance is unsigned."] if require_signature else []

    try:
        verify_provenance_signature(document, signature_doc, trusted_signers)
    except Exception as exc:
        return [f"Upstream provenance signature verification failed: {exc}"]
    return []


def evaluate_provenance_for_server_manifest(
    manifest: dict[str, Any],
    provenance_doc: dict[str, Any],
    *,
    required_builder_ids: set[str] | None = None,
) -> list[str]:
    issues: list[str] = []

    statement_type = provenance_doc.get("_type")
    if statement_type != PROVENANCE_STATEMENT_TYPE:
        issues.append(
            f"Upstream provenance must be an in-toto Statement (`{PROVENANCE_STATEMENT_TYPE}`), got '{statement_type}'."
        )
        return issues

    subjects = provenance_doc.get("subject")
    if not isinstance(subjects, list) or not subjects:
        issues.append("Upstream provenance is missing a non-empty `subject` list.")
        return issues

    executable_hash = ((manifest.get("executable") or {}).get("sha256"))
    if not executable_hash:
        issues.append(
            "Upstream provenance verification requires `executable.sha256`; generate and enforce the server baseline with executable hashing enabled."
        )
        return issues

    if not _subjects_match_sha256(subjects, executable_hash):
        issues.append("Upstream provenance subjects do not match the current executable sha256.")

    if required_builder_ids:
        builder_id = _extract_builder_id(provenance_doc)
        if not builder_id:
            issues.append("Upstream provenance is missing `predicate.runDetails.builder.id`.")
        elif builder_id not in required_builder_ids:
            issues.append(
                "Upstream provenance builder.id "
                f"'{builder_id}' is not in the allowed set: {sorted(required_builder_ids)}."
            )

    return issues


def summarize_provenance(provenance_doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "_type": provenance_doc.get("_type"),
        "predicateType": provenance_doc.get("predicateType"),
        "subject_count": len(provenance_doc.get("subject") or []),
        "builder_id": _extract_builder_id(provenance_doc),
    }


def _subjects_match_sha256(subjects: list[Any], expected_sha256: str) -> bool:
    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        digest = subject.get("digest")
        if not isinstance(digest, dict):
            continue
        sha256 = digest.get("sha256")
        if isinstance(sha256, str) and sha256.lower() == expected_sha256.lower():
            return True
    return False


def _extract_builder_id(provenance_doc: dict[str, Any]) -> str | None:
    predicate = provenance_doc.get("predicate")
    if not isinstance(predicate, dict):
        return None

    run_details = predicate.get("runDetails")
    if isinstance(run_details, dict):
        builder = run_details.get("builder")
        if isinstance(builder, dict):
            builder_id = builder.get("id")
            if isinstance(builder_id, str) and builder_id.strip():
                return builder_id

    legacy_builder = predicate.get("builder")
    if isinstance(legacy_builder, dict):
        builder_id = legacy_builder.get("id")
        if isinstance(builder_id, str) and builder_id.strip():
            return builder_id

    return None


def _decode_public_key(public_key_b64: str) -> bytes:
    try:
        raw = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Trusted provenance signer public key is not valid base64.") from exc
    if len(raw) != 32:
        raise ValueError("Trusted provenance signer public key must decode to 32 raw Ed25519 bytes.")
    return raw


def _decode_signature(signature_b64: str) -> bytes:
    try:
        raw = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Provenance signature is not valid base64.") from exc
    if len(raw) != 64:
        raise ValueError("Provenance signature must decode to 64 raw Ed25519 bytes.")
    return raw
