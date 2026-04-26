"""
core/supplier_signatures.py
Detached supplier artifact signature helpers for local upstream executables.
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


SERVER_ARTIFACT_SIGNATURE = "server-artifact.sig.json"


def load_artifact_signature(path: str | os.PathLike[str]) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_artifact_signature(path: str | os.PathLike[str], signature_doc: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(signature_doc, indent=2) + "\n", encoding="utf-8", newline="\n")


def default_artifact_signature_path(executable_path: str | os.PathLike[str]) -> Path:
    path = Path(executable_path)
    return path.with_name(f"{path.name}.sig.json")


def compute_file_sha256(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_trusted_supplier_signers(extra_signers: Optional[list[dict[str, str]]] = None) -> dict[str, dict[str, str]]:
    signers: dict[str, dict[str, str]] = {}

    env_path = os.getenv("VANGUARD_TRUSTED_SUPPLIER_SIGNERS_FILE")
    if env_path:
        extra_signers = list(extra_signers or []) + [signing.load_signer_file(env_path)]

    env_inline = os.getenv("VANGUARD_TRUSTED_SUPPLIER_SIGNER")
    if env_inline:
        try:
            inline_entry = json.loads(env_inline)
        except json.JSONDecodeError as exc:
            raise ValueError("VANGUARD_TRUSTED_SUPPLIER_SIGNER must contain a JSON signer document.") from exc
        extra_signers = list(extra_signers or []) + [inline_entry]

    for entry in extra_signers or []:
        key_id = entry.get("key_id")
        algorithm = entry.get("algorithm", signing.SIGNATURE_ALGORITHM)
        public_key = entry.get("public_key")
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("Trusted supplier signer entry is missing key_id.")
        if algorithm != signing.SIGNATURE_ALGORITHM:
            raise ValueError(f"Unsupported trusted supplier signer algorithm: {algorithm}.")
        if not isinstance(public_key, str) or not public_key.strip():
            raise ValueError(f"Trusted supplier signer '{key_id}' is missing a public_key.")
        signers[key_id] = {
            "algorithm": algorithm,
            "public_key": public_key,
            "supplier": str(entry.get("supplier") or ""),
        }

    return signers


def sign_artifact(
    artifact_path: str | os.PathLike[str],
    private_key_pem: bytes,
    key_id: str,
    *,
    supplier: str | None = None,
) -> dict[str, Any]:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Signing key must be an Ed25519 private key in PEM PKCS8 format.")

    artifact_bytes = Path(artifact_path).read_bytes()
    signature = private_key.sign(artifact_bytes)
    return {
        "version": signing.SIGNATURE_VERSION,
        "algorithm": signing.SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "file_name": Path(artifact_path).name,
        "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "supplier": supplier,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_artifact_signature(
    artifact_path: str | os.PathLike[str],
    signature_doc: dict[str, Any],
    trusted_signers: dict[str, dict[str, str]],
    *,
    allowed_suppliers: set[str] | None = None,
) -> None:
    if not isinstance(signature_doc, dict):
        raise ValueError("Artifact signature document is invalid.")

    algorithm = signature_doc.get("algorithm")
    if algorithm != signing.SIGNATURE_ALGORITHM:
        raise ValueError(f"Unsupported artifact signature algorithm: {algorithm}.")

    key_id = signature_doc.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("Artifact signature is missing key_id.")

    signer = trusted_signers.get(key_id)
    if signer is None:
        raise ValueError(f"Supplier artifact signer '{key_id}' is not trusted by this McpVanguard build.")

    supplier = str(signature_doc.get("supplier") or signer.get("supplier") or "").strip()
    if allowed_suppliers and supplier not in allowed_suppliers:
        raise ValueError(f"Supplier '{supplier or '<missing>'}' is not in the allowed supplier set: {sorted(allowed_suppliers)}.")

    artifact_bytes = Path(artifact_path).read_bytes()
    expected_digest = signature_doc.get("artifact_sha256")
    actual_digest = hashlib.sha256(artifact_bytes).hexdigest()
    if expected_digest and expected_digest != actual_digest:
        raise ValueError("Artifact signature metadata does not match the artifact digest.")

    public_key_bytes = _decode_public_key(signer["public_key"])
    signature_bytes = _decode_signature(signature_doc.get("signature", ""))
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    try:
        public_key.verify(signature_bytes, artifact_bytes)
    except InvalidSignature as exc:
        raise ValueError("Detached artifact signature verification failed.") from exc


def evaluate_artifact_signature(
    artifact_path: str | os.PathLike[str] | None,
    *,
    signature_doc: dict[str, Any] | None,
    trusted_signers: dict[str, dict[str, str]],
    require_signature: bool = True,
    allowed_suppliers: set[str] | None = None,
) -> list[str]:
    if artifact_path is None:
        return ["Supplier artifact verification requires a local resolved executable path."]
    if signature_doc is None:
        return ["Resolved executable is unsigned by a trusted supplier."] if require_signature else []

    try:
        verify_artifact_signature(
            artifact_path,
            signature_doc,
            trusted_signers,
            allowed_suppliers=allowed_suppliers,
        )
    except Exception as exc:
        return [f"Supplier artifact signature verification failed: {exc}"]
    return []


def _decode_public_key(public_key_b64: str) -> bytes:
    try:
        raw = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Trusted supplier signer public key is not valid base64.") from exc
    if len(raw) != 32:
        raise ValueError("Trusted supplier signer public key must decode to 32 raw Ed25519 bytes.")
    return raw


def _decode_signature(signature_b64: str) -> bytes:
    try:
        raw = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Artifact signature is not valid base64.") from exc
    if len(raw) != 64:
        raise ValueError("Artifact signature must decode to 64 raw Ed25519 bytes.")
    return raw
