"""
core/signing.py
Detached signature utilities for signed rule updates.
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

RULE_SIGNATURE = "manifest.sig.json"
SIGNATURE_VERSION = 1
SIGNATURE_ALGORITHM = "ed25519"

# Pinned signers trusted for official McpVanguard rule updates.
# The public key value is a base64-encoded 32-byte Ed25519 public key.
TRUSTED_SIGNERS: dict[str, dict[str, str]] = {
    "provnai-rules-2026q2": {
        "algorithm": SIGNATURE_ALGORITHM,
        "public_key": "Xwalc9ft9nnmzk18TC9Z8+fdErfFltJJDfxtDrBgaUw=",
    }
}


def canonicalize_manifest(manifest: dict[str, Any]) -> bytes:
    """Return the canonical byte representation used for detached signatures."""
    rules = manifest.get("rules")
    if not isinstance(rules, dict) or not rules:
        raise ValueError("Manifest is missing the required 'rules' mapping.")

    payload = {
        "version": int(manifest.get("version", 1)),
        "rules": rules,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize_manifest(manifest)).hexdigest()


def _decode_public_key(public_key_b64: str) -> bytes:
    try:
        raw = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Trusted signer public key is not valid base64.") from exc
    if len(raw) != 32:
        raise ValueError("Trusted signer public key must decode to 32 raw Ed25519 bytes.")
    return raw


def _decode_signature(signature_b64: str) -> bytes:
    try:
        raw = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Manifest signature is not valid base64.") from exc
    if len(raw) != 64:
        raise ValueError("Manifest signature must decode to 64 raw Ed25519 bytes.")
    return raw


def load_trusted_signers(extra_signers: Optional[list[dict[str, str]]] = None) -> dict[str, dict[str, str]]:
    signers = {key_id: dict(entry) for key_id, entry in TRUSTED_SIGNERS.items()}

    env_path = os.getenv("VANGUARD_TRUSTED_SIGNERS_FILE")
    if env_path:
        extra_signers = list(extra_signers or []) + [load_signer_file(env_path)]

    env_inline = os.getenv("VANGUARD_TRUSTED_SIGNER")
    if env_inline:
        try:
            inline_entry = json.loads(env_inline)
        except json.JSONDecodeError as exc:
            raise ValueError("VANGUARD_TRUSTED_SIGNER must contain a JSON signer document.") from exc
        extra_signers = list(extra_signers or []) + [inline_entry]

    for entry in extra_signers or []:
        key_id = entry.get("key_id")
        algorithm = entry.get("algorithm", SIGNATURE_ALGORITHM)
        public_key = entry.get("public_key")
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("Trusted signer entry is missing key_id.")
        if algorithm != SIGNATURE_ALGORITHM:
            raise ValueError(f"Unsupported trusted signer algorithm: {algorithm}.")
        if not isinstance(public_key, str) or not public_key.strip():
            raise ValueError(f"Trusted signer '{key_id}' is missing a public_key.")
        signers[key_id] = {
            "algorithm": algorithm,
            "public_key": public_key,
        }

    return signers


def load_signer_file(path: str | os.PathLike[str]) -> dict[str, str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if "keys" in data:
        raise ValueError("Signer registry files are not supported here; provide a single signer document.")
    return data


def generate_signing_keypair(key_id: str) -> tuple[bytes, dict[str, str]]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    public_doc = {
        "version": SIGNATURE_VERSION,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "public_key": public_b64,
    }
    return private_pem, public_doc


def sign_manifest(manifest: dict[str, Any], private_key_pem: bytes, key_id: str) -> dict[str, Any]:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Signing key must be an Ed25519 private key in PEM PKCS8 format.")

    payload = canonicalize_manifest(manifest)
    signature = private_key.sign(payload)
    return {
        "version": SIGNATURE_VERSION,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_manifest_signature(
    manifest: dict[str, Any],
    signature_doc: dict[str, Any],
    trusted_signers: dict[str, dict[str, str]],
) -> None:
    if not isinstance(signature_doc, dict):
        raise ValueError("Manifest signature document is invalid.")

    algorithm = signature_doc.get("algorithm")
    if algorithm != SIGNATURE_ALGORITHM:
        raise ValueError(f"Unsupported manifest signature algorithm: {algorithm}.")

    key_id = signature_doc.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("Manifest signature is missing key_id.")

    signer = trusted_signers.get(key_id)
    if signer is None:
        raise ValueError(f"Manifest signer '{key_id}' is not trusted by this McpVanguard build.")

    expected_digest = signature_doc.get("manifest_sha256")
    actual_digest = manifest_sha256(manifest)
    if expected_digest and expected_digest != actual_digest:
        raise ValueError("Manifest signature metadata does not match the manifest digest.")

    public_key_bytes = _decode_public_key(signer["public_key"])
    signature_bytes = _decode_signature(signature_doc.get("signature", ""))
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    try:
        public_key.verify(signature_bytes, canonicalize_manifest(manifest))
    except InvalidSignature as exc:
        raise ValueError("Detached manifest signature verification failed.") from exc


def build_rules_manifest(rules_dir: str | os.PathLike[str], filenames: list[str]) -> dict[str, Any]:
    rules_path = Path(rules_dir)
    rules: dict[str, dict[str, str]] = {}
    for filename in filenames:
        content = (rules_path / filename).read_text(encoding="utf-8")
        rules[filename] = {
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()
        }
    return {
        "version": 1,
        "rules": rules,
    }
