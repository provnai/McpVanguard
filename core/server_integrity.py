"""
core/server_integrity.py
Helpers for fingerprinting wrapped upstream MCP server commands.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import shlex
import shutil
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core import signing


MANIFEST_VERSION = 1
SERVER_MANIFEST_SIGNATURE = "server-manifest.sig.json"
VALID_APPROVAL_STATUSES = {"approved", "unapproved", "experimental", "revoked"}
VALID_TRUST_LEVELS = {"unknown", "internal", "partner", "third_party"}


def build_server_manifest(
    server_command: list[str],
    *,
    cwd: str | None = None,
    hash_executable: bool = False,
    approval_status: str = "unapproved",
    trust_level: str = "unknown",
) -> dict[str, Any]:
    if not server_command:
        raise ValueError("Server command cannot be empty.")
    if approval_status not in VALID_APPROVAL_STATUSES:
        raise ValueError(f"Unsupported approval_status: {approval_status}")
    if trust_level not in VALID_TRUST_LEVELS:
        raise ValueError(f"Unsupported trust_level: {trust_level}")

    executable = server_command[0]
    resolved_executable = _resolve_executable(executable, cwd=cwd)
    package_hints = _infer_package_hints(server_command)

    manifest: dict[str, Any] = {
        "version": MANIFEST_VERSION,
        "command": {
            "argv": server_command,
            "display": shlex.join(server_command),
            "fingerprint_sha256": hashlib.sha256(
                json.dumps(server_command, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).hexdigest(),
        },
        "executable": {
            "name": executable,
            "resolved_path": str(resolved_executable) if resolved_executable else None,
            "exists": bool(resolved_executable and resolved_executable.exists()),
        },
        "runtime": {
            "cwd": os.path.abspath(cwd or os.getcwd()),
            "package_manager": package_hints["package_manager"],
            "package_identifier": package_hints["package_identifier"],
            "package_version": package_hints["package_version"],
            "image_identifier": package_hints["image_identifier"],
        },
        "trust": {
            "approval_status": approval_status,
            "trust_level": trust_level,
        },
    }

    if hash_executable and resolved_executable and resolved_executable.exists() and resolved_executable.is_file():
        manifest["executable"]["sha256"] = _sha256_file(resolved_executable)

    return manifest


def compare_server_manifests(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    drifts: list[str] = []

    expected_cmd = (((expected.get("command") or {}).get("argv")) or [])
    actual_cmd = (((actual.get("command") or {}).get("argv")) or [])
    if expected_cmd != actual_cmd:
        drifts.append("command.argv")

    expected_path = ((expected.get("executable") or {}).get("resolved_path"))
    actual_path = ((actual.get("executable") or {}).get("resolved_path"))
    if expected_path != actual_path:
        drifts.append("executable.resolved_path")

    expected_hash = ((expected.get("executable") or {}).get("sha256"))
    actual_hash = ((actual.get("executable") or {}).get("sha256"))
    if expected_hash or actual_hash:
        if expected_hash != actual_hash:
            drifts.append("executable.sha256")

    for field in ("package_manager", "package_identifier", "package_version", "image_identifier"):
        expected_value = ((expected.get("runtime") or {}).get(field))
        actual_value = ((actual.get("runtime") or {}).get(field))
        if expected_value != actual_value:
            drifts.append(f"runtime.{field}")

    return drifts


def verify_server_sbom(actual: dict[str, Any], baseline: Optional[dict[str, Any]] = None) -> tuple[bool, float, list[str]]:
    """
    Verify the server's SBOM (Software Bill of Materials) against a baseline.
    Returns: (is_valid, risk_impact, drifts)
    """
    if not baseline:
        return True, 0.0, []
        
    drifts = compare_server_manifests(baseline, actual)
    if not drifts:
        return True, 0.0, []
        
    impact = 0.0
    for d in drifts:
        if d == "executable.sha256":
            impact += 40.0 # Critical: executable changed
        elif d == "command.argv":
            impact += 25.0 # High: startup arguments changed
        else:
            impact += 10.0 # Runtime drift (package version, etc)
            
    return False, min(100.0, impact), drifts


def write_server_manifest(path: str | os.PathLike[str], manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")


def load_server_manifest(path: str | os.PathLike[str]) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def default_server_manifest_signature_path(path: str | os.PathLike[str]) -> Path:
    manifest_path = Path(path)
    return manifest_path.with_name(f"{manifest_path.stem}.sig.json")


def write_server_manifest_signature(path: str | os.PathLike[str], signature_doc: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(signature_doc, indent=2) + "\n", encoding="utf-8", newline="\n")


def load_server_manifest_signature(path: str | os.PathLike[str]) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def canonicalize_server_manifest(manifest: dict[str, Any]) -> bytes:
    payload = {
        "version": int(manifest.get("version", MANIFEST_VERSION)),
        "command": manifest.get("command") or {},
        "executable": manifest.get("executable") or {},
        "runtime": manifest.get("runtime") or {},
        "trust": manifest.get("trust") or {},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def server_manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize_server_manifest(manifest)).hexdigest()


def load_trusted_server_signers(extra_signers: Optional[list[dict[str, str]]] = None) -> dict[str, dict[str, str]]:
    signers: dict[str, dict[str, str]] = {}

    env_path = os.getenv("VANGUARD_TRUSTED_SERVER_SIGNERS_FILE")
    if env_path:
        extra_signers = list(extra_signers or []) + [signing.load_signer_file(env_path)]

    env_inline = os.getenv("VANGUARD_TRUSTED_SERVER_SIGNER")
    if env_inline:
        try:
            inline_entry = json.loads(env_inline)
        except json.JSONDecodeError as exc:
            raise ValueError("VANGUARD_TRUSTED_SERVER_SIGNER must contain a JSON signer document.") from exc
        extra_signers = list(extra_signers or []) + [inline_entry]

    for entry in extra_signers or []:
        key_id = entry.get("key_id")
        algorithm = entry.get("algorithm", signing.SIGNATURE_ALGORITHM)
        public_key = entry.get("public_key")
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("Trusted server signer entry is missing key_id.")
        if algorithm != signing.SIGNATURE_ALGORITHM:
            raise ValueError(f"Unsupported trusted server signer algorithm: {algorithm}.")
        if not isinstance(public_key, str) or not public_key.strip():
            raise ValueError(f"Trusted server signer '{key_id}' is missing a public_key.")
        signers[key_id] = {
            "algorithm": algorithm,
            "public_key": public_key,
        }

    return signers


def sign_server_manifest(manifest: dict[str, Any], private_key_pem: bytes, key_id: str) -> dict[str, Any]:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Signing key must be an Ed25519 private key in PEM PKCS8 format.")

    payload = canonicalize_server_manifest(manifest)
    signature = private_key.sign(payload)
    return {
        "version": signing.SIGNATURE_VERSION,
        "algorithm": signing.SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_server_manifest_signature(
    manifest: dict[str, Any],
    signature_doc: dict[str, Any],
    trusted_signers: dict[str, dict[str, str]],
) -> None:
    if not isinstance(signature_doc, dict):
        raise ValueError("Server manifest signature document is invalid.")

    algorithm = signature_doc.get("algorithm")
    if algorithm != signing.SIGNATURE_ALGORITHM:
        raise ValueError(f"Unsupported server manifest signature algorithm: {algorithm}.")

    key_id = signature_doc.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("Server manifest signature is missing key_id.")

    signer = trusted_signers.get(key_id)
    if signer is None:
        raise ValueError(f"Server manifest signer '{key_id}' is not trusted by this McpVanguard build.")

    expected_digest = signature_doc.get("manifest_sha256")
    actual_digest = server_manifest_sha256(manifest)
    if expected_digest and expected_digest != actual_digest:
        raise ValueError("Server manifest signature metadata does not match the manifest digest.")

    public_key_bytes = _decode_public_key(signer["public_key"])
    signature_bytes = _decode_signature(signature_doc.get("signature", ""))
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    try:
        public_key.verify(signature_bytes, canonicalize_server_manifest(manifest))
    except InvalidSignature as exc:
        raise ValueError("Detached server manifest signature verification failed.") from exc


def evaluate_server_manifest_signature(
    manifest: dict[str, Any],
    *,
    signature_doc: dict[str, Any] | None,
    trusted_signers: dict[str, dict[str, str]],
    require_signature: bool = True,
) -> list[str]:
    if signature_doc is None:
        return ["Upstream server manifest is unsigned."] if require_signature else []

    try:
        verify_server_manifest_signature(manifest, signature_doc, trusted_signers)
    except Exception as exc:
        return [f"Upstream server manifest signature verification failed: {exc}"]
    return []


def evaluate_server_manifest_approval(manifest: dict[str, Any]) -> list[str]:
    trust = manifest.get("trust") or {}
    approval_status = trust.get("approval_status", "unapproved")

    if approval_status not in VALID_APPROVAL_STATUSES:
        return [f"Upstream server manifest approval_status '{approval_status}' is unsupported."]
    if approval_status == "approved":
        return []
    if approval_status == "revoked":
        return ["Upstream server manifest trust state is revoked."]
    return [f"Upstream server manifest approval_status is '{approval_status}'."]


def _resolve_executable(executable: str, *, cwd: str | None = None) -> Path | None:
    executable_path = Path(executable)
    if executable_path.is_absolute():
        return executable_path

    search_cwd = Path(cwd) if cwd else Path.cwd()
    local_candidate = search_cwd / executable
    if local_candidate.exists():
        return local_candidate.resolve()

    resolved = shutil.which(executable, path=os.environ.get("PATH"))
    return Path(resolved) if resolved else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _infer_package_hints(server_command: list[str]) -> dict[str, str | None]:
    first = server_command[0]
    second = server_command[1] if len(server_command) > 1 else None
    third = server_command[2] if len(server_command) > 2 else None

    package_manager = None
    package_identifier = None
    package_version = None
    image_identifier = None

    if first in {"npx", "npm", "pnpm", "yarn"}:
        package_manager = first
        if second and not second.startswith("-"):
            package_identifier, package_version = _split_package_version(second)
    elif first.endswith("python") or first.endswith("python.exe") or first.endswith("python3"):
        package_manager = "python"
        if second == "-m" and third:
            package_identifier = third
    elif first == "uv" and second == "run":
        package_manager = "uv"
        if third and not third.startswith("-"):
            package_identifier = third
    elif first == "docker" and second == "run":
        package_manager = "docker"
        image_identifier = _extract_docker_image(server_command[2:])

    return {
        "package_manager": package_manager,
        "package_identifier": package_identifier,
        "package_version": package_version,
        "image_identifier": image_identifier,
    }


def _split_package_version(value: str) -> tuple[str, str | None]:
    if "@" not in value[1:]:
        return value, None
    package, version = value.rsplit("@", 1)
    return package, version or None


def _extract_docker_image(args: list[str]) -> str | None:
    for arg in args:
        if arg.startswith("-"):
            continue
        return arg
    return None


def _decode_public_key(public_key_b64: str) -> bytes:
    try:
        raw = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Trusted server signer public key is not valid base64.") from exc
    if len(raw) != 32:
        raise ValueError("Trusted server signer public key must decode to 32 raw Ed25519 bytes.")
    return raw


def _decode_signature(signature_b64: str) -> bytes:
    try:
        raw = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Server manifest signature is not valid base64.") from exc
    if len(raw) != 64:
        raise ValueError("Server manifest signature must decode to 64 raw Ed25519 bytes.")
    return raw
