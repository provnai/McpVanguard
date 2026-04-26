"""
core/capability_fingerprint.py
Passive capability fingerprint helpers for MCP initialize and tools/list responses.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
from typing import Any, List, Dict, Optional
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from core import signing

MANIFEST_VERSION = 1
CAPABILITY_MANIFEST_SIGNATURE = "capability-manifest.sig.json"

@dataclass
class AttestationDrift:
    """Detailed record of a capability deviation."""
    section: str  # "initialize" or "tools"
    drift_type: str  # "mismatch", "missing", "unexpected"
    feature: Optional[str] = None  # tool name or capability key
    details: str = ""

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.section == other or self.feature == other or self.details == other
        if isinstance(other, AttestationDrift):
            return (
                self.section == other.section
                and self.drift_type == other.drift_type
                and self.feature == other.feature
                and self.details == other.details
            )
        return False

    def __str__(self) -> str:
        feature = f" [{self.feature}]" if self.feature else ""
        return f"{self.section}{feature}: {self.drift_type} - {self.details}"

@dataclass
class AttestationResult:
    is_valid: bool
    drifts: List[AttestationDrift] = field(default_factory=list)
    risk_impact: float = 0.0


def build_capability_manifest(
    *,
    initialize_payload: dict[str, Any] | None = None,
    tools_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "version": MANIFEST_VERSION,
        "initialize": None,
        "tools": None,
    }

    if initialize_payload is not None:
        manifest["initialize"] = fingerprint_initialize_payload(initialize_payload)
    if tools_payload is not None:
        manifest["tools"] = fingerprint_tools_payload(tools_payload)

    return manifest


def fingerprint_initialize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, dict):
        raise ValueError("Initialize payload must contain a result object.")

    capabilities = result.get("capabilities")
    normalized_capabilities = _normalize_json(capabilities if isinstance(capabilities, dict) else {})
    instructions = result.get("instructions")
    instructions_hash = None
    if isinstance(instructions, str) and instructions.strip():
        instructions_hash = _sha256_json_string(instructions)

    return {
        "protocolVersion": result.get("protocolVersion"),
        "serverInfo": _normalize_json(result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}),
        "capabilities": normalized_capabilities,
        "capabilities_sha256": _sha256_json(normalized_capabilities),
        "instructions_sha256": instructions_hash,
    }


def fingerprint_tools_payload(payload: dict[str, Any]) -> dict[str, Any]:
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, dict):
        raise ValueError("Tools payload must contain a result object.")

    tools = result.get("tools")
    if not isinstance(tools, list):
        raise ValueError("Tools payload must contain a tools list.")

    normalized_tools: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        annotations = tool.get("annotations")
        input_schema = tool.get("inputSchema")
        normalized_tools.append(
            {
                "name": tool.get("name"),
                "title": tool.get("title"),
                "description_sha256": _sha256_json_string(tool.get("description")) if isinstance(tool.get("description"), str) else None,
                "annotations": _normalize_json(annotations if isinstance(annotations, dict) else {}),
                "inputSchema": _normalize_json(input_schema if isinstance(input_schema, dict) else {}),
                "inputSchema_sha256": _sha256_json(
                    _normalize_json(input_schema if isinstance(input_schema, dict) else {})
                ),
            }
        )

    normalized_tools.sort(key=lambda item: (str(item.get("name") or ""), str(item.get("title") or "")))
    return {
        "count": len(normalized_tools),
        "tools": normalized_tools,
        "tools_sha256": _sha256_json(normalized_tools),
    }


def compare_capability_manifests(expected: dict[str, Any], actual: dict[str, Any]) -> list[AttestationDrift]:
    drifts: list[AttestationDrift] = []
    
    # 1. Check Initialize Section
    exp_init = expected.get("initialize")
    act_init = actual.get("initialize")
    if exp_init and not act_init:
        drifts.append(AttestationDrift("initialize", "missing", details="Pinned initialize manifest missing in actual response."))
    elif act_init and not exp_init:
        drifts.append(AttestationDrift("initialize", "unexpected", details="Actual initialize manifest present but not pinned."))
    elif exp_init != act_init:
        # Shallow check for now, can be deepened
        drifts.append(AttestationDrift("initialize", "mismatch", details="Initialization capabilities do not match pinned state."))

    # 2. Check Tools Section (Deeper Analysis)
    exp_tools_wrapper = expected.get("tools") or {}
    act_tools_wrapper = actual.get("tools") or {}
    
    exp_tools = {t["name"]: t for t in exp_tools_wrapper.get("tools", []) if "name" in t}
    act_tools = {t["name"]: t for t in act_tools_wrapper.get("tools", []) if "name" in t}
    
    # Check for missing tools
    for name in exp_tools:
        if name not in act_tools:
            drifts.append(AttestationDrift("tools", "missing", feature=name, details=f"Pinned tool '{name}' is missing from actual server."))
            
    # Check for unexpected/unauthorized tools (Critical Drift)
    for name, tool in act_tools.items():
        if name not in exp_tools:
            drifts.append(AttestationDrift("tools", "unexpected", feature=name, details=f"Unauthorized tool '{name}' detected (not in pinned manifest)."))
        else:
            # Check for input schema drift (Subtle context poisoning)
            if tool.get("inputSchema_sha256") != exp_tools[name].get("inputSchema_sha256"):
                drifts.append(AttestationDrift("tools", "mismatch", feature=name, details=f"Tool '{name}' input schema drifted from pinned state."))

    return drifts


def verify_attestation(actual: dict[str, Any], pinned: Optional[dict[str, Any]] = None) -> AttestationResult:
    """
    Higher-level helper for the Risk Engine.
    If no pinned manifest exists, attestation is considered successful (Audit only).
    """
    if not pinned:
        return AttestationResult(is_valid=True)
        
    drifts = compare_capability_manifests(pinned, actual)
    
    # Calculate risk impact: unexpected tools are CRITICAL
    impact = 0.0
    for d in drifts:
        if d.drift_type == "unexpected":
            impact += 50.0 # Huge hit for unauthorized capabilities
        elif d.drift_type == "mismatch":
            impact += 15.0
        else:
            impact += 5.0

    return AttestationResult(
        is_valid=len(drifts) == 0,
        drifts=drifts,
        risk_impact=min(100.0, impact)
    )


def compare_section(expected: dict[str, Any], actual: dict[str, Any], section: str) -> list[str]:
    if section not in {"initialize", "tools"}:
        raise ValueError(f"Unsupported capability section: {section}")
    return compare_capability_manifests({section: expected.get(section)}, {section: actual.get(section)})


def load_capability_manifest(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_capability_manifest(path: str | Path, manifest: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")


def default_capability_manifest_signature_path(path: str | os.PathLike[str]) -> Path:
    manifest_path = Path(path)
    return manifest_path.with_name(f"{manifest_path.stem}.sig.json")


def write_capability_manifest_signature(path: str | os.PathLike[str], signature_doc: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(signature_doc, indent=2) + "\n", encoding="utf-8", newline="\n")


def load_capability_manifest_signature(path: str | os.PathLike[str]) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def canonicalize_capability_manifest(manifest: dict[str, Any]) -> bytes:
    payload = {
        "version": int(manifest.get("version", MANIFEST_VERSION)),
        "initialize": manifest.get("initialize"),
        "tools": manifest.get("tools"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def capability_manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize_capability_manifest(manifest)).hexdigest()


def load_trusted_capability_signers(extra_signers: Optional[list[dict[str, str]]] = None) -> dict[str, dict[str, str]]:
    signers: dict[str, dict[str, str]] = {}

    env_path = os.getenv("VANGUARD_TRUSTED_CAPABILITY_SIGNERS_FILE")
    if env_path:
        extra_signers = list(extra_signers or []) + [signing.load_signer_file(env_path)]

    env_inline = os.getenv("VANGUARD_TRUSTED_CAPABILITY_SIGNER")
    if env_inline:
        try:
            inline_entry = json.loads(env_inline)
        except json.JSONDecodeError as exc:
            raise ValueError("VANGUARD_TRUSTED_CAPABILITY_SIGNER must contain a JSON signer document.") from exc
        extra_signers = list(extra_signers or []) + [inline_entry]

    for entry in extra_signers or []:
        key_id = entry.get("key_id")
        algorithm = entry.get("algorithm", signing.SIGNATURE_ALGORITHM)
        public_key = entry.get("public_key")
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("Trusted capability signer entry is missing key_id.")
        if algorithm != signing.SIGNATURE_ALGORITHM:
            raise ValueError(f"Unsupported trusted capability signer algorithm: {algorithm}.")
        if not isinstance(public_key, str) or not public_key.strip():
            raise ValueError(f"Trusted capability signer '{key_id}' is missing a public_key.")
        signers[key_id] = {
            "algorithm": algorithm,
            "public_key": public_key,
        }

    return signers


def sign_capability_manifest(manifest: dict[str, Any], private_key_pem: bytes, key_id: str) -> dict[str, Any]:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Signing key must be an Ed25519 private key in PEM PKCS8 format.")

    payload = canonicalize_capability_manifest(manifest)
    signature = private_key.sign(payload)
    return {
        "version": signing.SIGNATURE_VERSION,
        "algorithm": signing.SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_capability_manifest_signature(
    manifest: dict[str, Any],
    signature_doc: dict[str, Any],
    trusted_signers: dict[str, dict[str, str]],
) -> None:
    if not isinstance(signature_doc, dict):
        raise ValueError("Capability manifest signature document is invalid.")

    algorithm = signature_doc.get("algorithm")
    if algorithm != signing.SIGNATURE_ALGORITHM:
        raise ValueError(f"Unsupported capability manifest signature algorithm: {algorithm}.")

    key_id = signature_doc.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("Capability manifest signature is missing key_id.")

    signer = trusted_signers.get(key_id)
    if signer is None:
        raise ValueError(f"Capability manifest signer '{key_id}' is not trusted by this McpVanguard build.")

    expected_digest = signature_doc.get("manifest_sha256")
    actual_digest = capability_manifest_sha256(manifest)
    if expected_digest and expected_digest != actual_digest:
        raise ValueError("Capability manifest signature metadata does not match the manifest digest.")

    public_key_bytes = _decode_public_key(signer["public_key"])
    signature_bytes = _decode_signature(signature_doc.get("signature", ""))
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature_bytes, canonicalize_capability_manifest(manifest))
    except InvalidSignature as exc:
        raise ValueError("Detached capability manifest signature verification failed.") from exc


def evaluate_capability_manifest_signature(
    manifest: dict[str, Any],
    *,
    signature_doc: dict[str, Any] | None,
    trusted_signers: dict[str, dict[str, str]],
    require_signature: bool = True,
) -> list[str]:
    if signature_doc is None:
        return ["Capability manifest is unsigned."] if require_signature else []
    try:
        verify_capability_manifest_signature(manifest, signature_doc, trusted_signers)
    except Exception as exc:
        return [f"Capability manifest signature verification failed: {exc}"]
    return []


def _normalize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalize_json(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    return value


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sha256_json_string(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _decode_public_key(public_key_b64: str) -> bytes:
    try:
        raw = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Trusted capability signer public key is not valid base64.") from exc
    if len(raw) != 32:
        raise ValueError("Trusted capability signer public key must decode to 32 raw Ed25519 bytes.")
    return raw


def _decode_signature(signature_b64: str) -> bytes:
    try:
        raw = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Capability manifest signature is not valid base64.") from exc
    if len(raw) != 64:
        raise ValueError("Capability manifest signature must decode to 64 raw Ed25519 bytes.")
    return raw
