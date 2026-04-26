"""
core/auth.py
Verified bearer-token authentication helpers for optional OAuth-style mode.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa


class AuthValidationError(Exception):
    """Raised when a bearer token fails validation."""


# Deterministic mapping from tool prefixes to required OAuth scopes
TOOL_SCOPE_MAPPING = {
    "read_file": "scope:io",
    "write_file": "scope:io",
    "list_directory": "scope:io",
    "get_file_info": "scope:io",
    "read_resource": "scope:io",
    "write_resource": "scope:io",
    "shell": "scope:exec",
    "exec": "scope:exec",
    "fetch": "scope:net",
    "http_request": "scope:net",
    "vanguard_": "scope:admin",
}


@dataclass(frozen=True)
class VerifiedBearerToken:
    claims: dict[str, Any]
    header: dict[str, Any]


@dataclass(frozen=True)
class _CachedDocument:
    payload: Any
    expires_at: float


_JWKS_CACHE: dict[str, _CachedDocument] = {}
_DISCOVERY_CACHE: dict[str, _CachedDocument] = {}
_CACHE_LOCKS: dict[str, asyncio.Lock] = {}
_CACHE_STATS = {
    "jwks_hits": 0,
    "jwks_misses": 0,
    "oidc_hits": 0,
    "oidc_misses": 0,
}


def load_auth_config() -> dict[str, Any]:
    api_key = os.getenv("VANGUARD_API_KEY", "")
    default_mode = "api_key" if api_key else "none"
    jwks_cache_ttl = int(os.getenv("VANGUARD_JWKS_CACHE_TTL_SECS", "300"))
    return {
        "AUTH_MODE": os.getenv("VANGUARD_AUTH_MODE", default_mode).strip().lower(),
        "JWKS_FILE": os.getenv("VANGUARD_JWKS_FILE", "").strip(),
        "JWKS_JSON": os.getenv("VANGUARD_JWKS_JSON", "").strip(),
        "JWKS_URL": os.getenv("VANGUARD_JWKS_URL", "").strip(),
        "OAUTH_DISCOVERY_URL": os.getenv("VANGUARD_OAUTH_DISCOVERY_URL", "").strip(),
        "EXPECTED_BEARER_ISSUER": os.getenv("VANGUARD_EXPECTED_BEARER_ISSUER", "").strip(),
        "EXPECTED_BEARER_AUDIENCE": [aud.strip() for aud in os.getenv("VANGUARD_EXPECTED_BEARER_AUDIENCE", "").split(",") if aud.strip()],
        "AUTH_CLOCK_SKEW_SECS": int(os.getenv("VANGUARD_AUTH_CLOCK_SKEW_SECS", "60")),
        "JWKS_CACHE_TTL_SECS": jwks_cache_ttl,
        "DISCOVERY_CACHE_TTL_SECS": int(os.getenv("VANGUARD_DISCOVERY_CACHE_TTL_SECS", str(jwks_cache_ttl))),
        "JWKS_REFRESH_ON_KID_MISS": os.getenv("VANGUARD_JWKS_REFRESH_ON_KID_MISS", "true").lower() == "true",
        "OAUTH_HTTP_TIMEOUT_SECS": float(os.getenv("VANGUARD_OAUTH_HTTP_TIMEOUT_SECS", "5.0")),
    }


async def validate_bearer_token(token: str, cfg: dict[str, Any] | None = None) -> VerifiedBearerToken:
    config = cfg or load_auth_config()
    header_b64, payload_b64, signature_b64 = _split_jwt(token)
    header = _decode_json_segment(header_b64, "token header")
    claims = _decode_json_segment(payload_b64, "token payload")

    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise AuthValidationError("Bearer token must contain JSON header and payload.")

    alg = str(header.get("alg", "")).strip()
    if not alg or alg.lower() == "none":
        raise AuthValidationError("Bearer token must use a signed JWT algorithm.")

    try:
        jwk = _select_jwk(await _load_jwks(config), header)
    except AuthValidationError as exc:
        if not _can_refresh_dynamic_jwks(config, header, exc):
            raise
        jwk = _select_jwk(await _load_jwks(config, force_refresh=True), header)
    _verify_signature(alg, jwk, f"{header_b64}.{payload_b64}".encode("ascii"), _b64url_decode(signature_b64))
    _validate_registered_claims(claims, config)
    return VerifiedBearerToken(claims=claims, header=header)


def fingerprint_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def clear_auth_caches(scope: str = "all", target_url: str | None = None) -> dict[str, Any]:
    normalized_scope = _normalize_cache_scope(scope)
    normalized_target = (target_url or "").strip()

    jwks_keys = _matching_cache_keys(_JWKS_CACHE, normalized_target) if normalized_scope in {"all", "jwks"} else []
    discovery_keys = _matching_cache_keys(_DISCOVERY_CACHE, normalized_target) if normalized_scope in {"all", "discovery"} else []

    for key in jwks_keys:
        _JWKS_CACHE.pop(key, None)
    for key in discovery_keys:
        _DISCOVERY_CACHE.pop(key, None)

    lock_keys = set(jwks_keys + discovery_keys)
    if normalized_target and normalized_scope in {"all", "jwks", "discovery"}:
        lock_keys.add(normalized_target)
    for key in lock_keys:
        _CACHE_LOCKS.pop(key, None)

    return {
        "scope": normalized_scope,
        "target_url": normalized_target or None,
        "jwks_entries_cleared": len(jwks_keys),
        "discovery_entries_cleared": len(discovery_keys),
        "lock_entries_cleared": len(lock_keys),
    }


def get_auth_cache_stats() -> dict[str, Any]:
    stats = dict(_CACHE_STATS)
    stats.update(
        {
            "jwks_entries": len(_JWKS_CACHE),
            "oidc_entries": len(_DISCOVERY_CACHE),
            "jwks_cached_urls": sorted(_JWKS_CACHE.keys()),
            "oidc_cached_urls": sorted(_DISCOVERY_CACHE.keys()),
        }
    )
    return stats


async def refresh_auth_caches(cfg: dict[str, Any] | None = None, *, scope: str = "all") -> dict[str, Any]:
    config = cfg or load_auth_config()
    normalized_scope = _normalize_cache_scope(scope)
    result: dict[str, Any] = {
        "scope": normalized_scope,
        "jwks_refreshed": False,
        "discovery_refreshed": False,
        "jwks_source": None,
    }
    refreshed_metadata: Any = None

    if normalized_scope in {"all", "discovery"} and _has_discovery_source(config):
        refreshed_metadata, metadata_url = await _load_discovery_metadata(config, force_refresh=True)
        result["discovery_refreshed"] = True
        result["discovery_url"] = metadata_url
        if isinstance(refreshed_metadata, dict):
            result["discovery_jwks_uri"] = refreshed_metadata.get("jwks_uri")

    if normalized_scope in {"all", "jwks"}:
        payload: Any = None
        if config.get("JWKS_JSON"):
            payload = json.loads(config["JWKS_JSON"])
            result["jwks_source"] = "inline_json"
            result["jwks_refreshed"] = True
        elif config.get("JWKS_FILE"):
            with open(config["JWKS_FILE"], "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            result["jwks_source"] = "file"
            result["jwks_refreshed"] = True
            result["jwks_file"] = config["JWKS_FILE"]
        elif config.get("JWKS_URL"):
            payload = await _load_remote_document(
                _JWKS_CACHE,
                config["JWKS_URL"],
                ttl_secs=int(config.get("JWKS_CACHE_TTL_SECS", 300)),
                timeout_secs=float(config.get("OAUTH_HTTP_TIMEOUT_SECS", 5.0)),
                force_refresh=True,
                label="JWKS",
            )
            result["jwks_source"] = "jwks_url"
            result["jwks_refreshed"] = True
            result["jwks_url"] = config["JWKS_URL"]
        elif _has_discovery_source(config):
            jwks_uri = None
            discovery_url = None
            if isinstance(refreshed_metadata, dict):
                jwks_uri = refreshed_metadata.get("jwks_uri")
            if refreshed_metadata is None:
                refreshed_metadata, discovery_url = await _load_discovery_metadata(config, force_refresh=True)
                if isinstance(refreshed_metadata, dict):
                    jwks_uri = refreshed_metadata.get("jwks_uri")
            if isinstance(jwks_uri, str) and jwks_uri.strip():
                payload = await _load_remote_document(
                    _JWKS_CACHE,
                    jwks_uri.strip(),
                    ttl_secs=int(config.get("JWKS_CACHE_TTL_SECS", 300)),
                    timeout_secs=float(config.get("OAUTH_HTTP_TIMEOUT_SECS", 5.0)),
                    force_refresh=True,
                    label="discovered JWKS",
                )
            else:
                payload = await _load_jwks_from_discovery(config, force_refresh=True)
            result["jwks_source"] = "discovery"
            result["jwks_refreshed"] = True
            result["discovery_refreshed"] = True
            result["discovery_url"] = discovery_url or _resolve_discovery_urls(config)[0]
        else:
            raise AuthValidationError(
                "Auth cache refresh requires VANGUARD_JWKS_JSON, VANGUARD_JWKS_FILE, "
                "VANGUARD_JWKS_URL, or discovery configuration."
            )

        keys = _extract_jwks_keys(payload)
        result["jwks_key_count"] = len(keys)

    return result


def _split_jwt(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise AuthValidationError("Bearer token must be a JWT with three segments.")
    return parts[0], parts[1], parts[2]


def _decode_json_segment(segment: str, label: str) -> dict[str, Any]:
    try:
        decoded = _b64url_decode(segment).decode("utf-8")
        value = json.loads(decoded)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthValidationError(f"Invalid {label}.") from exc
    return value


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except ValueError as exc:
        raise AuthValidationError("Invalid base64url encoding in bearer token.") from exc


async def _load_jwks(cfg: dict[str, Any], *, force_refresh: bool = False) -> list[dict[str, Any]]:
    jwks_json = cfg.get("JWKS_JSON", "")
    jwks_file = cfg.get("JWKS_FILE", "")
    jwks_url = cfg.get("JWKS_URL", "")

    if jwks_json:
        payload = json.loads(jwks_json)
    elif jwks_file:
        with open(jwks_file, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    elif jwks_url:
        payload = await _load_remote_document(
            _JWKS_CACHE,
            jwks_url,
            ttl_secs=int(cfg.get("JWKS_CACHE_TTL_SECS", 300)),
            timeout_secs=float(cfg.get("OAUTH_HTTP_TIMEOUT_SECS", 5.0)),
            force_refresh=force_refresh,
            label="JWKS",
        )
    elif _has_discovery_source(cfg):
        payload = await _load_jwks_from_discovery(cfg, force_refresh=force_refresh)
    else:
        raise AuthValidationError(
            "OAuth mode requires VANGUARD_JWKS_JSON, VANGUARD_JWKS_FILE, "
            "VANGUARD_JWKS_URL, or discovery configuration."
        )

    if isinstance(payload, dict) and isinstance(payload.get("keys"), list):
        return _extract_jwks_keys(payload)
    if isinstance(payload, list):
        return _extract_jwks_keys(payload)
    raise AuthValidationError("JWKS payload must contain a 'keys' array.")


def _has_discovery_source(cfg: dict[str, Any]) -> bool:
    return bool(cfg.get("OAUTH_DISCOVERY_URL") or cfg.get("EXPECTED_BEARER_ISSUER"))


def _can_refresh_dynamic_jwks(cfg: dict[str, Any], header: dict[str, Any], exc: AuthValidationError) -> bool:
    if not cfg.get("JWKS_REFRESH_ON_KID_MISS", True):
        return False
    if not _uses_dynamic_jwks(cfg):
        return False
    if "kid" not in header:
        return False
    return "No JWKS key matched token kid" in str(exc)


def _uses_dynamic_jwks(cfg: dict[str, Any]) -> bool:
    return bool(cfg.get("JWKS_URL") or _has_discovery_source(cfg))


async def _load_jwks_from_discovery(cfg: dict[str, Any], *, force_refresh: bool = False) -> Any:
    metadata, metadata_url = await _load_discovery_metadata(cfg, force_refresh=force_refresh)
    if not isinstance(metadata, dict):
        raise AuthValidationError("OAuth discovery metadata must be a JSON object.")

    jwks_uri = metadata.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri.strip():
        raise AuthValidationError("OAuth discovery metadata did not include a valid jwks_uri.")

    return await _load_remote_document(
        _JWKS_CACHE,
        jwks_uri.strip(),
        ttl_secs=int(cfg.get("JWKS_CACHE_TTL_SECS", 300)),
        timeout_secs=float(cfg.get("OAUTH_HTTP_TIMEOUT_SECS", 5.0)),
        force_refresh=force_refresh,
        label="discovered JWKS",
    )


def _resolve_discovery_urls(cfg: dict[str, Any]) -> list[str]:
    explicit = cfg.get("OAUTH_DISCOVERY_URL", "")
    if explicit:
        return [explicit]

    issuer = str(cfg.get("EXPECTED_BEARER_ISSUER", "")).strip()
    if not issuer:
        raise AuthValidationError("OAuth discovery requires OAUTH_DISCOVERY_URL or EXPECTED_BEARER_ISSUER.")
    base = issuer.rstrip("/")
    return [
        base + "/.well-known/openid-configuration",
        base + "/.well-known/oauth-authorization-server",
    ]


async def _load_discovery_metadata(cfg: dict[str, Any], *, force_refresh: bool = False) -> tuple[dict[str, Any], str]:
    last_error: Optional[Exception] = None
    for metadata_url in _resolve_discovery_urls(cfg):
        try:
            metadata = await _load_remote_document(
                _DISCOVERY_CACHE,
                metadata_url,
                ttl_secs=int(cfg.get("DISCOVERY_CACHE_TTL_SECS", cfg.get("JWKS_CACHE_TTL_SECS", 300))),
                timeout_secs=float(cfg.get("OAUTH_HTTP_TIMEOUT_SECS", 5.0)),
                force_refresh=force_refresh,
                label="OAuth discovery metadata",
            )
            _validate_discovery_metadata(metadata, cfg)
            return metadata, metadata_url
        except AuthValidationError as exc:
            last_error = exc
            if cfg.get("OAUTH_DISCOVERY_URL") or "issuer mismatch" in str(exc):
                break
            continue
    raise AuthValidationError(f"Failed to load OAuth discovery metadata: {last_error}")


def _validate_discovery_metadata(metadata: Any, cfg: dict[str, Any]) -> None:
    if not isinstance(metadata, dict):
        raise AuthValidationError("OAuth discovery metadata must be a JSON object.")

    expected_issuer = str(cfg.get("EXPECTED_BEARER_ISSUER", "")).strip()
    if expected_issuer:
        issuer = metadata.get("issuer")
        if not isinstance(issuer, str) or not issuer.strip():
            raise AuthValidationError("OAuth discovery metadata did not include a valid issuer.")
        if issuer != expected_issuer:
            raise AuthValidationError(
                f"OAuth discovery issuer mismatch (expected {expected_issuer}, got {issuer})."
            )


async def _load_remote_document(
    cache: dict[str, _CachedDocument],
    url: str,
    *,
    ttl_secs: int,
    timeout_secs: float,
    force_refresh: bool,
    label: str,
) -> Any:
    cache_key = url.strip()
    if not cache_key:
        raise AuthValidationError(f"{label} URL cannot be empty.")

    now = time.time()
    cached = cache.get(cache_key)
    if not force_refresh and cached and cached.expires_at > now:
        _record_cache_stat(label, hit=True)
        return cached.payload

    if cache_key not in _CACHE_LOCKS:
        _CACHE_LOCKS[cache_key] = asyncio.Lock()

    async with _CACHE_LOCKS[cache_key]:
        # Double-check inside lock
        now = time.time()
        cached = cache.get(cache_key)
        if not force_refresh and cached and cached.expires_at > now:
            _record_cache_stat(label, hit=True)
            return cached.payload

        _record_cache_stat(label, hit=False)
        payload = await _fetch_json_document(cache_key, timeout_secs=timeout_secs, label=label)
        cache[cache_key] = _CachedDocument(payload=payload, expires_at=now + max(ttl_secs, 0))
        return payload


async def _fetch_json_document(url: str, *, timeout_secs: float, label: str) -> Any:
    try:
        async with httpx.AsyncClient(timeout=timeout_secs, follow_redirects=True) as client:
            response = await client.get(url, headers={"accept": "application/json"})
            response.raise_for_status()
            return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise AuthValidationError(f"Failed to fetch {label} from {url}: {exc}") from exc


def _select_jwk(keys: list[dict[str, Any]], header: dict[str, Any]) -> dict[str, Any]:
    kid = header.get("kid")
    x5t = header.get("x5t")
    alg = str(header.get("alg", "")).strip()

    if kid is not None:
        kid_matches = [key for key in keys if key.get("kid") == kid]
        compatible_matches = _filter_compatible_jwks(kid_matches, alg)
        if len(compatible_matches) == 1:
            return compatible_matches[0]
        if len(kid_matches) == 1:
            return kid_matches[0]
        if kid_matches:
            raise AuthValidationError(f"Multiple JWKS keys matched token kid '{kid}'.")
        raise AuthValidationError(f"No JWKS key matched token kid '{kid}'.")

    if x5t is not None:
        x5t_matches = [key for key in keys if key.get("x5t") == x5t]
        compatible_matches = _filter_compatible_jwks(x5t_matches, alg)
        if len(compatible_matches) == 1:
            return compatible_matches[0]
        if len(x5t_matches) == 1:
            return x5t_matches[0]
        if x5t_matches:
            raise AuthValidationError("Multiple JWKS keys matched token x5t.")
        raise AuthValidationError(f"No JWKS key matched token x5t '{x5t}'.")

    compatible_keys = _filter_compatible_jwks(keys, alg)
    if len(compatible_keys) == 1:
        return compatible_keys[0]
    if len(keys) == 1:
        return keys[0]
    raise AuthValidationError("Token header has no kid/x5t and JWKS contains multiple compatible keys.")


def _filter_compatible_jwks(keys: list[dict[str, Any]], alg: str) -> list[dict[str, Any]]:
    compatible: list[dict[str, Any]] = []
    for key in keys:
        if not _is_jwk_use_compatible(key):
            continue
        if not _is_jwk_alg_compatible(key, alg):
            continue
        compatible.append(key)
    return compatible


def _is_jwk_use_compatible(jwk: dict[str, Any]) -> bool:
    use = jwk.get("use")
    if use is not None and use != "sig":
        return False

    key_ops = jwk.get("key_ops")
    if isinstance(key_ops, list) and key_ops:
        allowed_ops = {op for op in key_ops if isinstance(op, str)}
        if not allowed_ops.intersection({"verify", "sign"}):
            return False
    return True


def _is_jwk_alg_compatible(jwk: dict[str, Any], alg: str) -> bool:
    jwk_alg = jwk.get("alg")
    if jwk_alg is not None and jwk_alg != alg:
        return False
    return True


def _verify_signature(alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
    if alg.startswith("HS"):
        _verify_hmac(alg, jwk, signing_input, signature)
        return
    if alg.startswith("RS"):
        _verify_rsa(alg, jwk, signing_input, signature)
        return
    if alg.startswith("ES"):
        _verify_ec(alg, jwk, signing_input, signature)
        return
    if alg == "EdDSA":
        _verify_eddsa(jwk, signing_input, signature)
        return
    raise AuthValidationError(f"Unsupported JWT algorithm '{alg}'.")


def _verify_hmac(alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
    if jwk.get("kty") != "oct":
        raise AuthValidationError("HMAC JWT requires an 'oct' JWK.")
    secret = _b64url_decode(str(jwk.get("k", "")))
    hash_alg = _hash_algorithm(alg)
    mac = crypto_hmac.HMAC(secret, hash_alg)
    mac.update(signing_input)
    expected = mac.finalize()
    if not hmac.compare_digest(expected, signature):
        raise AuthValidationError("Bearer token signature validation failed.")


def _verify_rsa(alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
    if jwk.get("kty") != "RSA":
        raise AuthValidationError("RSA JWT requires an RSA JWK.")
    public_key = _rsa_public_key_from_jwk(jwk)
    try:
        public_key.verify(signature, signing_input, padding.PKCS1v15(), _hash_algorithm(alg))
    except Exception as exc:
        raise AuthValidationError("Bearer token signature validation failed.") from exc


def _verify_ec(alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
    if jwk.get("kty") != "EC":
        raise AuthValidationError("EC JWT requires an EC JWK.")
    public_key = _ec_public_key_from_jwk(jwk)

    key_size = (public_key.curve.key_size + 7) // 8
    if len(signature) != key_size * 2:
        raise AuthValidationError("Invalid ECDSA JWT signature length.")
    r = int.from_bytes(signature[:key_size], "big")
    s = int.from_bytes(signature[key_size:], "big")
    der_signature = encode_dss_signature(r, s)
    try:
        public_key.verify(der_signature, signing_input, ec.ECDSA(_hash_algorithm(alg)))
    except Exception as exc:
        raise AuthValidationError("Bearer token signature validation failed.") from exc


def _verify_eddsa(jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
    if jwk.get("kty") != "OKP":
        raise AuthValidationError("EdDSA JWT requires an OKP JWK.")

    curve_name = str(jwk.get("crv", ""))
    public_bytes = _b64url_decode(str(jwk.get("x", "")))
    if curve_name == "Ed25519":
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    elif curve_name == "Ed448":
        public_key = ed448.Ed448PublicKey.from_public_bytes(public_bytes)
    else:
        raise AuthValidationError(f"Unsupported OKP curve '{curve_name}'.")

    try:
        public_key.verify(signature, signing_input)
    except Exception as exc:
        raise AuthValidationError("Bearer token signature validation failed.") from exc


def _hash_algorithm(alg: str):
    return {
        "HS256": hashes.SHA256(),
        "HS384": hashes.SHA384(),
        "HS512": hashes.SHA512(),
        "RS256": hashes.SHA256(),
        "RS384": hashes.SHA384(),
        "RS512": hashes.SHA512(),
        "ES256": hashes.SHA256(),
        "ES384": hashes.SHA384(),
        "ES512": hashes.SHA512(),
    }.get(alg) or _raise_unsupported_alg(alg)


def _rsa_public_key_from_jwk(jwk: dict[str, Any]):
    n = jwk.get("n")
    e = jwk.get("e")
    if n and e:
        return rsa.RSAPublicNumbers(
            e=int.from_bytes(_b64url_decode(str(e)), "big"),
            n=int.from_bytes(_b64url_decode(str(n)), "big"),
        ).public_key()

    x5c = jwk.get("x5c")
    if isinstance(x5c, list) and x5c and isinstance(x5c[0], str):
        cert_der = base64.b64decode(x5c[0].encode("ascii"))
        cert = x509.load_der_x509_certificate(cert_der)
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key

    raise AuthValidationError("RSA JWK must include modulus/exponent or x5c certificate data.")


def _ec_public_key_from_jwk(jwk: dict[str, Any]):
    curve_name = str(jwk.get("crv", ""))
    curve = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }.get(curve_name)
    if curve is None:
        raise AuthValidationError(f"Unsupported EC curve '{curve_name}'.")

    x = jwk.get("x")
    y = jwk.get("y")
    if x and y:
        return ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(_b64url_decode(str(x)), "big"),
            y=int.from_bytes(_b64url_decode(str(y)), "big"),
            curve=curve,
        ).public_key()

    x5c = jwk.get("x5c")
    if isinstance(x5c, list) and x5c and isinstance(x5c[0], str):
        cert_der = base64.b64decode(x5c[0].encode("ascii"))
        cert = x509.load_der_x509_certificate(cert_der)
        public_key = cert.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key

    raise AuthValidationError("EC JWK must include coordinates or x5c certificate data.")


def _raise_unsupported_alg(alg: str):
    raise AuthValidationError(f"Unsupported JWT algorithm '{alg}'.")


def _validate_registered_claims(claims: dict[str, Any], cfg: dict[str, Any]) -> None:
    now = int(time.time())
    leeway = int(cfg.get("AUTH_CLOCK_SKEW_SECS", 60))

    exp = claims.get("exp")
    if exp is not None:
        if not isinstance(exp, (int, float)):
            raise AuthValidationError("Bearer token exp claim must be numeric.")
        if now > int(exp) + leeway:
            raise AuthValidationError("Bearer token is expired.")

    nbf = claims.get("nbf")
    if nbf is not None:
        if not isinstance(nbf, (int, float)):
            raise AuthValidationError("Bearer token nbf claim must be numeric.")
        if now + leeway < int(nbf):
            raise AuthValidationError("Bearer token is not yet valid.")

    issuer = cfg.get("EXPECTED_BEARER_ISSUER", "")
    if issuer and claims.get("iss") != issuer:
        raise AuthValidationError(f"Bearer token issuer mismatch (expected {issuer}).")

    expected_audience = cfg.get("EXPECTED_BEARER_AUDIENCE", [])
    if expected_audience:
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience if isinstance(audience, list) else []
        if not any(isinstance(value, str) and value in expected_audience for value in audiences):
            raise AuthValidationError(f"Bearer token audience mismatch (expected one of {expected_audience}).")


def encode_dss_signature(r: int, s: int) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature as _encode

    return _encode(r, s)


def _record_cache_stat(label: str, *, hit: bool) -> None:
    normalized = label.lower()
    prefix = "oidc" if "discovery" in normalized else "jwks"
    suffix = "hits" if hit else "misses"
    key = f"{prefix}_{suffix}"
    _CACHE_STATS[key] += 1


def _normalize_cache_scope(scope: Any) -> str:
    if isinstance(scope, str):
        normalized = scope.strip().lower()
        if normalized in {"all", "jwks", "discovery"}:
            return normalized
    raise ValueError("scope must be one of: all, jwks, discovery")


def _matching_cache_keys(cache: dict[str, _CachedDocument], target_url: str) -> list[str]:
    if target_url:
        return [target_url] if target_url in cache else []
    return list(cache.keys())


def _extract_jwks_keys(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("keys"), list):
        raw_keys = payload["keys"]
    elif isinstance(payload, list):
        raw_keys = payload
    else:
        raise AuthValidationError("JWKS payload must contain a 'keys' array.")

    keys = [key for key in raw_keys if isinstance(key, dict)]
    if not keys:
        raise AuthValidationError("JWKS payload does not contain any keys.")
    return keys
