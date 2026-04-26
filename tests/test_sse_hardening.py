import pytest
import json
import base64
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from core import auth
from core.sse_server import ServerContext, _check_auth, _check_origin, _validate_message_request, handle_messages, handle_mcp, handle_sse


def test_validate_message_request_rejects_bad_content_type():
    cfg = {"MAX_BODY_BYTES": 1024}
    ok, status, message = _validate_message_request(
        {"headers": [(b"content-type", b"text/plain"), (b"content-length", b"2")]},
        cfg,
    )
    assert ok is False
    assert status == 415
    assert "application/json" in message


def test_validate_message_request_rejects_oversized_body():
    cfg = {"MAX_BODY_BYTES": 10}
    ok, status, message = _validate_message_request(
        {"headers": [(b"content-type", b"application/json"), (b"content-length", b"11")]},
        cfg,
    )
    assert ok is False
    assert status == 413
    assert "10" in message


def test_check_origin_allows_missing_origin_when_not_required():
    ok, status, message = _check_origin({"headers": []}, {"ALLOWED_ORIGINS": [], "REQUIRE_ORIGIN": False})
    assert ok is True
    assert status == 200
    assert message == ""


def test_check_origin_rejects_missing_origin_when_required():
    ok, status, message = _check_origin({"headers": []}, {"ALLOWED_ORIGINS": [], "REQUIRE_ORIGIN": True})
    assert ok is False
    assert status == 403
    assert "Missing Origin" in message


def test_check_origin_rejects_unlisted_origin():
    ok, status, message = _check_origin(
        {"headers": [(b"origin", b"https://evil.example")]},
        {"ALLOWED_ORIGINS": ["https://allowed.example"], "REQUIRE_ORIGIN": False},
    )
    assert ok is False
    assert status == 403
    assert "not allowed" in message


def test_check_origin_accepts_listed_origin_case_insensitively():
    ok, status, message = _check_origin(
        {"headers": [(b"origin", b"https://APP.EXAMPLE/")]},
        {"ALLOWED_ORIGINS": ["https://app.example"], "REQUIRE_ORIGIN": True},
    )
    assert ok is True
    assert status == 200
    assert message == ""


@pytest.mark.asyncio
async def test_handle_messages_rejects_unsupported_content_type():
    ctx = ServerContext(
        server_command=["python", "-c", "print('hello')"],
        config=None,
        sse_transport=MagicMock(),
        cfg={
            "API_KEY": "",
            "ALLOWED_IPS": [],
            "MAX_CONCURRENCY": 5,
            "MAX_GLOBAL_CONNECTIONS": 10,
            "RATE_LIMIT_PER_SEC": 10.0,
            "MAX_BODY_BYTES": 1024,
        },
    )

    scope = {
        "type": "http",
        "client": ["127.0.0.1", 1234],
        "headers": [(b"content-type", b"text/plain"), (b"content-length", b"12")],
    }

    with pytest.MonkeyPatch.context() as mp:
        send_error = AsyncMock()
        mp.setattr("core.sse_server._send_error", send_error)
        await handle_messages(scope, AsyncMock(), AsyncMock(), ctx)
        send_error.assert_awaited_once()
        assert send_error.await_args.args[1] == 415


@pytest.mark.asyncio
async def test_handle_messages_rejects_disallowed_origin():
    ctx = ServerContext(
        server_command=["python", "-c", "print('hello')"],
        config=None,
        sse_transport=MagicMock(),
        cfg={
            "API_KEY": "",
            "ALLOWED_IPS": [],
            "ALLOWED_ORIGINS": ["https://good.example"],
            "REQUIRE_ORIGIN": False,
            "MAX_CONCURRENCY": 5,
            "MAX_GLOBAL_CONNECTIONS": 10,
            "RATE_LIMIT_PER_SEC": 10.0,
            "MAX_BODY_BYTES": 1024,
        },
    )

    scope = {
        "type": "http",
        "client": ["127.0.0.1", 1234],
        "headers": [
            (b"origin", b"https://evil.example"),
            (b"content-type", b"application/json"),
            (b"content-length", b"12"),
        ],
    }

    with pytest.MonkeyPatch.context() as mp:
        send_error = AsyncMock()
        mp.setattr("core.sse_server._send_error", send_error)
        await handle_messages(scope, AsyncMock(), AsyncMock(), ctx)
        send_error.assert_awaited_once()
        assert send_error.await_args.args[1] == 403


@pytest.mark.asyncio
async def test_check_auth_returns_structured_principal_for_api_key(monkeypatch):
    monkeypatch.setenv("VANGUARD_API_KEY", "top-secret")

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"x-api-key", b"top-secret")],
        }
    )

    assert ok is True
    assert message == ""
    assert principal is not None
    assert principal.auth_type == "api_key"
    assert principal.principal_id.startswith("api_key:")


def _jwt_like_token(claims: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")).decode("ascii").rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode("utf-8")).decode("ascii").rstrip("=")
    return f"{header}.{payload}.signature"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _rsa_jwk_and_token(claims: dict, kid: str = "test-key-1") -> tuple[dict, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")),
    }
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode("utf-8"))
    payload = _b64url(json.dumps(claims).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    token = f"{header}.{payload}.{_b64url(signature)}"
    return jwk, token


def _rsa_jwk_and_token_with_header(
    claims: dict,
    *,
    header_overrides: dict | None = None,
    kid: str = "test-key-1",
    include_kid_in_jwk: bool = True,
    jwk_overrides: dict | None = None,
) -> tuple[dict, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": _b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")),
    }
    if include_kid_in_jwk:
        jwk["kid"] = kid
    if jwk_overrides:
        jwk.update(jwk_overrides)
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    if header_overrides:
        header.update(header_overrides)
    encoded_header = _b64url(json.dumps(header).encode("utf-8"))
    payload = _b64url(json.dumps(claims).encode("utf-8"))
    signing_input = f"{encoded_header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    token = f"{encoded_header}.{payload}.{_b64url(signature)}"
    return jwk, token


def _rsa_x5c_jwk_and_token(claims: dict, kid: str = "x5c-key-1") -> tuple[dict, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcpvanguard-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=7))
        .sign(private_key, hashes.SHA256())
    )
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "x5c": [base64.b64encode(cert.public_bytes(Encoding.DER)).decode("ascii")],
    }
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode("utf-8"))
    payload = _b64url(json.dumps(claims).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    token = f"{header}.{payload}.{_b64url(signature)}"
    return jwk, token


def _ec_jwk_and_token(claims: dict, kid: str = "ec-key-1") -> tuple[dict, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "kid": kid,
        "alg": "ES256",
        "use": "sig",
        "crv": "P-256",
        "x": _b64url(public_numbers.x.to_bytes((public_numbers.x.bit_length() + 7) // 8, "big")),
        "y": _b64url(public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, "big")),
    }
    header = _b64url(json.dumps({"alg": "ES256", "typ": "JWT", "kid": kid}).encode("utf-8"))
    payload = _b64url(json.dumps(claims).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    key_size = (private_key.curve.key_size + 7) // 8
    raw_signature = r.to_bytes(key_size, "big") + s.to_bytes(key_size, "big")
    token = f"{header}.{payload}.{_b64url(raw_signature)}"
    return jwk, token


def _eddsa_jwk_and_token(claims: dict, kid: str = "eddsa-key-1") -> tuple[dict, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    jwk = {
        "kty": "OKP",
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
        "crv": "Ed25519",
        "x": _b64url(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
    }
    header = _b64url(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": kid}).encode("utf-8"))
    payload = _b64url(json.dumps(claims).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input)
    token = f"{header}.{payload}.{_b64url(signature)}"
    return jwk, token


def decode_dss_signature(signature: bytes) -> tuple[int, int]:
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature as _decode

    return _decode(signature)


class _SendCollector:
    def __init__(self):
        self.messages = []

    async def __call__(self, message):
        self.messages.append(message)


@pytest.mark.asyncio
async def test_check_auth_enriches_bearer_principal_with_unverified_claims(monkeypatch):
    token = _jwt_like_token(
        {
            "sub": "user-123",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard", "secondary"],
            "scope": "tools.read tools.write",
            "roles": ["admin", "operator"],
        }
    )
    monkeypatch.setenv("VANGUARD_API_KEY", token)

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
        }
    )

    assert ok is True
    assert message == ""
    assert principal is not None
    assert principal.auth_type == "bearer"
    assert principal.principal_id == "bearer:https://issuer.example:user-123"
    assert principal.roles == ["authenticated", "admin", "operator"]
    assert principal.attributes["claims_verified"] is False
    assert principal.attributes["token_subject"] == "user-123"
    assert principal.attributes["token_issuer"] == "https://issuer.example"
    assert principal.attributes["token_audience"] == ["mcpvanguard", "secondary"]
    assert principal.attributes["token_scope"] == ["tools.read", "tools.write"]


@pytest.mark.asyncio
async def test_check_auth_bearer_claim_parsing_falls_back_cleanly_for_opaque_token(monkeypatch):
    monkeypatch.setenv("VANGUARD_API_KEY", "opaque-shared-secret")

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", b"Bearer opaque-shared-secret")],
        }
    )

    assert ok is True
    assert message == ""
    assert principal is not None
    assert principal.auth_type == "bearer"
    assert principal.principal_id.startswith("bearer:")
    assert principal.principal_id != "bearer:"
    assert principal.roles == ["authenticated"]
    assert "claims_verified" not in principal.attributes


@pytest.mark.asyncio
async def test_check_auth_warns_on_bearer_claim_expectation_mismatch(monkeypatch):
    token = _jwt_like_token(
        {
            "sub": "user-123",
            "iss": "https://issuer.example",
            "aud": ["wrong-audience"],
        }
    )
    monkeypatch.setenv("VANGUARD_API_KEY", token)
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_ISSUER", "https://issuer.example")
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_AUDIENCE", "mcpvanguard")
    monkeypatch.setenv("VANGUARD_BEARER_CLAIM_POLICY", "warn")

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
        }
    )

    assert ok is True
    assert message == ""
    assert principal is not None
    assert principal.attributes["claim_policy"] == "warn"
    assert principal.attributes["auth_warnings"] == [
        "audience mismatch (expected one of ['mcpvanguard'], got ['wrong-audience'])"
    ]


@pytest.mark.asyncio
async def test_check_auth_blocks_on_bearer_claim_expectation_mismatch(monkeypatch):
    token = _jwt_like_token(
        {
            "sub": "user-123",
            "iss": "https://unexpected-issuer.example",
        }
    )
    monkeypatch.setenv("VANGUARD_API_KEY", token)
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_ISSUER", "https://issuer.example")
    monkeypatch.setenv("VANGUARD_BEARER_CLAIM_POLICY", "block")

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
        }
    )

    assert ok is False
    assert "issuer mismatch" in message
    assert principal is None


@pytest.mark.asyncio
async def test_check_auth_warns_on_missing_required_bearer_claim(monkeypatch):
    token = _jwt_like_token(
        {
            "sub": "user-123",
            "iss": "https://issuer.example",
        }
    )
    monkeypatch.setenv("VANGUARD_API_KEY", token)
    monkeypatch.setenv("VANGUARD_REQUIRED_BEARER_CLAIMS", "sub,jti")
    monkeypatch.setenv("VANGUARD_BEARER_CLAIM_POLICY", "warn")

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
        }
    )

    assert ok is True
    assert message == ""
    assert principal is not None
    assert principal.attributes["token_claim_keys"] == ["iss", "sub"]
    assert principal.attributes["auth_warnings"] == ["missing required claim 'jti'"]


@pytest.mark.asyncio
async def test_check_auth_blocks_when_required_scopes_all_are_missing(monkeypatch):
    token = _jwt_like_token(
        {
            "sub": "user-123",
            "scope": "tools.read",
        }
    )
    monkeypatch.setenv("VANGUARD_API_KEY", token)
    monkeypatch.setenv("VANGUARD_REQUIRED_BEARER_SCOPES", "tools.read,tools.write")
    monkeypatch.setenv("VANGUARD_BEARER_SCOPE_MATCH", "all")
    monkeypatch.setenv("VANGUARD_BEARER_CLAIM_POLICY", "block")

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
        }
    )

    assert ok is False
    assert "scope mismatch" in message
    assert principal is None


@pytest.mark.asyncio
async def test_check_auth_accepts_required_bearer_claims_and_scopes(monkeypatch):
    token = _jwt_like_token(
        {
            "sub": "user-123",
            "iss": "https://issuer.example",
            "jti": "token-abc",
            "scope": "tools.read tools.write",
            "roles": ["admin"],
        }
    )
    monkeypatch.setenv("VANGUARD_API_KEY", token)
    monkeypatch.setenv("VANGUARD_REQUIRED_BEARER_CLAIMS", "sub,jti")
    monkeypatch.setenv("VANGUARD_REQUIRED_BEARER_SCOPES", "tools.write")
    monkeypatch.setenv("VANGUARD_BEARER_SCOPE_MATCH", "any")
    monkeypatch.setenv("VANGUARD_BEARER_CLAIM_POLICY", "block")

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
        }
    )

    assert ok is True
    assert message == ""
    assert principal is not None
    assert principal.roles == ["authenticated", "admin"]
    assert principal.attributes["token_scope"] == ["tools.read", "tools.write"]
    assert principal.attributes["token_claim_keys"] == ["iss", "jti", "roles", "scope", "sub"]
    assert "auth_warnings" not in principal.attributes


@pytest.mark.asyncio
async def test_check_auth_accepts_string_scp_claim_as_scope_list(monkeypatch):
    token = _jwt_like_token(
        {
            "sub": "user-123",
            "scp": "tools.read tools.write",
        }
    )
    monkeypatch.setenv("VANGUARD_API_KEY", token)

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
        }
    )

    assert ok is True
    assert message == ""
    assert principal is not None
    assert principal.attributes["token_scope"] == ["tools.read", "tools.write"]


@pytest.mark.asyncio
async def test_check_auth_oauth_mode_verifies_rsa_signed_bearer_token(monkeypatch):
    now = int(time.time())
    jwk, token = _rsa_jwk_and_token(
        {
            "sub": "verified-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "scope": "tools.read tools.write",
            "exp": now + 300,
        }
    )
    monkeypatch.setenv("VANGUARD_AUTH_MODE", "oauth")
    monkeypatch.setenv("VANGUARD_JWKS_JSON", json.dumps({"keys": [jwk]}))
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_ISSUER", "https://issuer.example")
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_AUDIENCE", "mcpvanguard")
    monkeypatch.delenv("VANGUARD_API_KEY", raising=False)

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
        }
    )

    assert ok is True
    assert message == ""
    assert principal is not None
    assert principal.auth_type == "bearer"
    assert principal.principal_id == "bearer:https://issuer.example:verified-user"
    assert principal.attributes["claims_verified"] is True


@pytest.mark.asyncio
async def test_check_auth_oauth_mode_rejects_invalid_signature(monkeypatch):
    now = int(time.time())
    jwk, token = _rsa_jwk_and_token(
        {
            "sub": "verified-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        }
    )
    tampered = token[:-2] + ("aa" if token[-2:] != "aa" else "bb")
    monkeypatch.setenv("VANGUARD_AUTH_MODE", "oauth")
    monkeypatch.setenv("VANGUARD_JWKS_JSON", json.dumps({"keys": [jwk]}))
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_ISSUER", "https://issuer.example")
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_AUDIENCE", "mcpvanguard")
    monkeypatch.delenv("VANGUARD_API_KEY", raising=False)

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {tampered}".encode("utf-8"))],
        }
    )

    assert ok is False
    assert "validation failed" in message
    assert principal is None


@pytest.mark.asyncio
async def test_check_auth_oauth_mode_rejects_expired_token(monkeypatch):
    now = int(time.time())
    jwk, token = _rsa_jwk_and_token(
        {
            "sub": "verified-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now - 1000,
        }
    )
    monkeypatch.setenv("VANGUARD_AUTH_MODE", "oauth")
    monkeypatch.setenv("VANGUARD_JWKS_JSON", json.dumps({"keys": [jwk]}))
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_ISSUER", "https://issuer.example")
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_AUDIENCE", "mcpvanguard")
    monkeypatch.setenv("VANGUARD_AUTH_CLOCK_SKEW_SECS", "0")
    monkeypatch.delenv("VANGUARD_API_KEY", raising=False)

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
        }
    )

    assert ok is False
    assert "expired" in message
    assert principal is None


@pytest.mark.asyncio
async def test_check_auth_oauth_mode_accepts_required_scope_from_scp_string(monkeypatch):
    now = int(time.time())
    jwk, token = _rsa_jwk_and_token(
        {
            "sub": "verified-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "scp": "tools.read tools.write",
            "exp": now + 300,
        }
    )
    monkeypatch.setenv("VANGUARD_AUTH_MODE", "oauth")
    monkeypatch.setenv("VANGUARD_JWKS_JSON", json.dumps({"keys": [jwk]}))
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_ISSUER", "https://issuer.example")
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_AUDIENCE", "mcpvanguard")
    monkeypatch.setenv("VANGUARD_REQUIRED_BEARER_SCOPES", "tools.write")
    monkeypatch.setenv("VANGUARD_BEARER_CLAIM_POLICY", "block")
    monkeypatch.delenv("VANGUARD_API_KEY", raising=False)

    ok, message, principal = await _check_auth(
        {
            "client": ["127.0.0.1", 1234],
            "headers": [(b"authorization", f"Bearer {token}".encode("utf-8"))],
        }
    )

    assert ok is True
    assert message == ""
    assert principal is not None
    assert principal.attributes["token_scope"] == ["tools.read", "tools.write"]


@pytest.mark.asyncio
async def test_validate_bearer_token_loads_jwks_from_url_and_caches(monkeypatch):
    auth.clear_auth_caches()
    now = int(time.time())
    jwk, token = _rsa_jwk_and_token(
        {
            "sub": "cached-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        }
    )
    calls: list[str] = []

    async def fake_fetch(url: str, *, timeout_secs: float, label: str):
        calls.append(url)
        return {"keys": [jwk]}

    monkeypatch.setattr("core.auth._fetch_json_document", fake_fetch)
    cfg = {
        "JWKS_URL": "https://issuer.example/jwks.json",
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "EXPECTED_BEARER_AUDIENCE": ["mcpvanguard"],
        "AUTH_CLOCK_SKEW_SECS": 60,
        "JWKS_CACHE_TTL_SECS": 300,
        "OAUTH_HTTP_TIMEOUT_SECS": 5.0,
    }

    first = await auth.validate_bearer_token(token, cfg)
    second = await auth.validate_bearer_token(token, cfg)

    assert first.claims["sub"] == "cached-user"
    assert second.claims["sub"] == "cached-user"
    assert calls == ["https://issuer.example/jwks.json"]


@pytest.mark.asyncio
async def test_validate_bearer_token_uses_discovery_to_find_jwks(monkeypatch):
    auth.clear_auth_caches()
    now = int(time.time())
    jwk, token = _rsa_jwk_and_token(
        {
            "sub": "discovered-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        }
    )
    calls: list[str] = []

    async def fake_fetch(url: str, *, timeout_secs: float, label: str):
        calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": "https://issuer.example", "jwks_uri": "https://issuer.example/keys"}
        if url == "https://issuer.example/keys":
            return {"keys": [jwk]}
        raise AssertionError(f"unexpected fetch url: {url}")

    monkeypatch.setattr("core.auth._fetch_json_document", fake_fetch)
    cfg = {
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "EXPECTED_BEARER_AUDIENCE": ["mcpvanguard"],
        "AUTH_CLOCK_SKEW_SECS": 60,
        "JWKS_CACHE_TTL_SECS": 300,
        "OAUTH_HTTP_TIMEOUT_SECS": 5.0,
    }

    verified = await auth.validate_bearer_token(token, cfg)

    assert verified.claims["sub"] == "discovered-user"
    assert calls == [
        "https://issuer.example/.well-known/openid-configuration",
        "https://issuer.example/keys",
    ]


@pytest.mark.asyncio
async def test_validate_bearer_token_falls_back_to_oauth_authorization_server_metadata(monkeypatch):
    auth.clear_auth_caches()
    now = int(time.time())
    jwk, token = _rsa_jwk_and_token(
        {
            "sub": "fallback-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        }
    )
    calls: list[str] = []

    async def fake_fetch(url: str, *, timeout_secs: float, label: str):
        calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            raise auth.AuthValidationError("provider does not expose OpenID metadata here")
        if url.endswith("/.well-known/oauth-authorization-server"):
            return {
                "issuer": "https://issuer.example",
                "jwks_uri": "https://issuer.example/oauth-keys",
            }
        if url == "https://issuer.example/oauth-keys":
            return {"keys": [jwk]}
        raise AssertionError(f"unexpected fetch url: {url}")

    monkeypatch.setattr("core.auth._fetch_json_document", fake_fetch)
    cfg = {
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "EXPECTED_BEARER_AUDIENCE": ["mcpvanguard"],
        "AUTH_CLOCK_SKEW_SECS": 60,
        "JWKS_CACHE_TTL_SECS": 300,
        "DISCOVERY_CACHE_TTL_SECS": 300,
        "OAUTH_HTTP_TIMEOUT_SECS": 5.0,
    }

    verified = await auth.validate_bearer_token(token, cfg)

    assert verified.claims["sub"] == "fallback-user"
    assert calls == [
        "https://issuer.example/.well-known/openid-configuration",
        "https://issuer.example/.well-known/oauth-authorization-server",
        "https://issuer.example/oauth-keys",
    ]


@pytest.mark.asyncio
async def test_validate_bearer_token_rejects_discovery_issuer_mismatch(monkeypatch):
    auth.clear_auth_caches()
    now = int(time.time())
    jwk, token = _rsa_jwk_and_token(
        {
            "sub": "issuer-check-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        }
    )

    async def fake_fetch(url: str, *, timeout_secs: float, label: str):
        if url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": "https://wrong-issuer.example",
                "jwks_uri": "https://issuer.example/keys",
            }
        if url == "https://issuer.example/keys":
            return {"keys": [jwk]}
        raise AssertionError(f"unexpected fetch url: {url}")

    monkeypatch.setattr("core.auth._fetch_json_document", fake_fetch)
    cfg = {
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "EXPECTED_BEARER_AUDIENCE": ["mcpvanguard"],
        "AUTH_CLOCK_SKEW_SECS": 60,
        "JWKS_CACHE_TTL_SECS": 300,
        "DISCOVERY_CACHE_TTL_SECS": 300,
        "OAUTH_HTTP_TIMEOUT_SECS": 5.0,
    }

    with pytest.raises(auth.AuthValidationError, match="discovery issuer mismatch"):
        await auth.validate_bearer_token(token, cfg)


@pytest.mark.asyncio
async def test_validate_bearer_token_refreshes_dynamic_jwks_on_kid_miss(monkeypatch):
    auth.clear_auth_caches()
    now = int(time.time())
    stale_jwk, _ = _rsa_jwk_and_token(
        {
            "sub": "stale-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        },
        kid="stale-key",
    )
    fresh_jwk, token = _rsa_jwk_and_token(
        {
            "sub": "fresh-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        },
        kid="fresh-key",
    )
    responses = [
        {"keys": [stale_jwk]},
        {"keys": [fresh_jwk]},
    ]
    calls: list[str] = []

    async def fake_fetch(url: str, *, timeout_secs: float, label: str):
        calls.append(url)
        return responses.pop(0)

    monkeypatch.setattr("core.auth._fetch_json_document", fake_fetch)
    cfg = {
        "JWKS_URL": "https://issuer.example/jwks.json",
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "EXPECTED_BEARER_AUDIENCE": ["mcpvanguard"],
        "AUTH_CLOCK_SKEW_SECS": 60,
        "JWKS_CACHE_TTL_SECS": 300,
        "OAUTH_HTTP_TIMEOUT_SECS": 5.0,
    }

    verified = await auth.validate_bearer_token(token, cfg)

    assert verified.claims["sub"] == "fresh-user"
    assert calls == [
        "https://issuer.example/jwks.json",
        "https://issuer.example/jwks.json",
    ]


@pytest.mark.asyncio
async def test_validate_bearer_token_can_disable_refresh_on_kid_miss(monkeypatch):
    auth.clear_auth_caches()
    now = int(time.time())
    stale_jwk, _ = _rsa_jwk_and_token(
        {
            "sub": "stale-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        },
        kid="stale-key",
    )
    fresh_jwk, token = _rsa_jwk_and_token(
        {
            "sub": "fresh-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        },
        kid="fresh-key",
    )
    responses = [
        {"keys": [stale_jwk]},
        {"keys": [fresh_jwk]},
    ]
    calls: list[str] = []

    async def fake_fetch(url: str, *, timeout_secs: float, label: str):
        calls.append(url)
        return responses.pop(0)

    monkeypatch.setattr("core.auth._fetch_json_document", fake_fetch)
    cfg = {
        "JWKS_URL": "https://issuer.example/jwks.json",
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "EXPECTED_BEARER_AUDIENCE": ["mcpvanguard"],
        "AUTH_CLOCK_SKEW_SECS": 60,
        "JWKS_CACHE_TTL_SECS": 300,
        "DISCOVERY_CACHE_TTL_SECS": 300,
        "OAUTH_HTTP_TIMEOUT_SECS": 5.0,
        "JWKS_REFRESH_ON_KID_MISS": False,
    }

    with pytest.raises(auth.AuthValidationError, match="No JWKS key matched token kid"):
        await auth.validate_bearer_token(token, cfg)

    assert calls == ["https://issuer.example/jwks.json"]


@pytest.mark.asyncio
async def test_validate_bearer_token_matches_jwk_by_x5t_when_kid_missing(monkeypatch):
    auth.clear_auth_caches()
    now = int(time.time())
    x5t_value = "legacy-thumbprint"
    jwk, token = _rsa_jwk_and_token_with_header(
        {
            "sub": "x5t-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        },
        header_overrides={"x5t": x5t_value, "kid": None},
        include_kid_in_jwk=False,
        jwk_overrides={"x5t": x5t_value},
    )
    cfg = {
        "JWKS_JSON": json.dumps({"keys": [jwk]}),
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "EXPECTED_BEARER_AUDIENCE": ["mcpvanguard"],
        "AUTH_CLOCK_SKEW_SECS": 60,
    }

    verified = await auth.validate_bearer_token(token, cfg)

    assert verified.claims["sub"] == "x5t-user"


@pytest.mark.asyncio
async def test_validate_bearer_token_accepts_es256_signed_token(monkeypatch):
    auth.clear_auth_caches()
    now = int(time.time())
    jwk, token = _ec_jwk_and_token(
        {
            "sub": "ec-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        }
    )
    cfg = {
        "JWKS_JSON": json.dumps({"keys": [jwk]}),
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "EXPECTED_BEARER_AUDIENCE": ["mcpvanguard"],
        "AUTH_CLOCK_SKEW_SECS": 60,
    }

    verified = await auth.validate_bearer_token(token, cfg)

    assert verified.claims["sub"] == "ec-user"


@pytest.mark.asyncio
async def test_validate_bearer_token_accepts_x5c_only_rsa_jwk(monkeypatch):
    auth.clear_auth_caches()
    now = int(time.time())
    jwk, token = _rsa_x5c_jwk_and_token(
        {
            "sub": "x5c-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        }
    )
    cfg = {
        "JWKS_JSON": json.dumps({"keys": [jwk]}),
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "EXPECTED_BEARER_AUDIENCE": ["mcpvanguard"],
        "AUTH_CLOCK_SKEW_SECS": 60,
    }

    verified = await auth.validate_bearer_token(token, cfg)

    assert verified.claims["sub"] == "x5c-user"


@pytest.mark.asyncio
async def test_validate_bearer_token_accepts_eddsa_ed25519_token(monkeypatch):
    auth.clear_auth_caches()
    now = int(time.time())
    jwk, token = _eddsa_jwk_and_token(
        {
            "sub": "eddsa-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now + 300,
        }
    )
    cfg = {
        "JWKS_JSON": json.dumps({"keys": [jwk]}),
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "EXPECTED_BEARER_AUDIENCE": ["mcpvanguard"],
        "AUTH_CLOCK_SKEW_SECS": 60,
    }

    verified = await auth.validate_bearer_token(token, cfg)

    assert verified.claims["sub"] == "eddsa-user"


@pytest.mark.asyncio
async def test_refresh_auth_caches_for_jwks_url_forces_refetch(monkeypatch):
    auth.clear_auth_caches()
    calls: list[str] = []

    async def fake_fetch(url: str, *, timeout_secs: float, label: str):
        calls.append(url)
        return {"keys": [{"kty": "RSA", "kid": "refresh-key", "n": "AQAB", "e": "AQAB"}]}

    monkeypatch.setattr("core.auth._fetch_json_document", fake_fetch)
    cfg = {
        "JWKS_URL": "https://issuer.example/jwks.json",
        "JWKS_CACHE_TTL_SECS": 300,
        "DISCOVERY_CACHE_TTL_SECS": 300,
        "OAUTH_HTTP_TIMEOUT_SECS": 5.0,
    }

    summary = await auth.refresh_auth_caches(cfg, scope="jwks")
    stats = auth.get_auth_cache_stats()

    assert summary["jwks_refreshed"] is True
    assert summary["jwks_source"] == "jwks_url"
    assert summary["jwks_key_count"] == 1
    assert stats["jwks_entries"] == 1
    assert stats["jwks_cached_urls"] == ["https://issuer.example/jwks.json"]
    assert calls == ["https://issuer.example/jwks.json"]


@pytest.mark.asyncio
async def test_refresh_auth_caches_via_discovery_refreshes_metadata_and_jwks(monkeypatch):
    auth.clear_auth_caches()
    calls: list[str] = []

    async def fake_fetch(url: str, *, timeout_secs: float, label: str):
        calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": "https://issuer.example", "jwks_uri": "https://issuer.example/keys"}
        if url == "https://issuer.example/keys":
            return {"keys": [{"kty": "RSA", "kid": "refresh-key", "n": "AQAB", "e": "AQAB"}]}
        raise AssertionError(f"unexpected fetch url: {url}")

    monkeypatch.setattr("core.auth._fetch_json_document", fake_fetch)
    cfg = {
        "EXPECTED_BEARER_ISSUER": "https://issuer.example",
        "JWKS_CACHE_TTL_SECS": 300,
        "DISCOVERY_CACHE_TTL_SECS": 120,
        "OAUTH_HTTP_TIMEOUT_SECS": 5.0,
    }

    summary = await auth.refresh_auth_caches(cfg, scope="all")
    stats = auth.get_auth_cache_stats()

    assert summary["discovery_refreshed"] is True
    assert summary["jwks_refreshed"] is True
    assert summary["jwks_source"] == "discovery"
    assert summary["jwks_key_count"] == 1
    assert stats["oidc_entries"] == 1
    assert stats["jwks_entries"] == 1
    assert calls == [
        "https://issuer.example/.well-known/openid-configuration",
        "https://issuer.example/keys",
    ]


def test_clear_auth_caches_can_target_discovery_only():
    auth.clear_auth_caches()
    auth._JWKS_CACHE["https://issuer.example/jwks.json"] = auth._CachedDocument(
        payload={"keys": [{"kid": "jwks"}]},
        expires_at=time.time() + 300,
    )
    auth._DISCOVERY_CACHE["https://issuer.example/.well-known/openid-configuration"] = auth._CachedDocument(
        payload={"jwks_uri": "https://issuer.example/jwks.json"},
        expires_at=time.time() + 300,
    )

    summary = auth.clear_auth_caches(scope="discovery")

    assert summary["jwks_entries_cleared"] == 0
    assert summary["discovery_entries_cleared"] == 1
    assert len(auth._JWKS_CACHE) == 1
    assert len(auth._DISCOVERY_CACHE) == 0
    auth.clear_auth_caches()


@pytest.mark.asyncio
async def test_handle_messages_audits_auth_warnings_and_continues(monkeypatch):
    token = _jwt_like_token(
        {
            "sub": "user-123",
            "iss": "https://issuer.example",
            "aud": ["wrong-audience"],
        }
    )
    monkeypatch.setenv("VANGUARD_API_KEY", token)
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_AUDIENCE", "mcpvanguard")
    monkeypatch.setenv("VANGUARD_BEARER_CLAIM_POLICY", "warn")

    transport = MagicMock()
    transport.handle_post_message = AsyncMock()
    ctx = ServerContext(
        server_command=["python", "-c", "print('hello')"],
        config=None,
        sse_transport=transport,
        cfg={
            "API_KEY": token,
            "ALLOWED_IPS": [],
            "ALLOWED_ORIGINS": [],
            "REQUIRE_ORIGIN": False,
            "MAX_CONCURRENCY": 5,
            "MAX_GLOBAL_CONNECTIONS": 10,
            "RATE_LIMIT_PER_SEC": 10.0,
            "MAX_BODY_BYTES": 1024,
        },
    )
    scope = {
        "type": "http",
        "client": ["127.0.0.1", 1234],
        "headers": [
            (b"authorization", f"Bearer {token}".encode("utf-8")),
            (b"content-type", b"application/json"),
            (b"content-length", b"12"),
        ],
    }

    with pytest.MonkeyPatch.context() as mp:
        send_error = AsyncMock()
        audit_auth = MagicMock()
        mp.setattr("core.sse_server._send_error", send_error)
        mp.setattr("core.sse_server._audit_auth_finding", audit_auth)
        await handle_messages(scope, AsyncMock(), AsyncMock(), ctx)

    send_error.assert_not_awaited()
    transport.handle_post_message.assert_awaited_once()
    audit_auth.assert_called_once()
    assert audit_auth.call_args.kwargs["action"] == "WARN"


@pytest.mark.asyncio
async def test_handle_mcp_audits_and_blocks_on_claim_policy_failure(monkeypatch):
    token = _jwt_like_token(
        {
            "sub": "user-123",
            "iss": "https://unexpected-issuer.example",
        }
    )
    monkeypatch.setenv("VANGUARD_API_KEY", token)
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_ISSUER", "https://issuer.example")
    monkeypatch.setenv("VANGUARD_BEARER_CLAIM_POLICY", "block")

    ctx = ServerContext(
        server_command=["python", "-c", "print('hello')"],
        config=None,
        sse_transport=MagicMock(),
        cfg={
            "API_KEY": token,
            "ALLOWED_IPS": [],
            "ALLOWED_ORIGINS": [],
            "REQUIRE_ORIGIN": False,
            "MAX_CONCURRENCY": 5,
            "MAX_GLOBAL_CONNECTIONS": 10,
            "RATE_LIMIT_PER_SEC": 10.0,
            "MAX_BODY_BYTES": 1024,
        },
        streamable_manager=MagicMock(),
    )
    scope = {
        "type": "http",
        "method": "POST",
        "client": ["127.0.0.1", 1234],
        "headers": [
            (b"authorization", f"Bearer {token}".encode("utf-8")),
            (b"content-type", b"application/json"),
            (b"content-length", b"12"),
        ],
    }

    with pytest.MonkeyPatch.context() as mp:
        send_error = AsyncMock()
        audit_auth = MagicMock()
        mp.setattr("core.sse_server._send_error_with_headers", send_error)
        mp.setattr("core.sse_server._audit_auth_finding", audit_auth)
        await handle_mcp(scope, AsyncMock(), AsyncMock(), ctx)

    send_error.assert_awaited_once()
    assert send_error.await_args.args[1] == 403
    audit_auth.assert_called_once()
    assert audit_auth.call_args.kwargs["action"] == "BLOCK"


@pytest.mark.asyncio
async def test_handle_mcp_oauth_missing_bearer_returns_www_authenticate(monkeypatch):
    monkeypatch.setenv("VANGUARD_AUTH_MODE", "oauth")
    monkeypatch.delenv("VANGUARD_API_KEY", raising=False)

    ctx = ServerContext(
        server_command=["python", "-c", "print('hello')"],
        config=None,
        sse_transport=MagicMock(),
        cfg={
            "AUTH_MODE": "oauth",
            "API_KEY": "",
            "ALLOWED_IPS": [],
            "ALLOWED_ORIGINS": [],
            "REQUIRE_ORIGIN": False,
            "MAX_CONCURRENCY": 5,
            "MAX_GLOBAL_CONNECTIONS": 10,
            "RATE_LIMIT_PER_SEC": 10.0,
            "MAX_BODY_BYTES": 1024,
        },
        streamable_manager=MagicMock(),
    )
    scope = {
        "type": "http",
        "method": "POST",
        "client": ["127.0.0.1", 1234],
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", b"12"),
        ],
    }
    send = _SendCollector()

    await handle_mcp(scope, AsyncMock(), send, ctx)

    start = send.messages[0]
    assert start["type"] == "http.response.start"
    assert start["status"] == 401
    headers = dict(start["headers"])
    assert b"www-authenticate" in headers
    challenge = headers[b"www-authenticate"].decode("utf-8")
    assert 'Bearer realm="mcpvanguard"' in challenge
    assert 'error="' not in challenge


@pytest.mark.asyncio
async def test_handle_messages_oauth_invalid_token_returns_invalid_token_challenge(monkeypatch):
    now = int(time.time())
    jwk, token = _rsa_jwk_and_token(
        {
            "sub": "verified-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "exp": now - 1000,
        }
    )
    monkeypatch.setenv("VANGUARD_AUTH_MODE", "oauth")
    monkeypatch.setenv("VANGUARD_JWKS_JSON", json.dumps({"keys": [jwk]}))
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_ISSUER", "https://issuer.example")
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_AUDIENCE", "mcpvanguard")
    monkeypatch.setenv("VANGUARD_AUTH_CLOCK_SKEW_SECS", "0")
    monkeypatch.delenv("VANGUARD_API_KEY", raising=False)

    transport = MagicMock()
    transport.handle_post_message = AsyncMock()
    ctx = ServerContext(
        server_command=["python", "-c", "print('hello')"],
        config=None,
        sse_transport=transport,
        cfg={
            "AUTH_MODE": "oauth",
            "API_KEY": "",
            "ALLOWED_IPS": [],
            "ALLOWED_ORIGINS": [],
            "REQUIRE_ORIGIN": False,
            "MAX_CONCURRENCY": 5,
            "MAX_GLOBAL_CONNECTIONS": 10,
            "RATE_LIMIT_PER_SEC": 10.0,
            "MAX_BODY_BYTES": 1024,
        },
    )
    scope = {
        "type": "http",
        "client": ["127.0.0.1", 1234],
        "headers": [
            (b"authorization", f"Bearer {token}".encode("utf-8")),
            (b"content-type", b"application/json"),
            (b"content-length", b"12"),
        ],
    }
    send = _SendCollector()

    await handle_messages(scope, AsyncMock(), send, ctx)

    transport.handle_post_message.assert_not_awaited()
    start = send.messages[0]
    assert start["type"] == "http.response.start"
    assert start["status"] == 401
    headers = dict(start["headers"])
    assert b"www-authenticate" in headers
    challenge = headers[b"www-authenticate"].decode("utf-8")
    assert 'error="invalid_token"' in challenge
    assert "expired" in challenge


@pytest.mark.asyncio
async def test_handle_messages_oauth_insufficient_scope_returns_403_challenge(monkeypatch):
    now = int(time.time())
    jwk, token = _rsa_jwk_and_token(
        {
            "sub": "verified-user",
            "iss": "https://issuer.example",
            "aud": ["mcpvanguard"],
            "scope": "tools.read",
            "exp": now + 300,
        }
    )
    monkeypatch.setenv("VANGUARD_AUTH_MODE", "oauth")
    monkeypatch.setenv("VANGUARD_JWKS_JSON", json.dumps({"keys": [jwk]}))
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_ISSUER", "https://issuer.example")
    monkeypatch.setenv("VANGUARD_EXPECTED_BEARER_AUDIENCE", "mcpvanguard")
    monkeypatch.setenv("VANGUARD_REQUIRED_BEARER_SCOPES", "tools.write")
    monkeypatch.setenv("VANGUARD_BEARER_CLAIM_POLICY", "block")
    monkeypatch.delenv("VANGUARD_API_KEY", raising=False)

    transport = MagicMock()
    transport.handle_post_message = AsyncMock()
    ctx = ServerContext(
        server_command=["python", "-c", "print('hello')"],
        config=None,
        sse_transport=transport,
        cfg={
            "AUTH_MODE": "oauth",
            "API_KEY": "",
            "ALLOWED_IPS": [],
            "ALLOWED_ORIGINS": [],
            "REQUIRE_ORIGIN": False,
            "MAX_CONCURRENCY": 5,
            "MAX_GLOBAL_CONNECTIONS": 10,
            "RATE_LIMIT_PER_SEC": 10.0,
            "MAX_BODY_BYTES": 1024,
            "REQUIRED_BEARER_SCOPES": ["tools.write"],
        },
    )
    scope = {
        "type": "http",
        "client": ["127.0.0.1", 1234],
        "headers": [
            (b"authorization", f"Bearer {token}".encode("utf-8")),
            (b"content-type", b"application/json"),
            (b"content-length", b"12"),
        ],
    }
    send = _SendCollector()

    await handle_messages(scope, AsyncMock(), send, ctx)

    transport.handle_post_message.assert_not_awaited()
    start = send.messages[0]
    assert start["type"] == "http.response.start"
    assert start["status"] == 403
    headers = dict(start["headers"])
    assert b"www-authenticate" in headers
    challenge = headers[b"www-authenticate"].decode("utf-8")
    assert 'error="insufficient_scope"' in challenge
    assert 'scope="tools.write"' in challenge


@pytest.mark.asyncio
async def test_handle_sse_api_key_mode_does_not_emit_oauth_challenge(monkeypatch):
    monkeypatch.setenv("VANGUARD_API_KEY", "top-secret")
    monkeypatch.delenv("VANGUARD_AUTH_MODE", raising=False)

    ctx = ServerContext(
        server_command=["python", "-c", "print('hello')"],
        config=None,
        sse_transport=MagicMock(),
        cfg={
            "AUTH_MODE": "api_key",
            "API_KEY": "top-secret",
            "ALLOWED_IPS": [],
            "ALLOWED_ORIGINS": [],
            "REQUIRE_ORIGIN": False,
            "MAX_CONCURRENCY": 5,
            "MAX_GLOBAL_CONNECTIONS": 10,
            "RATE_LIMIT_PER_SEC": 10.0,
            "MAX_BODY_BYTES": 1024,
        },
    )
    scope = {
        "type": "http",
        "client": ["127.0.0.1", 1234],
        "headers": [],
    }
    send = _SendCollector()

    await handle_sse(scope, AsyncMock(), send, ctx)

    start = send.messages[0]
    assert start["type"] == "http.response.start"
    assert start["status"] == 401
    headers = dict(start["headers"])
    assert b"www-authenticate" not in headers
