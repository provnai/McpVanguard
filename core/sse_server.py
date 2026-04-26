"""
core/sse_server.py
The SSE bridge for McpVanguard.
"""

from __future__ import annotations

import asyncio
import logging
import json
import sys
import hmac
import base64
import collections
import os
import time
import ipaddress
from contextlib import asynccontextmanager
from dataclasses import dataclass
from http import HTTPStatus
from typing import Optional, Any

from mcp.server.sse import SseServerTransport, SessionMessage
from mcp.server.streamable_http import (
    MCP_SESSION_ID_HEADER,
    SESSION_ID_PATTERN,
    StreamableHTTPServerTransport,
)
from core.models import AuthPrincipal, AuditEvent
from core.proxy import VanguardProxy, ProxyConfig, setup_audit_logger
from core import session_isolation
from core import auth
from core.rules_engine import RulesEngine
from core import fleet
from mcp.types import INVALID_REQUEST, ErrorData, JSONRPCError

logger = logging.getLogger("vanguard.sse")

# Initialize RulesEngine
RulesEngine.get_instance()

class RateLimiter:
    """Simple token-bucket rate limiter."""
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, amount: float = 1.0) -> bool:
        async with self._lock:
            now = time.monotonic()
            passed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + passed * self.rate)
            self.last_update = now
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

_rate_limiters: dict[str, RateLimiter] = {}
_active_connections: dict[str, int] = collections.defaultdict(int)
_total_active_connections: int = 0
_registry_lock = asyncio.Lock()

def _get_sse_config():
    cfg = {
        "API_KEY": os.getenv("VANGUARD_API_KEY", ""),
        "ALLOWED_IPS": os.getenv("VANGUARD_ALLOWED_IPS", "").split(",") if os.getenv("VANGUARD_ALLOWED_IPS") else [],
        "ALLOWED_ORIGINS": [origin.strip().lower() for origin in os.getenv("VANGUARD_ALLOWED_ORIGINS", "").split(",") if origin.strip()],
        "REQUIRE_ORIGIN": os.getenv("VANGUARD_REQUIRE_ORIGIN", "false").lower() == "true",
        "EXPECTED_BEARER_ISSUER": os.getenv("VANGUARD_EXPECTED_BEARER_ISSUER", "").strip(),
        "EXPECTED_BEARER_AUDIENCE": [aud.strip() for aud in os.getenv("VANGUARD_EXPECTED_BEARER_AUDIENCE", "").split(",") if aud.strip()],
        "REQUIRED_BEARER_CLAIMS": [claim.strip() for claim in os.getenv("VANGUARD_REQUIRED_BEARER_CLAIMS", "").split(",") if claim.strip()],
        "REQUIRED_BEARER_SCOPES": [scope.strip() for scope in os.getenv("VANGUARD_REQUIRED_BEARER_SCOPES", "").split(",") if scope.strip()],
        "BEARER_SCOPE_MATCH": os.getenv("VANGUARD_BEARER_SCOPE_MATCH", "any").lower(),
        "BEARER_CLAIM_POLICY": os.getenv("VANGUARD_BEARER_CLAIM_POLICY", "warn").lower(),
        "BIND_STREAMABLE_SESSIONS": os.getenv("VANGUARD_BIND_STREAMABLE_SESSIONS", "true").lower() == "true",
        "TRUST_PROXY_HEADERS": os.getenv("VANGUARD_TRUST_PROXY_HEADERS", "false").lower() == "true",
        "TRUSTED_PROXY_IPS": [ip.strip() for ip in os.getenv("VANGUARD_TRUSTED_PROXY_IPS", "").split(",") if ip.strip()],
        "MAX_CONCURRENCY": int(os.getenv("VANGUARD_MAX_CONCURRENT_SSE", "5")),
        "MAX_GLOBAL_CONNECTIONS": int(os.getenv("VANGUARD_MAX_GLOBAL_CONNECTIONS", "50")),
        "RATE_LIMIT_PER_SEC": float(os.getenv("VANGUARD_SSE_RATE_LIMIT", "1.0")),
        "MAX_BODY_BYTES": int(os.getenv("VANGUARD_SSE_MAX_BODY_BYTES", "131072")),
    }
    cfg.update(auth.load_auth_config())
    return cfg


def _scope_headers(scope) -> dict[bytes, bytes]:
    return dict(scope.get("headers", []))


def _normalize_origin(origin: str) -> str:
    return origin.strip().rstrip("/").lower()


def _is_loopback_host(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _normalize_ip(ip: str) -> str:
    value = ip.strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _peer_ip(scope) -> str:
    return _normalize_ip(scope.get("client", ["unknown"])[0])


def _extract_forwarded_for(headers: dict[bytes, bytes]) -> str:
    raw = headers.get(b"x-forwarded-for", b"").decode("utf-8", errors="replace").strip()
    if not raw:
        return ""
    first_hop = raw.split(",")[0].strip()
    return _normalize_ip(first_hop)


def _effective_client_ip(scope, cfg: dict[str, Any]) -> str:
    peer_ip = _peer_ip(scope)
    if not cfg.get("TRUST_PROXY_HEADERS"):
        return peer_ip

    trusted_proxy_ips = {_normalize_ip(ip) for ip in cfg.get("TRUSTED_PROXY_IPS", []) if ip}
    if peer_ip not in trusted_proxy_ips:
        return peer_ip

    headers = _scope_headers(scope)
    forwarded_ip = _extract_forwarded_for(headers)
    return forwarded_ip or peer_ip


def _check_origin(scope, cfg: dict[str, Any]) -> tuple[bool, int, str]:
    headers = _scope_headers(scope)
    origin = headers.get(b"origin", b"").decode("utf-8", errors="replace").strip()

    if not origin:
        if cfg.get("REQUIRE_ORIGIN"):
            return False, 403, "Missing Origin header."
        return True, 200, ""

    normalized = _normalize_origin(origin)
    allowed_origins = cfg.get("ALLOWED_ORIGINS", [])
    if allowed_origins and normalized not in allowed_origins:
        return False, 403, f"Origin '{origin}' is not allowed."

    return True, 200, ""


def _validate_message_request(scope, cfg: dict[str, Any]) -> tuple[bool, int, str]:
    headers = _scope_headers(scope)
    raw_type = headers.get(b"content-type", b"").decode("utf-8", errors="replace").lower()
    if raw_type and "application/json" not in raw_type:
        return False, 415, "Unsupported Content-Type. Use application/json."

    raw_len = headers.get(b"content-length", b"").decode("utf-8", errors="replace").strip()
    if raw_len:
        try:
            content_len = int(raw_len)
        except ValueError:
            return False, 400, "Invalid Content-Length header."
        if content_len > cfg["MAX_BODY_BYTES"]:
            return False, 413, f"Request body too large. Limit is {cfg['MAX_BODY_BYTES']} bytes."

    return True, 200, ""

async def _check_auth(scope) -> tuple[bool, str, Optional[AuthPrincipal]]:
    """Returns (is_authed, error_message, principal). Module-level for testing."""
    cfg = _get_sse_config()
    client_ip = _peer_ip(scope)
    
    if cfg["ALLOWED_IPS"] and client_ip not in cfg["ALLOWED_IPS"]:
        return False, f"IP {client_ip} not in allowlist.", None

    auth_mode = cfg.get("AUTH_MODE", "none")
    if auth_mode == "none" and not cfg["API_KEY"]:
        return True, "", None

    headers = dict(scope.get("headers", []))
    try:
        api_key = headers.get(b"x-api-key", b"").decode("utf-8")
        bearer = headers.get(b"authorization", b"").decode("utf-8")
    except UnicodeDecodeError:
        return False, "Invalid encoding in authentication headers.", None

    auth_type = None
    credential = ""
    if bearer.lower().startswith("bearer "):
        credential = bearer[7:].strip()
        auth_type = "bearer"
    elif api_key:
        credential = api_key
        auth_type = "api_key"

    if auth_mode == "oauth":
        if auth_type != "bearer" or not credential:
            return False, "Unauthorized. Provide a valid bearer token.", None
        try:
            verified = await auth.validate_bearer_token(credential, cfg)
        except auth.AuthValidationError as exc:
            return False, f"Bearer token validation failed: {exc}", None

        claims = verified.claims
        principal = AuthPrincipal(
            principal_id=_resolve_principal_id("bearer", credential, claims),
            auth_type="bearer",
            roles=list(dict.fromkeys(["authenticated", *_extract_token_roles(claims)])),
            attributes={
                "client_ip": client_ip,
                "claims_verified": True,
                "token_subject": claims.get("sub"),
                "token_issuer": claims.get("iss"),
                "token_audience": _normalize_token_audience(claims.get("aud")),
                "token_scope": _normalize_token_scope(claims),
                "token_claim_keys": sorted(key for key in claims.keys() if isinstance(key, str)),
            },
        )
        claim_issues = _evaluate_bearer_claim_expectations(cfg, claims)
        if claim_issues:
            principal.attributes["auth_warnings"] = claim_issues
            principal.attributes["claim_policy"] = _normalize_claim_policy(cfg.get("BEARER_CLAIM_POLICY"))
            if _normalize_claim_policy(cfg.get("BEARER_CLAIM_POLICY")) == "block":
                return False, f"Bearer token claims failed policy: {'; '.join(claim_issues)}", None
        return True, "", principal

    ok = hmac.compare_digest(api_key, cfg["API_KEY"]) or hmac.compare_digest(credential, cfg["API_KEY"])
    if not ok:
        return False, "Unauthorized. Provide valid VANGUARD_API_KEY.", None

    claims = _decode_unverified_bearer_claims(credential) if auth_type == "bearer" else {}
    principal_id = _resolve_principal_id(auth_type, credential, claims)
    roles = ["authenticated", *_extract_token_roles(claims)] if auth_type == "bearer" else ["authenticated"]
    attributes = {"client_ip": client_ip}
    claim_issues = _evaluate_bearer_claim_expectations(cfg, claims) if auth_type == "bearer" else []
    if claims:
        attributes.update(
            {
                "claims_verified": False,
                "token_subject": claims.get("sub"),
                "token_issuer": claims.get("iss"),
                "token_audience": _normalize_token_audience(claims.get("aud")),
                "token_scope": _normalize_token_scope(claims),
                "token_claim_keys": sorted(key for key in claims.keys() if isinstance(key, str)),
            }
        )
    if claim_issues:
        attributes["auth_warnings"] = claim_issues
        attributes["claim_policy"] = _normalize_claim_policy(cfg.get("BEARER_CLAIM_POLICY"))

    principal = AuthPrincipal(
        principal_id=principal_id,
        auth_type=auth_type or "unknown",
        roles=list(dict.fromkeys(role for role in roles if role)),
        attributes={key: value for key, value in attributes.items() if value is not None},
    )
    if claim_issues and _normalize_claim_policy(cfg.get("BEARER_CLAIM_POLICY")) == "block":
        return False, f"Bearer token claims failed policy: {'; '.join(claim_issues)}", None
    return True, "", principal


def _audit_auth_finding(
    *,
    scope,
    action: str,
    reason: str,
    principal: Optional[AuthPrincipal] = None,
) -> None:
    warnings = []
    if principal:
        raw_warnings = principal.attributes.get("auth_warnings")
        if isinstance(raw_warnings, list):
            warnings = [item for item in raw_warnings if isinstance(item, str)]

    audit = setup_audit_logger(os.getenv("VANGUARD_LOG_FILE", "audit.log"))
    audit.info(
        AuditEvent(
            session_id="transport-auth",
            principal_id=principal.principal_id if principal else None,
            auth_type=principal.auth_type if principal else None,
            direction="system",
            method="auth/check",
            action=action,
            rule_id="VANGUARD-AUTH-CLAIMS",
            blocked_reason=reason,
            auth_warnings=warnings,
        ).to_log_line(format=os.getenv("VANGUARD_AUDIT_FORMAT", "text").lower())
    )


def _principal_fingerprint(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _decode_unverified_bearer_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2 or not parts[1]:
        return {}

    payload = parts[1]
    padded = payload + "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        claims = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}

    return claims if isinstance(claims, dict) else {}


def _normalize_token_audience(audience: Any) -> list[str]:
    if isinstance(audience, str):
        return [audience]
    if isinstance(audience, list):
        return [item for item in audience if isinstance(item, str)]
    return []


def _normalize_token_scope(claims: dict[str, Any]) -> list[str]:
    scope = claims.get("scope")
    if isinstance(scope, str):
        return [item for item in scope.split() if item]
    if isinstance(scope, list):
        return [item for item in scope if isinstance(item, str)]
    scp = claims.get("scp")
    if isinstance(scp, str):
        return [item for item in scp.split() if item]
    if isinstance(scp, list):
        return [item for item in scp if isinstance(item, str)]
    return []


def _extract_token_roles(claims: dict[str, Any]) -> list[str]:
    roles = claims.get("roles")
    if isinstance(roles, str):
        return [roles]
    if isinstance(roles, list):
        return [item for item in roles if isinstance(item, str)]
    return []


def _resolve_principal_id(auth_type: Optional[str], credential: str, claims: dict[str, Any]) -> str:
    if auth_type == "bearer":
        subject = claims.get("sub")
        issuer = claims.get("iss")
        if isinstance(subject, str) and subject:
            if isinstance(issuer, str) and issuer:
                return f"bearer:{issuer}:{subject}"
            return f"bearer:{subject}"
    if credential and auth_type:
        return f"{auth_type}:{_principal_fingerprint(credential)}"
    return "authenticated"


def _normalize_claim_policy(policy: Any) -> str:
    if isinstance(policy, str) and policy.lower() == "block":
        return "block"
    return "warn"


def _evaluate_bearer_claim_expectations(cfg: dict[str, Any], claims: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    expected_issuer = cfg.get("EXPECTED_BEARER_ISSUER", "")
    expected_audience = cfg.get("EXPECTED_BEARER_AUDIENCE", [])
    required_claims = cfg.get("REQUIRED_BEARER_CLAIMS", [])
    required_scopes = cfg.get("REQUIRED_BEARER_SCOPES", [])
    scope_match = _normalize_scope_match(cfg.get("BEARER_SCOPE_MATCH"))
    actual_issuer = claims.get("iss")
    actual_audience = _normalize_token_audience(claims.get("aud"))
    actual_scopes = _normalize_token_scope(claims)

    if expected_issuer:
        if not isinstance(actual_issuer, str) or not actual_issuer:
            issues.append("missing issuer claim")
        elif actual_issuer != expected_issuer:
            issues.append(f"issuer mismatch (expected {expected_issuer}, got {actual_issuer})")

    if expected_audience:
        if not actual_audience:
            issues.append("missing audience claim")
        elif not any(aud in actual_audience for aud in expected_audience):
            issues.append(
                "audience mismatch "
                f"(expected one of {expected_audience}, got {actual_audience})"
            )

    for claim_name in required_claims:
        if claim_name not in claims:
            issues.append(f"missing required claim '{claim_name}'")

    if required_scopes:
        if not actual_scopes:
            issues.append("missing scope claim")
        elif scope_match == "all":
            missing_scopes = [scope for scope in required_scopes if scope not in actual_scopes]
            if missing_scopes:
                issues.append(
                    f"scope mismatch (required all of {required_scopes}, missing {missing_scopes}, got {actual_scopes})"
                )
        elif not any(scope in actual_scopes for scope in required_scopes):
            issues.append(
                f"scope mismatch (required any of {required_scopes}, got {actual_scopes})"
            )

    return issues


def _normalize_scope_match(value: Any) -> str:
    if isinstance(value, str) and value.lower() == "all":
        return "all"
    return "any"

async def _send_error(send, status: int, message: str):
    await send({"type": "http.response.start", "status": status, "headers": [[b"content-type", b"application/json"]]})
    await send({"type": "http.response.body", "body": json.dumps({"error": message}).encode("utf-8")})


async def _send_error_with_headers(send, status: int, message: str, headers: list[tuple[bytes, bytes]] | None = None):
    response_headers = [[b"content-type", b"application/json"]]
    if headers:
        response_headers.extend([[name, value] for name, value in headers])
    await send({"type": "http.response.start", "status": status, "headers": response_headers})
    await send({"type": "http.response.body", "body": json.dumps({"error": message}).encode("utf-8")})


def _oauth_www_authenticate_value(
    error: str | None = None,
    description: str | None = None,
    scope: str | None = None,
) -> str:
    parts = ['Bearer realm="mcpvanguard"']
    if error:
        parts.append(f'error="{error}"')
    if description:
        escaped = description.replace("\\", "\\\\").replace('"', '\\"')
        parts.append(f'error_description="{escaped}"')
    if scope:
        escaped_scope = scope.replace("\\", "\\\\").replace('"', '\\"')
        parts.append(f'scope="{escaped_scope}"')
    return ", ".join(parts)


def _auth_error_response(err: str, cfg: dict[str, Any], oauth_error: Optional[str] = None) -> tuple[int, list[tuple[bytes, bytes]] | None]:
    if cfg.get("AUTH_MODE") != "oauth":
        return (401 if "Unauthorized" in err else 403, None)

    required_scope = " ".join(cfg.get("REQUIRED_BEARER_SCOPES", [])) or None

    if not oauth_error:
        if err == "Unauthorized. Provide a valid bearer token.":
            challenge = _oauth_www_authenticate_value()
            return 401, [(b"www-authenticate", challenge.encode("utf-8"))]
        if err == "Invalid encoding in authentication headers.":
            oauth_error = "invalid_request"
        elif "Insufficient scope" in err or "scope mismatch" in err or "missing scope claim" in err:
            oauth_error = "insufficient_scope"
        else:
            oauth_error = "invalid_token"

    status = 403 if oauth_error == "insufficient_scope" else 400 if oauth_error == "invalid_request" else 401
    challenge = _oauth_www_authenticate_value(
        oauth_error,
        err,
        scope=required_scope if oauth_error == "insufficient_scope" else None,
    )
    return status, [(b"www-authenticate", challenge.encode("utf-8"))]

class StreamWrapper:
    def __init__(self, read_stream, write_stream):
        self.read_stream = read_stream
        self.write_stream = write_stream
        self._buffer = b""

    async def readline(self) -> bytes:
        while True:
            if b"\n" in self._buffer:
                idx = self._buffer.find(b"\n")
                line = self._buffer[:idx+1]
                self._buffer = self._buffer[idx+1:]
                return line

            try:
                msg = await self.read_stream.receive()
                if not msg:
                    return b""
                
                # SseServerTransport yields SessionMessage(message=...)
                if hasattr(msg, "message"):
                    msg = msg.message
                
                chunk = b""
                if hasattr(msg, "model_dump_json"):
                    chunk = msg.model_dump_json().encode("utf-8")
                elif hasattr(msg, "json"):
                    chunk = msg.json().encode("utf-8")
                elif isinstance(msg, dict):
                    chunk = json.dumps(msg).encode("utf-8")
                elif isinstance(msg, bytes):
                    chunk = msg
                else:
                    try:
                        chunk = json.dumps(msg, default=str).encode("utf-8")
                    except Exception:
                        chunk = str(msg).encode("utf-8")
                
                self._buffer += chunk
                
                # Check for balanced JSON object
                stripped = self._buffer.strip()
                if stripped.startswith(b"{") and stripped.endswith(b"}"):
                    line = self._buffer
                    if not line.endswith(b"\n"):
                        line += b"\n"
                    self._buffer = b""
                    return line
            except Exception as e:
                logger.debug(f"StreamWrapper read error: {e}")
                return b""

    def write(self, data: bytes):
        self._pending_write = data

    async def drain(self):
        if hasattr(self, "_pending_write"):
            try:
                raw_str = self._pending_write.decode("utf-8", errors="replace").strip()
                try:
                    obj = json.loads(raw_str)
                    from mcp.types import JSONRPCMessage
                    # Proper MCP SDK serialization
                    msg_obj = SessionMessage(message=JSONRPCMessage.model_validate(obj))
                    await self.write_stream.send(msg_obj)
                except Exception:
                    # Fallback for non-JSON or other errors
                    await self.write_stream.send(raw_str)
            except Exception as e:
                logger.error(f"StreamWrapper drain error: {e}")
            finally:
                if hasattr(self, "_pending_write"):
                    del self._pending_write

@dataclass
class ServerContext:
    server_command: list[str]
    config: Optional[ProxyConfig]
    sse_transport: SseServerTransport
    cfg: dict[str, Any]
    streamable_manager: Optional["VanguardStreamableSessionManager"] = None


@dataclass(frozen=True)
class StreamableSessionBinding:
    client_ip: str
    origin: str
    user_agent: str
    principal_id: str
    auth_type: str


class VanguardStreamableSessionManager:
    """Owns Streamable HTTP sessions and bridges them into VanguardProxy instances."""

    def __init__(
        self,
        server_command: list[str],
        config: Optional[ProxyConfig],
        *,
        enforce_bindings: bool = True,
        request_config: Optional[dict[str, Any]] = None,
    ):
        self.server_command = server_command
        self.config = config
        self.enforce_bindings = enforce_bindings
        self.request_config = request_config or _get_sse_config()
        self._sessions: dict[str, StreamableHTTPServerTransport] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._bindings: dict[str, StreamableSessionBinding] = {}
        self._principals: dict[str, Optional[AuthPrincipal]] = {}
        self._lock = asyncio.Lock()

    async def shutdown(self) -> None:
        async with self._lock:
            tasks = list(self._tasks.values())
            transports = list(self._sessions.values())
            self._tasks.clear()
            self._sessions.clear()
            self._bindings.clear()
            self._principals.clear()

        for transport in transports:
            try:
                await transport.terminate()
            except Exception:
                logger.debug("Error terminating streamable transport during shutdown", exc_info=True)

        for task in tasks:
            task.cancel()

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def handle_request(self, scope, receive, send) -> None:
        request_headers = _scope_headers(scope)
        requested_session_id = request_headers.get(MCP_SESSION_ID_HEADER.encode("ascii"), b"").decode("utf-8", errors="replace") or None
        method = scope.get("method", "GET").upper()

        if requested_session_id and not self._is_valid_session_id(requested_session_id):
            await self._send_invalid_session(scope, receive, send)
            return

        transport = None
        if requested_session_id:
            async with self._lock:
                transport = self._sessions.get(requested_session_id)
                binding = self._bindings.get(requested_session_id)
            if transport is None:
                await self._send_session_not_found(scope, receive, send)
                return
            current_binding = self._make_binding(scope)
            if self.enforce_bindings and (binding is None or binding != current_binding):
                logger.warning(
                    "Rejected Streamable HTTP session reuse due to binding mismatch for session %s: expected=%s actual=%s",
                    requested_session_id,
                    binding,
                    current_binding,
                )
                await self._send_session_binding_mismatch(scope, receive, send)
                return
        else:
            transport = await self._create_session(scope)

        await transport.handle_request(scope, receive, send)

        if method == "DELETE" and transport.mcp_session_id:
            await self._drop_session(transport.mcp_session_id)

    async def _create_session(self, scope) -> StreamableHTTPServerTransport:
        transport = StreamableHTTPServerTransport(
            mcp_session_id=os.urandom(16).hex(),
            is_json_response_enabled=False,
        )
        assert transport.mcp_session_id is not None

        ready = asyncio.Event()
        principal = self._scope_principal(scope)
        task = asyncio.create_task(self._run_session(transport, ready, principal))
        await ready.wait()

        async with self._lock:
            self._sessions[transport.mcp_session_id] = transport
            self._tasks[transport.mcp_session_id] = task
            self._bindings[transport.mcp_session_id] = self._make_binding(scope)
            self._principals[transport.mcp_session_id] = principal

        return transport

    async def _run_session(
        self,
        transport: StreamableHTTPServerTransport,
        ready: asyncio.Event,
        principal: Optional[AuthPrincipal],
    ) -> None:
        session_id = transport.mcp_session_id
        try:
            async with transport.connect() as (read_stream, write_stream):
                bridge = StreamWrapper(read_stream, write_stream)
                ready.set()
                proxy = VanguardProxy(
                    server_command=self.server_command,
                    config=self.config,
                    agent_reader=bridge,
                    agent_writer=bridge,
                    principal=principal,
                    server_id=session_isolation.derive_server_id(self.server_command),
                )
                await proxy.run()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Streamable HTTP session crashed: %s", session_id)
        finally:
            ready.set()
            if session_id:
                await self._drop_session(session_id, terminate=False)

    async def _drop_session(self, session_id: str, terminate: bool = True) -> None:
        async with self._lock:
            transport = self._sessions.pop(session_id, None)
            task = self._tasks.pop(session_id, None)
            self._bindings.pop(session_id, None)
            self._principals.pop(session_id, None)

        if terminate and transport is not None:
            try:
                await transport.terminate()
            except Exception:
                logger.debug("Error terminating streamable transport", exc_info=True)

        if task is not None and not task.done() and task is not asyncio.current_task():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _send_session_not_found(self, scope, receive, send) -> None:
        error_response = JSONRPCError(
            jsonrpc="2.0",
            id="server-error",
            error=ErrorData(
                code=INVALID_REQUEST,
                message="Session not found",
            ),
        )
        from starlette.responses import Response

        response = Response(
            content=error_response.model_dump_json(by_alias=True, exclude_none=True),
            status_code=HTTPStatus.NOT_FOUND,
            media_type="application/json",
        )
        await response(scope, receive, send)

    async def _send_invalid_session(self, scope, receive, send) -> None:
        error_response = JSONRPCError(
            jsonrpc="2.0",
            id="server-error",
            error=ErrorData(
                code=INVALID_REQUEST,
                message="Invalid session ID format",
            ),
        )
        from starlette.responses import Response

        response = Response(
            content=error_response.model_dump_json(by_alias=True, exclude_none=True),
            status_code=HTTPStatus.BAD_REQUEST,
            media_type="application/json",
        )
        await response(scope, receive, send)

    async def _send_session_binding_mismatch(self, scope, receive, send) -> None:
        error_response = JSONRPCError(
            jsonrpc="2.0",
            id="server-error",
            error=ErrorData(
                code=INVALID_REQUEST,
                message="Session binding mismatch",
            ),
        )
        from starlette.responses import Response

        response = Response(
            content=error_response.model_dump_json(by_alias=True, exclude_none=True),
            status_code=HTTPStatus.FORBIDDEN,
            media_type="application/json",
        )
        await response(scope, receive, send)

    def _make_binding(self, scope) -> StreamableSessionBinding:
        headers = _scope_headers(scope)
        origin = headers.get(b"origin", b"").decode("utf-8", errors="replace").strip()
        user_agent = headers.get(b"user-agent", b"").decode("utf-8", errors="replace").strip()
        principal = self._scope_principal(scope)
        return StreamableSessionBinding(
            client_ip=_effective_client_ip(scope, self.request_config),
            origin=_normalize_origin(origin) if origin else "",
            user_agent=user_agent,
            principal_id=principal.principal_id if principal else "",
            auth_type=principal.auth_type if principal else "",
        )

    @staticmethod
    def _scope_principal(scope) -> Optional[AuthPrincipal]:
        principal = scope.get("vanguard.auth_principal")
        if isinstance(principal, AuthPrincipal):
            return principal
        return None

    @staticmethod
    def _is_valid_session_id(session_id: str) -> bool:
        return SESSION_ID_PATTERN.fullmatch(session_id) is not None

async def handle_sse(scope, receive, send, ctx: ServerContext):
    global _total_active_connections
    assert scope["type"] == "http"
    ok, status, message = _check_origin(scope, ctx.cfg)
    if not ok:
        await _send_error(send, status, message)
        return

    authed, err, principal = await _check_auth(scope)
    if not authed:
        if "Bearer token claims failed policy:" in err or "Bearer token validation failed:" in err:
            _audit_auth_finding(scope=scope, action="BLOCK", reason=err)
        status, headers = _auth_error_response(err, ctx.cfg)
        await _send_error_with_headers(send, status, err, headers)
        return
    if principal and principal.attributes.get("auth_warnings"):
        _audit_auth_finding(
            scope=scope,
            action="WARN",
            reason="Bearer token claims did not match configured expectations.",
            principal=principal,
        )

    client_ip = scope.get("client", ["unknown"])[0]

    # Registry operations (Rate Limiter and Concurrency Guard)
    async with _registry_lock:
        if client_ip not in _rate_limiters:
            _rate_limiters[client_ip] = RateLimiter(ctx.cfg["RATE_LIMIT_PER_SEC"], ctx.cfg["MAX_CONCURRENCY"] * 2)
        
        limiter = _rate_limiters[client_ip]
        
        # Concurrency Guard (Global)
        if _total_active_connections >= ctx.cfg["MAX_GLOBAL_CONNECTIONS"]:
            logger.warning("Global connection limit (%d) reached.", ctx.cfg["MAX_GLOBAL_CONNECTIONS"])
            await _send_error(send, 503, "Server too busy. Global connection limit reached.")
            return

        # Concurrency Guard (Per IP)
        if _active_connections[client_ip] >= ctx.cfg["MAX_CONCURRENCY"]:
            await _send_error(send, 429, f"Concurrent connection limit ({ctx.cfg['MAX_CONCURRENCY']}) reached.")
            return

        _active_connections[client_ip] += 1
        _total_active_connections += 1

    # Rate Limiting (consume outside the registry lock to avoid blocking other IPs)
    if not await limiter.consume():
        async with _registry_lock:
            _active_connections[client_ip] -= 1
            _total_active_connections -= 1
        await _send_error(send, 429, "Too Many Requests. Rate limit exceeded.")



    try:
        async with ctx.sse_transport.connect_sse(scope, receive, send) as (read_stream, write_stream):
            bridge = StreamWrapper(read_stream, write_stream)
            proxy = VanguardProxy(
                server_command=ctx.server_command,
                config=ctx.config,
                agent_reader=bridge,
                agent_writer=bridge,
                principal=principal,
                server_id=session_isolation.derive_server_id(ctx.server_command),
            )
            await proxy.run()
    finally:
        async with _registry_lock:
            _active_connections[client_ip] -= 1
            _total_active_connections -= 1

async def handle_messages(scope, receive, send, ctx: ServerContext):
    assert scope["type"] == "http"
    ok, status, message = _check_origin(scope, ctx.cfg)
    if not ok:
        await _send_error(send, status, message)
        return

    authed, err, _principal = await _check_auth(scope)
    if not authed:
        if "Bearer token claims failed policy:" in err or "Bearer token validation failed:" in err:
            _audit_auth_finding(scope=scope, action="BLOCK", reason=err)
        status, headers = _auth_error_response(err, ctx.cfg)
        await _send_error_with_headers(send, status, err, headers)
        return
    if _principal and _principal.attributes.get("auth_warnings"):
        _audit_auth_finding(
            scope=scope,
            action="WARN",
            reason="Bearer token claims did not match configured expectations.",
            principal=_principal,
        )

    client_ip = scope.get("client", ["unknown"])[0]
    
    # Apply the same rate-limiting and concurrency bucket as handle_sse
    async with _registry_lock:
        if client_ip not in _rate_limiters:
            _rate_limiters[client_ip] = RateLimiter(ctx.cfg["RATE_LIMIT_PER_SEC"], ctx.cfg["MAX_CONCURRENCY"] * 2)
        limiter = _rate_limiters[client_ip]
    
    if not await limiter.consume():
        await _send_error(send, 429, "Too Many Requests. Message rate limit exceeded.")
        return

    ok, status, message = _validate_message_request(scope, ctx.cfg)
    if not ok:
        await _send_error(send, status, message)
        return

    await ctx.sse_transport.handle_post_message(scope, receive, send)


async def handle_mcp(scope, receive, send, ctx: ServerContext):
    assert scope["type"] == "http"
    ok, status, message = _check_origin(scope, ctx.cfg)
    if not ok:
        await _send_error(send, status, message)
        return

    authed, err, principal = await _check_auth(scope)
    if not authed:
        if "Bearer token claims failed policy:" in err or "Bearer token validation failed:" in err:
            _audit_auth_finding(scope=scope, action="BLOCK", reason=err)
        status, headers = _auth_error_response(err, ctx.cfg)
        await _send_error_with_headers(send, status, err, headers)
        return
    if principal and principal.attributes.get("auth_warnings"):
        _audit_auth_finding(
            scope=scope,
            action="WARN",
            reason="Bearer token claims did not match configured expectations.",
            principal=principal,
        )
    scope["vanguard.auth_principal"] = principal

    ok, status, message = _validate_message_request(scope, ctx.cfg)
    if scope.get("method", "").upper() == "POST" and not ok:
        await _send_error(send, status, message)
        return

    if ctx.streamable_manager is None:
        await _send_error(send, 500, "Streamable HTTP transport is not initialized.")
        return

    await ctx.streamable_manager.handle_request(scope, receive, send)

async def health_check_handler(scope, receive, send):
    """Deep health check for Railway/Cloud readiness."""
    assert scope["type"] == "http"
    
    from core.behavioral import check_redis_health
    from core.semantic import check_semantic_health
    from core import __version__
    import starlette.responses
    
    redis_ok = await check_redis_health()
    semantic_ok = await check_semantic_health()
    
    status = "ok" if redis_ok and semantic_ok else "degraded"
    
    health_data = {
        "status": status,
        "version": __version__,
        "layers": {
            "l1_rules": "ok", 
            "l2_semantic": "ok" if semantic_ok else "unreachable",
            "l3_behavioral": "ok" if redis_ok else "redis_disconnected"
        },
        "timestamp": time.time()
    }
    
    response = starlette.responses.Response(
        json.dumps(health_data), 
        status_code=200 if status == "ok" else 503,
        media_type="application/json"
    )
    await response(scope, receive, send)

async def run_sse_server(
    server_command: list[str],
    host: str = "127.0.0.1",
    port: int = 8080,
    config: Optional[ProxyConfig] = None
):
    from starlette.applications import Starlette
    from starlette.routing import Route

    cfg = _get_sse_config()
    if cfg["API_KEY"]:
        print(f"[Vanguard] SSE authentication ENABLED (VANGUARD_API_KEY is set)")
    else:
        print(f"[Vanguard] WARNING: VANGUARD_API_KEY not set. SSE endpoints are open.")

    if not _is_loopback_host(host):
        print(f"[Vanguard] WARNING: HTTP bridge is binding to non-loopback host {host}.")
        if not cfg["API_KEY"]:
            print("[Vanguard] WARNING: Public bind without VANGUARD_API_KEY increases exposure.")
    if not cfg["BIND_STREAMABLE_SESSIONS"]:
        print("[Vanguard] WARNING: Streamable HTTP session binding is DISABLED.")
    if cfg["TRUST_PROXY_HEADERS"]:
        print("[Vanguard] WARNING: Trusting proxy headers for Streamable HTTP identity binding.")

    # Ensure the RulesEngine is initialized as a singleton for this process
    RulesEngine(rules_dir=config.rules_dir)

    print(f"Starting Vanguard SSE Bridge on {host}:{port}")
    sse_transport = SseServerTransport("/messages")
    streamable_manager = VanguardStreamableSessionManager(
        server_command=server_command,
        config=config,
        enforce_bindings=cfg["BIND_STREAMABLE_SESSIONS"],
        request_config=cfg,
    )
    
    ctx = ServerContext(
        server_command=server_command,
        config=config,
        sse_transport=sse_transport,
        cfg=cfg,
        streamable_manager=streamable_manager,
    )

    @asynccontextmanager
    async def lifespan(app):
        # Start background tasks
        await fleet.start_fleet_sync(ctx.cfg, config.rules_dir)
        try:
            yield
        finally:
            # Shutdown background tasks
            await fleet.stop_fleet_sync()
            await streamable_manager.shutdown()

    class AsgiAppWrapper:
        def __init__(self, func, ctx=None):
            self.func = func
            self.ctx = ctx
        async def __call__(self, scope, receive, send):
            if self.ctx:
                await self.func(scope, receive, send, self.ctx)
            else:
                await self.func(scope, receive, send)

    app = Starlette(
        debug=False,
        lifespan=lifespan,
        routes=[
            Route("/mcp", endpoint=AsgiAppWrapper(handle_mcp, ctx), methods=["GET", "POST", "DELETE"]),
            Route("/sse", endpoint=AsgiAppWrapper(handle_sse, ctx), methods=["GET"]),
            Route("/messages", endpoint=AsgiAppWrapper(handle_messages, ctx), methods=["POST"]),
            Route("/health", endpoint=health_check_handler, methods=["GET"]),
        ]
    )

    import uvicorn
    config_uv = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        proxy_headers=False,
    )
    server = uvicorn.Server(config_uv)
    await server.serve()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        asyncio.run(run_sse_server(sys.argv[1:]))
    else:
        asyncio.run(run_sse_server([sys.executable, "-c", "import sys; [sys.stdout.write(l) for l in sys.stdin]"]))
