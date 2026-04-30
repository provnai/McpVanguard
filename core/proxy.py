"""
core/proxy.py
The McpVanguard transparent stdio proxy.

Sits between an AI agent and a real MCP server subprocess.
Intercepts every JSON-RPC message in both directions,
runs inspection layers, and blocks or forwards accordingly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import math
import os
import sys
import time
import unicodedata
import urllib.parse
from typing import Optional, Any

if sys.platform != "win32":
    try:
        if os.getenv("VANGUARD_DISABLE_UVLOOP", "0") == "1" or os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("NIXPACKS"):
            raise ImportError("uvloop disabled by VANGUARD_DISABLE_UVLOOP or environment auto-detect (Railway/Nixpacks)")
        import uvloop
        HAS_UVLOOP = True
    except ImportError:
        HAS_UVLOOP = False
else:
    HAS_UVLOOP = False

from core.models import (
    AuthPrincipal,
    AuditEvent,
    InspectionResult,
    RuleMatch,
    make_block_response,
)
from core.rules_engine import RulesEngine
from core.session import SessionManager, SessionState
from core import semantic, behavioral, telemetry
from core.vex_client import submit_blocked_call
from core import management
from core import metadata_inspection
from core import server_integrity
from core import capability_fingerprint
from core import session_isolation
from core import provenance
from core import supplier_signatures
from core import sigstore_bundle
from core.risk import RiskEngine, EnforcementLevel

logger = logging.getLogger(__name__)

from core.auth import TOOL_SCOPE_MAPPING


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class ProxyConfig:
    """Runtime configuration for the proxy, loaded from env vars."""

    def __init__(self):
        self.log_level: str = os.getenv("VANGUARD_LOG_LEVEL", "INFO")
        self.log_file: str = os.getenv("VANGUARD_LOG_FILE", "audit.log")
        self.rules_dir: str = os.getenv("VANGUARD_RULES_DIR", "rules")
        self.semantic_enabled: bool = os.getenv("VANGUARD_SEMANTIC_ENABLED", "false").lower() == "true"
        self.behavioral_enabled: bool = os.getenv("VANGUARD_BEHAVIORAL_ENABLED", "true").lower() == "true"
        self.management_tools_enabled: bool = os.getenv("VANGUARD_MANAGEMENT_TOOLS_ENABLED", "false").lower() == "true"
        self.block_threshold: float = float(os.getenv("VANGUARD_BLOCK_THRESHOLD", "0.8"))
        self.warn_threshold: float = float(os.getenv("VANGUARD_WARN_THRESHOLD", "0.5"))
        # Mode: "enforce" (default) or "audit" (log but don't block)
        self.mode: str = os.getenv("VANGUARD_MODE", "enforce").lower()
        # SSE auth key — also read by sse_server.py directly for early validation
        self.api_key: str = os.getenv("VANGUARD_API_KEY", "")
        # Off by default in production to avoid leaking rule internals.
        self.expose_block_reason: bool = os.getenv("VANGUARD_EXPOSE_BLOCK_REASON", "false").lower() == "true"
        # Maximum string length allowed in incoming tool calls (prevents memory exhaustion)
        self.max_string_len: int = int(os.getenv("VANGUARD_MAX_STRING_LEN", "65536")) # 64KB default
        # Audit format: "text" (human-readable) or "json" (SIEM ingest)
        self.audit_format: str = os.getenv("VANGUARD_AUDIT_FORMAT", "text").lower()
        self.metadata_inspection_enabled: bool = os.getenv("VANGUARD_METADATA_INSPECTION_ENABLED", "true").lower() == "true"
        self.metadata_policy: str = os.getenv("VANGUARD_METADATA_POLICY", "block").lower()
        self.server_manifest_file: str = os.getenv("VANGUARD_SERVER_MANIFEST_FILE", "")
        self.server_manifest_signature_file: str = os.getenv("VANGUARD_SERVER_MANIFEST_SIGNATURE_FILE", "")
        self.server_manifest_policy: str = os.getenv("VANGUARD_SERVER_MANIFEST_POLICY", "warn").lower()
        self.server_trust_policy: str = os.getenv("VANGUARD_SERVER_TRUST_POLICY", "off").lower()
        self.server_manifest_hash_executable: bool = os.getenv("VANGUARD_SERVER_MANIFEST_HASH_EXECUTABLE", "false").lower() == "true"
        self.server_provenance_file: str = os.getenv("VANGUARD_SERVER_PROVENANCE_FILE", "")
        self.server_provenance_signature_file: str = os.getenv("VANGUARD_SERVER_PROVENANCE_SIGNATURE_FILE", "")
        self.server_provenance_policy: str = os.getenv("VANGUARD_SERVER_PROVENANCE_POLICY", "off").lower()
        self.required_provenance_builders: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_REQUIRED_PROVENANCE_BUILDERS", "").split(",")
            if value.strip()
        ]
        self.server_artifact_signature_file: str = os.getenv("VANGUARD_SERVER_ARTIFACT_SIGNATURE_FILE", "")
        self.server_artifact_policy: str = os.getenv("VANGUARD_SERVER_ARTIFACT_POLICY", "off").lower()
        self.allowed_supplier_ids: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SUPPLIER_IDS", "").split(",")
            if value.strip()
        ]
        self.server_sigstore_bundle_file: str = os.getenv("VANGUARD_SERVER_SIGSTORE_BUNDLE_FILE", "")
        self.server_sigstore_policy: str = os.getenv("VANGUARD_SERVER_SIGSTORE_POLICY", "off").lower()
        self.allowed_sigstore_cert_fingerprints: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_CERT_FINGERPRINTS", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_identities: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_IDENTITIES", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_oidc_issuers: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_OIDC_ISSUERS", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_build_signer_uris: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_BUILD_SIGNER_URIS", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_source_repositories: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_SOURCE_REPOSITORIES", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_source_refs: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_SOURCE_REFS", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_source_digests: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_SOURCE_DIGESTS", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_build_triggers: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_BUILD_TRIGGERS", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_tlog_key_ids: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_TLOG_KEY_IDS", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_github_repositories: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_GITHUB_REPOSITORIES", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_github_refs: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_GITHUB_REFS", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_github_shas: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_GITHUB_SHAS", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_github_triggers: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_GITHUB_TRIGGERS", "").split(",")
            if value.strip()
        ]
        self.allowed_sigstore_github_workflow_names: list[str] = [
            value.strip()
            for value in os.getenv("VANGUARD_ALLOWED_SIGSTORE_GITHUB_WORKFLOW_NAMES", "").split(",")
            if value.strip()
        ]
        self.sigstore_tlog_policy: str = os.getenv("VANGUARD_SIGSTORE_TLOG_POLICY", "off").lower()
        self.capability_manifest_file: str = os.getenv("VANGUARD_CAPABILITY_MANIFEST_FILE", "")
        self.capability_manifest_signature_file: str = os.getenv("VANGUARD_CAPABILITY_MANIFEST_SIGNATURE_FILE", "")
        self.capability_trust_policy: str = os.getenv("VANGUARD_CAPABILITY_TRUST_POLICY", "off").lower()
        self.capability_manifest_policy: str = os.getenv("VANGUARD_CAPABILITY_MANIFEST_POLICY", "warn").lower()
        self.auth_warning_tool_policy: str = os.getenv("VANGUARD_AUTH_WARNING_TOOL_POLICY", "warn").lower()
        self.destructive_tool_auth_policy: str = os.getenv("VANGUARD_DESTRUCTIVE_TOOL_AUTH_POLICY", "block").lower()
        self.required_destructive_roles: list[str] = [
            value.strip() for value in os.getenv("VANGUARD_REQUIRED_DESTRUCTIVE_ROLES", "").split(",") if value.strip()
        ]
        self.required_destructive_scopes: list[str] = [
            value.strip() for value in os.getenv("VANGUARD_REQUIRED_DESTRUCTIVE_SCOPES", "").split(",") if value.strip()
        ]


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

def setup_audit_logger(log_file: str) -> logging.Logger:
    """Set up a dedicated file logger for the audit trail."""
    audit = logging.getLogger("vanguard.audit")
    audit.setLevel(logging.INFO)
    audit.propagate = False
    desired_path = os.path.abspath(log_file)

    existing_file = False
    existing_stderr = False
    for handler in list(audit.handlers):
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            if os.path.abspath(handler.baseFilename) == desired_path:
                existing_file = True
            else:
                audit.removeHandler(handler)
                handler.close()
        elif isinstance(handler, logging.StreamHandler) and getattr(handler, "stream", None) is sys.stderr:
            existing_stderr = True

    if not existing_file:
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        fh.setFormatter(logging.Formatter("%(message)s"))
        audit.addHandler(fh)

    if not existing_stderr:
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(logging.Formatter("%(message)s"))
        audit.addHandler(ch)
    return audit


# ---------------------------------------------------------------------------
# The Proxy
# ---------------------------------------------------------------------------

class VanguardProxy:
    """
    The core McpVanguard proxy.
    """

    def __init__(
        self,
        server_command: list[str],
        config: Optional[ProxyConfig] = None,
        agent_reader: Optional[asyncio.StreamReader] = None,
        agent_writer: Optional[asyncio.StreamWriter] = None,
        principal: Optional[AuthPrincipal] = None,
        server_id: Optional[str] = None,
    ):
        self.server_command = server_command
        self.config = config or ProxyConfig()
        self.principal = principal
        # Phase 6: derive a stable identity for the upstream server
        self._server_id: str = server_id or session_isolation.derive_server_id(server_command)
        self.session_manager = SessionManager()
        self.rules_engine = RulesEngine.get_instance()
        self.risk_engine = RiskEngine.get_instance()
        self.audit = setup_audit_logger(self.config.log_file)
        self._server_process: Optional[asyncio.subprocess.Process] = None
        self._session: Optional[SessionState] = None
        self._stats = {"allowed": 0, "blocked": 0, "warned": 0, "total": 0}
        self._pending_tool_lists: set[Any] = set()
        self._pending_initializations: set[Any] = set()
        self._expected_capability_manifest: Optional[dict[str, Any]] = None
        self._observed_capability_manifest: dict[str, Any] = {"version": 1, "initialize": None, "tools": None}

        self.agent_reader = agent_reader
        self.agent_writer = agent_writer

        logger.info(
            f"[Vanguard] Loaded {self.rules_engine.rule_count} rules from '{self.config.rules_dir}'"
        )

    def _current_risk_context(self) -> dict[str, Any]:
        """Return the current session risk state for audit enrichment."""
        if not self._session:
            return {}

        try:
            return {
                "risk_score": round(
                    self.risk_engine.get_score(self._session.session_id, self._server_id),
                    2,
                ),
                "risk_enforcement": self.risk_engine.get_enforcement(
                    self._session.session_id,
                    self._server_id,
                ).name,
            }
        except Exception as exc:
            logger.debug("[Vanguard] Failed to enrich audit event with risk state: %s", exc)
            return {}

    def _build_audit_event(self, **kwargs) -> AuditEvent:
        """Build a normalized audit event with principal/server/risk context."""
        event_kwargs: dict[str, Any] = {
            "session_id": self._session.session_id if self._session else "N/A",
            "principal_id": self.principal.principal_id if self.principal else None,
            "auth_type": self.principal.auth_type if self.principal else None,
            "server_id": self._server_id,
        }
        event_kwargs.update(self._current_risk_context())
        event_kwargs.update(kwargs)
        return AuditEvent(**event_kwargs)

    def _log_audit_event(self, **kwargs) -> None:
        self.audit.info(
            self._build_audit_event(**kwargs).to_log_line(format=self.config.audit_format)
        )

    # -----------------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------------

    async def run(self):
        """Start the proxy."""
        self._session = self.session_manager.create(principal=self.principal, server_id=self._server_id)
        logger.info(f"[Vanguard] Session {self._session.session_id} started (server={self._server_id})")
        self._check_server_integrity_baseline()
        self._load_capability_manifest_baseline()

        try:
            self._server_process = await asyncio.create_subprocess_exec(
                *self.server_command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (BlockingIOError, OSError) as e:
            if getattr(e, "errno", None) == 11:
                 logger.critical(f"[Vanguard] RESOURCE EXHAUSTION: Cannot spawn MCP server (Errno 11). System limits reached.")
                 raise RuntimeError("Server capacity reached (OS process limit). Please try again later.")
            logger.error(f"[Vanguard] Failed to launch server: {e}")
            raise RuntimeError(f"MCP Server command failed: {e}")
        except Exception as e:
            logger.error(f"[Vanguard] Unexpected error launching server: {e}")
            raise RuntimeError(f"MCP Server command failed: {e}")

        logger.info(f"[Vanguard] Server PID {self._server_process.pid} proxy active")

        try:
            # Run all pumps until the first one completes (usually agent_to_server closing)
            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(self._pump_agent_to_server()),
                    asyncio.create_task(self._pump_server_to_agent()),
                    asyncio.create_task(self._pump_server_stderr()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )
            # Cancel the remaining pumps
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        except Exception as e:
            logger.error(f"[Vanguard] Unexpected error in proxy loop: {e}")
        finally:
            current = asyncio.current_task()
            pending_cancels = current.cancelling() if current else 0
            if current and pending_cancels:
                for _ in range(pending_cancels):
                    current.uncancel()
            try:
                await self._shutdown()
            finally:
                if current and pending_cancels:
                    for _ in range(pending_cancels):
                        current.cancel()

    def _check_server_integrity_baseline(self) -> None:
        manifest_file = self.config.server_manifest_file
        if not manifest_file:
            return

        policy = self.config.server_manifest_policy
        current_manifest = server_integrity.build_server_manifest(
            self.server_command,
            hash_executable=self.config.server_manifest_hash_executable,
        )

        try:
            expected_manifest = server_integrity.load_server_manifest(manifest_file)
        except Exception as exc:
            message = f"Failed to load upstream server manifest '{manifest_file}': {exc}"
            self._record_server_integrity_event(
                action="BLOCK" if policy == "block" else "WARN",
                rule_id="VANGUARD-SERVER-MANIFEST-LOAD",
                reason=message,
            )
            if policy == "block":
                raise RuntimeError(message)
            logger.warning("[Vanguard] %s", message)
            return

        self._check_server_manifest_trust(expected_manifest, manifest_file)

        is_valid, impact, drift_labels = server_integrity.verify_server_sbom(current_manifest, expected_manifest)
        if is_valid:
            self._check_server_provenance(current_manifest)
            self._check_supplier_artifact_signature(current_manifest)
            self._check_server_sigstore_bundle(current_manifest)
            logger.info("[Vanguard] Upstream server manifest matched baseline.")
            return

        message = f"Upstream server drift detected before launch: {', '.join(drift_labels)}"
        action = "BLOCK" if policy == "block" else "WARN"
        
        # Record to risk engine
        if self._session:
            self.risk_engine.record_event(
                self._session.session_id, self._server_id, "SBOM_MISMATCH", 
                {"drifts": drift_labels, "impact": impact}
            )
        self._record_server_integrity_event(
            action=action,
            rule_id="VANGUARD-SERVER-DRIFT",
            reason=message,
        )

        if policy == "block":
            raise RuntimeError(message)

        logger.warning("[Vanguard] %s", message)

    def _record_server_integrity_event(self, *, action: str, rule_id: str, reason: str) -> None:
        self._log_audit_event(
            direction="system",
            method="server/verify",
            action=action,
            rule_id=rule_id,
            blocked_reason=reason,
        )

    def _check_server_manifest_trust(self, expected_manifest: dict[str, Any], manifest_file: str) -> None:
        policy = self.config.server_trust_policy
        if policy not in {"warn", "block"}:
            return

        issues: list[str] = []
        trusted_signers: dict[str, dict[str, str]] = {}
        signature_doc: Optional[dict[str, Any]] = None

        signature_path = self.config.server_manifest_signature_file or str(
            server_integrity.default_server_manifest_signature_path(manifest_file)
        )

        if os.path.exists(signature_path):
            try:
                signature_doc = server_integrity.load_server_manifest_signature(signature_path)
            except Exception as exc:
                issues.append(f"Failed to load upstream server manifest signature '{signature_path}': {exc}")
        else:
            signature_doc = None

        try:
            trusted_signers = server_integrity.load_trusted_server_signers()
        except Exception as exc:
            issues.append(f"Failed to load trusted upstream server signers: {exc}")

        issues.extend(
            server_integrity.evaluate_server_manifest_signature(
                expected_manifest,
                signature_doc=signature_doc,
                trusted_signers=trusted_signers,
                require_signature=True,
            )
        )
        issues.extend(server_integrity.evaluate_server_manifest_approval(expected_manifest))

        if not issues:
            logger.info("[Vanguard] Upstream server manifest signature and trust state verified.")
            return

        message = "; ".join(dict.fromkeys(issues))
        action = "BLOCK" if policy == "block" else "WARN"
        self._record_server_integrity_event(
            action=action,
            rule_id="VANGUARD-SERVER-TRUST",
            reason=message,
        )
        if policy == "block":
            raise RuntimeError(message)
        logger.warning("[Vanguard] %s", message)

    def _check_supplier_artifact_signature(self, current_manifest: dict[str, Any]) -> None:
        policy = self.config.server_artifact_policy
        if policy not in {"warn", "block"}:
            return

        issues: list[str] = []
        signature_doc: Optional[dict[str, Any]] = None
        trusted_signers: dict[str, dict[str, str]] = {}

        executable_path = ((current_manifest.get("executable") or {}).get("resolved_path"))
        signature_path = self.config.server_artifact_signature_file
        if not signature_path and executable_path:
            candidate = supplier_signatures.default_artifact_signature_path(executable_path)
            if candidate.exists():
                signature_path = str(candidate)

        if signature_path and os.path.exists(signature_path):
            try:
                signature_doc = supplier_signatures.load_artifact_signature(signature_path)
            except Exception as exc:
                issues.append(f"Failed to load supplier artifact signature '{signature_path}': {exc}")

        try:
            trusted_signers = supplier_signatures.load_trusted_supplier_signers()
        except Exception as exc:
            issues.append(f"Failed to load trusted supplier signers: {exc}")

        issues.extend(
            supplier_signatures.evaluate_artifact_signature(
                executable_path,
                signature_doc=signature_doc,
                trusted_signers=trusted_signers,
                require_signature=True,
                allowed_suppliers=set(self.config.allowed_supplier_ids) or None,
            )
        )

        if not issues:
            logger.info("[Vanguard] Supplier artifact signature verified successfully.")
            return

        message = "; ".join(dict.fromkeys(issues))
        action = "BLOCK" if policy == "block" else "WARN"
        self._record_server_integrity_event(
            action=action,
            rule_id="VANGUARD-SUPPLIER-SIGNATURE",
            reason=message,
        )
        if policy == "block":
            raise RuntimeError(message)
        logger.warning("[Vanguard] %s", message)

    def _check_server_sigstore_bundle(self, current_manifest: dict[str, Any]) -> None:
        policy = self.config.server_sigstore_policy
        if policy not in {"warn", "block"}:
            return

        issues: list[str] = []
        bundle_doc: Optional[dict[str, Any]] = None
        executable_path = ((current_manifest.get("executable") or {}).get("resolved_path"))

        bundle_path = self.config.server_sigstore_bundle_file
        if not bundle_path and executable_path:
            candidate = sigstore_bundle.default_sigstore_bundle_path(executable_path)
            if candidate.exists():
                bundle_path = str(candidate)

        if bundle_path and os.path.exists(bundle_path):
            try:
                bundle_doc = sigstore_bundle.load_sigstore_bundle(bundle_path)
            except Exception as exc:
                issues.append(f"Failed to load Sigstore bundle '{bundle_path}': {exc}")

        try:
            trusted_hint_signers = supplier_signatures.load_trusted_supplier_signers()
        except Exception as exc:
            trusted_hint_signers = {}
            issues.append(f"Failed to load trusted Sigstore hint signers: {exc}")

        try:
            allowed_fingerprints = sigstore_bundle.load_allowed_sigstore_cert_fingerprints(
                self.config.allowed_sigstore_cert_fingerprints
            )
        except Exception as exc:
            allowed_fingerprints = set()
            issues.append(f"Failed to load allowed Sigstore certificate fingerprints: {exc}")

        try:
            allowed_identities = sigstore_bundle.load_allowed_sigstore_identities(
                self.config.allowed_sigstore_identities
            )
        except Exception as exc:
            allowed_identities = set()
            issues.append(f"Failed to load allowed Sigstore certificate identities: {exc}")

        try:
            allowed_oidc_issuers = sigstore_bundle.load_allowed_sigstore_oidc_issuers(
                self.config.allowed_sigstore_oidc_issuers
            )
        except Exception as exc:
            allowed_oidc_issuers = set()
            issues.append(f"Failed to load allowed Sigstore OIDC issuers: {exc}")

        try:
            allowed_build_signer_uris = sigstore_bundle.load_allowed_sigstore_build_signer_uris(
                self.config.allowed_sigstore_build_signer_uris
            )
        except Exception as exc:
            allowed_build_signer_uris = set()
            issues.append(f"Failed to load allowed Sigstore build signer URIs: {exc}")

        try:
            allowed_source_repositories = sigstore_bundle.load_allowed_sigstore_source_repository_uris(
                self.config.allowed_sigstore_source_repositories
            )
        except Exception as exc:
            allowed_source_repositories = set()
            issues.append(f"Failed to load allowed Sigstore source repositories: {exc}")

        try:
            allowed_source_refs = sigstore_bundle.load_allowed_sigstore_source_repository_refs(
                self.config.allowed_sigstore_source_refs
            )
        except Exception as exc:
            allowed_source_refs = set()
            issues.append(f"Failed to load allowed Sigstore source refs: {exc}")

        try:
            allowed_source_digests = sigstore_bundle.load_allowed_sigstore_source_repository_digests(
                self.config.allowed_sigstore_source_digests
            )
        except Exception as exc:
            allowed_source_digests = set()
            issues.append(f"Failed to load allowed Sigstore source digests: {exc}")

        try:
            allowed_build_triggers = sigstore_bundle.load_allowed_sigstore_build_triggers(
                self.config.allowed_sigstore_build_triggers
            )
        except Exception as exc:
            allowed_build_triggers = set()
            issues.append(f"Failed to load allowed Sigstore build triggers: {exc}")

        try:
            allowed_tlog_key_ids = sigstore_bundle.load_allowed_sigstore_tlog_key_ids(
                self.config.allowed_sigstore_tlog_key_ids
            )
        except Exception as exc:
            allowed_tlog_key_ids = set()
            issues.append(f"Failed to load allowed Sigstore transparency log key ids: {exc}")

        try:
            allowed_github_repositories = sigstore_bundle.load_allowed_sigstore_github_repositories(
                self.config.allowed_sigstore_github_repositories
            )
        except Exception as exc:
            allowed_github_repositories = set()
            issues.append(f"Failed to load allowed Sigstore GitHub repositories: {exc}")

        try:
            allowed_github_refs = sigstore_bundle.load_allowed_sigstore_github_refs(
                self.config.allowed_sigstore_github_refs
            )
        except Exception as exc:
            allowed_github_refs = set()
            issues.append(f"Failed to load allowed Sigstore GitHub refs: {exc}")

        try:
            allowed_github_shas = sigstore_bundle.load_allowed_sigstore_github_shas(
                self.config.allowed_sigstore_github_shas
            )
        except Exception as exc:
            allowed_github_shas = set()
            issues.append(f"Failed to load allowed Sigstore GitHub SHAs: {exc}")

        try:
            allowed_github_triggers = sigstore_bundle.load_allowed_sigstore_github_triggers(
                self.config.allowed_sigstore_github_triggers
            )
        except Exception as exc:
            allowed_github_triggers = set()
            issues.append(f"Failed to load allowed Sigstore GitHub triggers: {exc}")

        try:
            allowed_github_workflow_names = sigstore_bundle.load_allowed_sigstore_github_workflow_names(
                self.config.allowed_sigstore_github_workflow_names
            )
        except Exception as exc:
            allowed_github_workflow_names = set()
            issues.append(f"Failed to load allowed Sigstore GitHub workflow names: {exc}")

        issues.extend(
            sigstore_bundle.evaluate_sigstore_bundle(
                executable_path,
                bundle_doc=bundle_doc,
                trusted_hint_signers=trusted_hint_signers,
                require_bundle=True,
                allowed_cert_fingerprints=allowed_fingerprints or None,
                allowed_identities=allowed_identities or None,
                allowed_oidc_issuers=allowed_oidc_issuers or None,
                allowed_build_signer_uris=allowed_build_signer_uris or None,
                allowed_source_repository_uris=allowed_source_repositories or None,
                allowed_source_repository_refs=allowed_source_refs or None,
                allowed_source_repository_digests=allowed_source_digests or None,
                allowed_build_triggers=allowed_build_triggers or None,
                allowed_tlog_key_ids=allowed_tlog_key_ids or None,
                allowed_github_repositories=allowed_github_repositories or None,
                allowed_github_refs=allowed_github_refs or None,
                allowed_github_shas=allowed_github_shas or None,
                allowed_github_triggers=allowed_github_triggers or None,
                allowed_github_workflow_names=allowed_github_workflow_names or None,
                tlog_policy=self.config.sigstore_tlog_policy,
            )
        )

        if not issues:
            logger.info("[Vanguard] Sigstore bundle verified successfully.")
            return

        message = "; ".join(dict.fromkeys(issues))
        action = "BLOCK" if policy == "block" else "WARN"
        self._record_server_integrity_event(
            action=action,
            rule_id="VANGUARD-SIGSTORE-BUNDLE",
            reason=message,
        )
        if policy == "block":
            raise RuntimeError(message)
        logger.warning("[Vanguard] %s", message)

    def _check_server_provenance(self, current_manifest: dict[str, Any]) -> None:
        policy = self.config.server_provenance_policy
        provenance_file = self.config.server_provenance_file
        if policy not in {"warn", "block"} or not provenance_file:
            return

        issues: list[str] = []
        provenance_doc: Optional[dict[str, Any]] = None
        signature_doc: Optional[dict[str, Any]] = None
        trusted_signers: dict[str, dict[str, str]] = {}

        try:
            provenance_doc = provenance.load_provenance(provenance_file)
        except Exception as exc:
            issues.append(f"Failed to load upstream provenance '{provenance_file}': {exc}")

        signature_path = self.config.server_provenance_signature_file or str(
            provenance.default_provenance_signature_path(provenance_file)
        )
        if os.path.exists(signature_path):
            try:
                signature_doc = provenance.load_provenance_signature(signature_path)
            except Exception as exc:
                issues.append(f"Failed to load upstream provenance signature '{signature_path}': {exc}")
        else:
            signature_doc = None

        try:
            trusted_signers = provenance.load_trusted_provenance_signers()
        except Exception as exc:
            issues.append(f"Failed to load trusted provenance signers: {exc}")

        if provenance_doc is not None:
            issues.extend(
                provenance.evaluate_provenance_signature(
                    provenance_doc,
                    signature_doc=signature_doc,
                    trusted_signers=trusted_signers,
                    require_signature=True,
                )
            )
            issues.extend(
                provenance.evaluate_provenance_for_server_manifest(
                    current_manifest,
                    provenance_doc,
                    required_builder_ids=set(self.config.required_provenance_builders) or None,
                )
            )

        if not issues:
            logger.info("[Vanguard] Upstream provenance verified successfully.")
            return

        message = "; ".join(dict.fromkeys(issues))
        action = "BLOCK" if policy == "block" else "WARN"
        self._record_server_integrity_event(
            action=action,
            rule_id="VANGUARD-PROVENANCE",
            reason=message,
        )
        if policy == "block":
            raise RuntimeError(message)
        logger.warning("[Vanguard] %s", message)

    def _load_capability_manifest_baseline(self) -> None:
        manifest_file = self.config.capability_manifest_file
        if not manifest_file:
            return

        try:
            self._expected_capability_manifest = capability_fingerprint.load_capability_manifest(manifest_file)
        except Exception as exc:
            message = f"Failed to load capability manifest '{manifest_file}': {exc}"
            self._record_server_integrity_event(
                action="BLOCK" if self.config.capability_manifest_policy == "block" else "WARN",
                rule_id="VANGUARD-CAPABILITY-MANIFEST-LOAD",
                reason=message,
            )
            if self.config.capability_manifest_policy == "block":
                raise RuntimeError(message)
            logger.warning("[Vanguard] %s", message)
            return

        policy = self.config.capability_trust_policy
        if policy not in {"warn", "block"}:
            return

        issues: list[str] = []
        signature_doc: Optional[dict[str, Any]] = None
        signature_path = self.config.capability_manifest_signature_file or str(
            capability_fingerprint.default_capability_manifest_signature_path(manifest_file)
        )

        if os.path.exists(signature_path):
            try:
                signature_doc = capability_fingerprint.load_capability_manifest_signature(signature_path)
            except Exception as exc:
                issues.append(f"Failed to load capability manifest signature '{signature_path}': {exc}")

        try:
            trusted_signers = capability_fingerprint.load_trusted_capability_signers()
        except Exception as exc:
            trusted_signers = {}
            issues.append(f"Failed to load trusted capability signers: {exc}")

        issues.extend(
            capability_fingerprint.evaluate_capability_manifest_signature(
                self._expected_capability_manifest,
                signature_doc=signature_doc,
                trusted_signers=trusted_signers,
                require_signature=True,
            )
        )

        if not issues:
            logger.info("[Vanguard] Capability manifest signature verified successfully.")
            return

        message = "; ".join(dict.fromkeys(issues))
        self._record_server_integrity_event(
            action="BLOCK" if policy == "block" else "WARN",
            rule_id="VANGUARD-CAPABILITY-MANIFEST-SIGNATURE",
            reason=message,
        )
        if policy == "block":
            raise RuntimeError(message)
        logger.warning("[Vanguard] %s", message)

    def _observe_capability_section(self, section: str, payload: dict[str, Any]) -> None:
        try:
            if section == "initialize":
                self._observed_capability_manifest["initialize"] = capability_fingerprint.fingerprint_initialize_payload(payload)
            elif section == "tools":
                self._observed_capability_manifest["tools"] = capability_fingerprint.fingerprint_tools_payload(payload)
        except Exception as exc:
            logger.warning("[Vanguard] Failed to fingerprint %s response: %s", section, exc)

    def _capability_policy_action(self, section: Optional[str]) -> tuple[Optional[str], Optional[str]]:
        if not section or not self._expected_capability_manifest:
            return None, None

        normalized_section = "tools" if section == "tools/list" else section

        # Phase 7: Use verify_attestation for risk scoring
        res = capability_fingerprint.verify_attestation(
            self._observed_capability_manifest,
            self._expected_capability_manifest
        )
        
        if res.is_valid:
            return None, None

        # Filter drifts for the current section to avoid redundant alerts
        section_drifts = [d for d in res.drifts if d.section == normalized_section]
        if not section_drifts:
            return None, None

        drift_labels = [f"{d.feature or ''} ({d.drift_type})" for d in section_drifts]
        message = f"Upstream capability drift detected in {normalized_section}: {', '.join(drift_labels)}"
        action = "BLOCK" if self.config.capability_manifest_policy == "block" else "WARN"
        
        # Record to risk engine
        if self._session:
            self.risk_engine.record_event(
                self._session.session_id, self._server_id, "ATTESTATION_DRIFT", 
                {"section": normalized_section, "drifts": drift_labels}
            )

        if action == "WARN":
            logger.warning("[Vanguard] %s", message)
        return action, message

    # -----------------------------------------------------------------------
    # Agent → Server pump
    # -----------------------------------------------------------------------

    async def _pump_agent_to_server(self):
        loop = asyncio.get_event_loop()

        while True:
            try:
                if self.agent_reader:
                    line = await self.agent_reader.readline()
                else:
                    line = await loop.run_in_executor(None, sys.stdin.buffer.readline)
            except Exception:
                break

            if not line:
                break

            if isinstance(line, bytes):
                line = line.decode("utf-8", errors="replace")
            
            line = line.strip()
            if not line:
                continue

            # ─── Phase 7: Risk Engine Enforcement Check ───
            if self._session:
                enforcement = self.risk_engine.get_enforcement(self._session.session_id, self._server_id)
                if enforcement == EnforcementLevel.BLOCK:
                    logger.critical(f"[Vanguard] [FAIL-CLOSED] Risk Engine terminated session {self._session.session_id} due to low trust score.")
                    break
                elif enforcement == EnforcementLevel.DEGRADE:
                    # Force Semantic Scanning and moderate throttling for degraded sessions
                    if not self.config.semantic_enabled:
                        logger.warning(f"[Vanguard] DEGRADED MODE: Forcing semantic scanning for session {self._session.session_id}")
                    self.config.semantic_enabled = True
                    # Small delay to simulate throttling on request side too
                    await asyncio.sleep(0.05)

            t_start = time.monotonic()

            try:
                raw_message = json.loads(line)
            except json.JSONDecodeError:
                continue

            method = raw_message.get("method", "")
            request_id = raw_message.get("id")
            tool_name = None
            if method == "tools/call":
                tool_name = raw_message.get("params", {}).get("name")

            # 0. OAuth 2.1 Scope Enforcement (RFC 6750)
            if method == "tools/call" and tool_name:
                required_scope = None
                
                if tool_name in TOOL_SCOPE_MAPPING:
                    required_scope = TOOL_SCOPE_MAPPING[tool_name]
                else:
                    for prefix, scope in TOOL_SCOPE_MAPPING.items():
                        if prefix.endswith("_") and tool_name.startswith(prefix):
                            required_scope = scope
                            break
                
                if required_scope and self.principal:
                    granted_scopes = self.principal.attributes.get("token_scope", [])
                    if required_scope not in granted_scopes:
                        logger.warning(f"[Vanguard] INSUFFICIENT_SCOPE: tool {tool_name} requires {required_scope}")
                        self._stats["blocked"] += 1
                        telemetry.metrics.record_status("blocked")
                        self._log_audit_event(
                            direction="agent→server",
                            method=method,
                            tool_name=tool_name,
                            action="BLOCK",
                            rule_id="VANGUARD-AUTH-SCOPE",
                            blocked_reason=f"Insufficient scope. Tool requires {required_scope}.",
                        )
                        block_response = make_block_response(
                            request_id=request_id,
                            reason=f"Insufficient scope. Your token must include the '{required_scope}' scope to use this tool.",
                            rule_id="VANGUARD-AUTH-SCOPE",
                        )
                        if "error" in block_response and "data" in block_response["error"]:
                            block_response["error"]["data"]["oauth_error"] = "insufficient_scope"
                            block_response["error"]["data"]["required_scope"] = required_scope
                            block_response["error"]["data"]["granted_scopes"] = granted_scopes
                        await self._write_to_agent(json.dumps(block_response))
                        continue

            # 1. Handle native Vanguard tools
            if method == "tools/call" and tool_name and tool_name.startswith("vanguard_"):
                self._stats["total"] += 1
                if self._session:
                    self._session.record_call(
                        tool_name=tool_name,
                        method=method,
                        params=raw_message.get("params", {}),
                        action="ALLOW" if self.config.management_tools_enabled else "BLOCK",
                    )

                if not self.config.management_tools_enabled:
                    telemetry.metrics.record_status("blocked")
                    self._stats["blocked"] += 1
                    self._log_audit_event(
                        direction="agent→server",
                        method=method,
                        tool_name=tool_name,
                        action="BLOCK",
                        rule_id="VANGUARD-MGMT-DISABLED",
                        blocked_reason="Management tools are disabled on this McpVanguard instance.",
                    )
                    block_response = make_block_response(
                        request_id=request_id,
                        reason="Management tools are disabled on this McpVanguard instance.",
                        rule_id="VANGUARD-MGMT-DISABLED",
                    )
                    await self._write_to_agent(json.dumps(block_response))
                    continue

                telemetry.metrics.record_status("allowed")
                self._stats["allowed"] += 1
                self._log_audit_event(
                    direction="agent→server",
                    method=method,
                    tool_name=tool_name,
                    action="ALLOW",
                )
                args = raw_message.get("params", {}).get("arguments", {})
                vanguard_result = await management.handle_vanguard_tool(
                    tool_name,
                    args,
                    context=management.ManagementContext(
                        session_id=self._session.session_id if self._session else None,
                        log_file=self.config.log_file,
                        rules_engine=self.rules_engine,
                    ),
                )
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": vanguard_result
                }
                await self._write_to_agent(json.dumps(response))
                continue

            # 2. Track tool listing requests for enrichment
            if method == "tools/list" and request_id:
                self._pending_tool_lists.add(request_id)
            elif method == "initialize" and request_id:
                self._pending_initializations.add(request_id)

            # Normalize the message before inspection to prevent encoding bypasses
            try:
                normalized_message = self._normalize_message(raw_message)
            except ValueError as e:
                # MED-2 Fix: Reject oversized messages instead of truncating and allowing bypass
                logger.warning(f"[Vanguard] REJECTED: Message contains oversized field: {e}")
                block_response = make_block_response(
                    request_id=request_id,
                    reason=f"Security Policy: Message contains a field exceeding the {self.config.max_string_len} byte limit.",
                    rule_id="VANGUARD-SIZE-001",
                )
                await self._write_to_agent(json.dumps(block_response))
                continue

            # Inspect the message (with 5s Fail-Closed timeout)
            try:
                result = await asyncio.wait_for(
                    self._inspect_message(normalized_message), timeout=5.0
                )
            except asyncio.TimeoutError:
                logger.error(f"[Vanguard] Inspection TIMEOUT (Fail-Closed) for {method}")
                result = InspectionResult.block(
                    reason="Security inspection timeout (Fail-Closed policy).",
                    layer=2,
                )
            latency_ms = (time.monotonic() - t_start) * 1000
            telemetry.metrics.record_latency("TOTAL", latency_ms)
            result_rule_id = result.rule_matches[0].rule_id if result.rule_matches else "VANGUARD"

            # Record into risk engine (Phase 7)
            if self._session:
                if result.action == "BLOCK":
                    etype = "RULE_BLOCK" if result.layer_triggered == 1 else "BEHAVIORAL_BLOCK"
                    self.risk_engine.record_event(
                        self._session.session_id,
                        self._server_id,
                        etype,
                        {"rule": result_rule_id},
                    )
                elif result.action == "WARN":
                    etype = "RULE_WARN" if result.layer_triggered == 1 else "BEHAVIORAL_WARN"
                    self.risk_engine.record_event(
                        self._session.session_id,
                        self._server_id,
                        etype,
                        {"rule": result_rule_id},
                    )

            # Record into session state
            self._stats["total"] += 1
            if self._session:
                self._session.record_call(
                    tool_name=tool_name or method,
                    method=method,
                    params=raw_message.get("params", {}),
                    action=result.action,
                )

            # Audit logging
            is_audit = (self.config.mode == "audit")
            effective_action = result.action
            if not result.allowed and is_audit:
                effective_action = "SHADOW-BLOCK"

            self._log_audit_event(
                direction="agent→server",
                method=method,
                tool_name=tool_name,
                action=effective_action,
                layer_triggered=result.layer_triggered,
                rule_id=result.rule_matches[0].rule_id if result.rule_matches else None,
                semantic_score=result.semantic_score,
                latency_ms=round(latency_ms, 2),
                blocked_reason=result.block_reason,
            )

            is_audit = (self.config.mode == "audit")

            if result.allowed or is_audit:
                if not result.allowed:
                    logger.info(f"[Vanguard] [SHADOW-BLOCK] Audit mode allowing violation: {tool_name or method}")
                    self._stats["shadow_blocked"] = self._stats.get("shadow_blocked", 0) + 1

                self._stats["allowed"] += 1
                telemetry.metrics.record_status("allowed")
                if result.action == "WARN":
                    self._stats["warned"] += 1
                    telemetry.metrics.record_status("warned")
                # Forward the normalized message to ensure inspection/execution symmetry
                # This prevents truncation-based bypasses (P2 Audit Finding)
                forward_data = json.dumps(normalized_message)
                await self._write_to_server(forward_data)
            else:
                self._stats["blocked"] += 1
                telemetry.metrics.record_status("blocked")
                rule_id = result_rule_id

                if self._session:
                    submit_blocked_call(raw_message, session_id=self._session.session_id)

                # Sanitize response: only expose detail if explicitly opted-in
                if self.config.expose_block_reason:
                    agent_reason = result.block_reason or "Security policy violation"
                else:
                    agent_reason = "Request blocked by McpVanguard security policy."

                block_response = make_block_response(
                    request_id=request_id,
                    reason=agent_reason,
                    rule_id=rule_id,
                )
                logger.info(f"[Vanguard] BLOCKED {method} {tool_name or ''}")
                await self._write_to_agent(json.dumps(block_response))

    # -----------------------------------------------------------------------
    # Server → Agent pump
    # -----------------------------------------------------------------------

    async def _pump_server_to_agent(self):
        while True:
            try:
                line = await self._server_process.stdout.readline()
            except Exception:
                break

            if not line:
                break

            throttle_delay = 0.0
            if self.config.behavioral_enabled and self._session:
                try:
                    line_str = line.decode("utf-8", errors="replace")
                    resp_result = await behavioral.inspect_response(
                        self._session.session_id, line_str, self._server_id
                    )
                    
                    if resp_result and not resp_result.allowed:
                        logger.warning(f"[Vanguard] Blocking large response: {resp_result.block_reason}")
                        request_id = None
                        try:
                            request_id = json.loads(line_str).get("id")
                        except json.JSONDecodeError:
                            pass

                        if self.config.expose_block_reason:
                            agent_reason = resp_result.block_reason or "Response blocked by security policy."
                        else:
                            agent_reason = "Response blocked by McpVanguard security policy."

                        rule_id = resp_result.rule_matches[0].rule_id if resp_result.rule_matches else "VANGUARD-RESP"
                        block_response = make_block_response(
                            request_id=request_id,
                            reason=agent_reason,
                            rule_id=rule_id,
                        )
                        self._stats["blocked"] += 1
                        telemetry.metrics.record_status("blocked")
                        await self._write_to_agent(json.dumps(block_response))
                        continue
                        
                    # Requirement 3.1: Apply 1 byte/sec throttle if governor is empty
                    state = behavioral.get_state(self._session.session_id, self._server_id)
                    
                    # Periodic check: can we clear the throttle? (P2 Audit Finding)
                    state.update_throttle_status()

                    if state.is_throttled:
                        # Preserve JSON-RPC framing by delaying the full frame instead
                        # of fragmenting one message into multiple newline-delimited chunks.
                        total_len = len(line)
                        throttle_delay = max(0.0, (total_len - 1024) / 1024.0)
                except Exception as e:
                    logger.error(f"[Vanguard] Error in behavioral response inspection: {e}")

            # 3. Enrich tool listing responses with safety hints
            try:
                line_str = line.decode("utf-8", errors="replace")
                resp_json = json.loads(line_str)
                resp_id = resp_json.get("id")
                metadata_result = None
                response_method = None
                response_changed = False

                if resp_id in self._pending_initializations:
                    response_method = "initialize"
                    self._pending_initializations.remove(resp_id)
                    self._observe_capability_section("initialize", resp_json)
                    if self.config.metadata_inspection_enabled:
                        metadata_result = metadata_inspection.inspect_initialize_payload(resp_json)

                if resp_id in self._pending_tool_lists:
                    response_method = "tools/list"
                    self._pending_tool_lists.remove(resp_id)
                    if "result" in resp_json and "tools" in resp_json["result"]:
                        enriched_tools = self._enrich_tool_list(resp_json["result"]["tools"])
                        if self.config.metadata_inspection_enabled and self.config.metadata_policy == "drop-tool":
                            safe_tools, dropped_tools = metadata_inspection.filter_poisoned_tools(enriched_tools)
                            if dropped_tools:
                                resp_json["result"]["tools"] = safe_tools
                                response_changed = True
                                self._stats["warned"] += 1
                                telemetry.metrics.record_status("warned")
                                for dropped_tool, drop_result in dropped_tools:
                                    rule_id = drop_result.rule_matches[0].rule_id if drop_result.rule_matches else "VANGUARD-META"
                                    self._log_audit_event(
                                        direction="server→agent",
                                        method="tools/list",
                                        tool_name=dropped_tool.get("name"),
                                        action="WARN",
                                        layer_triggered=drop_result.layer_triggered,
                                        rule_id=rule_id,
                                        blocked_reason=f"Dropped poisoned tool metadata for '{dropped_tool.get('name', 'unknown')}'.",
                                    )
                        else:
                            resp_json["result"]["tools"] = enriched_tools
                            response_changed = True
                            if self.config.metadata_inspection_enabled:
                                metadata_result = metadata_inspection.inspect_tool_list_payload(resp_json)
                        self._observe_capability_section("tools", resp_json)

                metadata_action = self._metadata_policy_action(metadata_result)
                capability_action, capability_reason = self._capability_policy_action(response_method)
                if metadata_result and metadata_action:
                    rule_id = metadata_result.rule_matches[0].rule_id if metadata_result.rule_matches else "VANGUARD-META"
                    self._log_audit_event(
                        direction="server→agent",
                        method=response_method,
                        action=metadata_action,
                        layer_triggered=metadata_result.layer_triggered,
                        rule_id=rule_id,
                        blocked_reason=metadata_result.block_reason,
                    )

                    if metadata_action == "WARN":
                        self._stats["warned"] += 1
                        telemetry.metrics.record_status("warned")
                    else:
                        self._stats["blocked"] += 1
                        telemetry.metrics.record_status("blocked")
                        block_response = make_block_response(
                            request_id=resp_id,
                            reason="Server metadata blocked by McpVanguard security policy.",
                            rule_id=rule_id,
                        )
                        await self._write_to_agent(json.dumps(block_response))
                        continue

                if capability_action:
                    self._log_audit_event(
                        direction="server→agent",
                        method=response_method,
                        action=capability_action,
                        rule_id="VANGUARD-CAPABILITY-DRIFT",
                        blocked_reason=capability_reason,
                    )

                    if capability_action == "WARN":
                        self._stats["warned"] += 1
                        telemetry.metrics.record_status("warned")
                    else:
                        self._stats["blocked"] += 1
                        telemetry.metrics.record_status("blocked")
                        block_response = make_block_response(
                            request_id=resp_id,
                            reason=capability_reason or "Upstream capability drift detected.",
                            rule_id="VANGUARD-CAPABILITY-DRIFT",
                        )
                        await self._write_to_agent(json.dumps(block_response))
                        continue

                if response_changed:
                    line = json.dumps(resp_json).encode("utf-8")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

            if throttle_delay > 0:
                await asyncio.sleep(throttle_delay)

            await self._write_to_agent(line)

    def _enrich_tool_list(self, tools: list[dict]) -> list[dict]:
        """Inject Vanguard management tools and apply safety hints/titles."""
        all_tools = list(tools)
        if self.config.management_tools_enabled:
            all_tools.extend(management.get_vanguard_tools())
        
        # Keywords for inference
        READ_PREFIXES = ("get_", "list_", "read_", "check_", "fetch_", "search_", "inspect_", "query_", "audit_")
        WRITE_PREFIXES = ("delete_", "remove_", "update_", "set_", "write_", "enforce_", "block_", "reset_", "clear_", "apply_", "push_", "exec_", "shell_")

        for t in all_tools:
            name = t.get("name", "")
            
            # Inject Title if missing
            if "title" not in t:
                t["title"] = name.replace("_", " ").title()

            # Inject Safety Hints
            if "readOnlyHint" not in t and "destructiveHint" not in t:
                if any(name.startswith(p) for p in READ_PREFIXES) or "status" in name:
                    t["readOnlyHint"] = True
                elif any(name.startswith(p) for p in WRITE_PREFIXES):
                    t["destructiveHint"] = True
                else:
                    # Default: label as conservative if ambiguous but mostly tool-like
                    t["readOnlyHint"] = True
            
        return all_tools

    def _metadata_policy_action(self, result: Optional[InspectionResult]) -> Optional[str]:
        if not result or result.allowed:
            return None

        policy = self.config.metadata_policy
        if policy == "warn":
            return "WARN"
        if policy == "drop-tool":
            return "BLOCK"

        # Default to blocking for unknown values to avoid silently weakening policy.
        return "BLOCK"

    async def _pump_server_stderr(self):
        while True:
            try:
                line = await self._server_process.stderr.readline()
            except Exception:
                break
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    # -----------------------------------------------------------------------
    # Inspection pipeline
    # -----------------------------------------------------------------------

    async def _inspect_message(self, message: dict) -> InspectionResult:
        auth_result = self._inspect_auth_policy(message)
        if auth_result:
            return auth_result

        t_start = time.monotonic()
        result = self.rules_engine.check(message)
        telemetry.metrics.record_latency("L1", (time.monotonic() - t_start) * 1000)

        if not result.allowed:
            return result

        # Parallel L2/L3 execution to minimize latency
        beh_task = None
        if self.config.behavioral_enabled and self._session:
            beh_task = asyncio.create_task(behavioral.inspect_request(
                self._session.session_id, message, self._server_id
            ))

        sem_task = None
        if self.config.semantic_enabled:
            from dataclasses import replace
            settings = semantic._get_settings()
            settings = replace(settings, enabled=self.config.semantic_enabled)
            sem_task = asyncio.create_task(semantic.score_intent(message, settings=settings))

        if beh_task:
            t_start_l3 = time.monotonic()
            beh_result = await beh_task
            telemetry.metrics.record_latency("L3", (time.monotonic() - t_start_l3) * 1000)
            if beh_result:
                if not beh_result.allowed:
                    return beh_result
                if beh_result.action == "WARN":
                    result.action = "WARN"
                    result.rule_matches.extend(beh_result.rule_matches)

        if sem_task:
            t_start_l2 = time.monotonic()
            sem_result = await sem_task
            telemetry.metrics.record_latency("L2", (time.monotonic() - t_start_l2) * 1000)
            if sem_result:
                if not sem_result.allowed:
                    return sem_result
                result.semantic_score = sem_result.semantic_score
                if sem_result.action == "WARN":
                    result.action = "WARN"
                    result.rule_matches.extend(sem_result.rule_matches)

        return result

    def _inspect_auth_policy(self, message: dict) -> Optional[InspectionResult]:
        if message.get("method") != "tools/call":
            return None

        params = message.get("params") or {}
        if not isinstance(params, dict):
            return None

        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            return None

        if not self._is_destructive_tool_name(tool_name):
            return None

        principal = self.principal
        warning_policy = self._normalize_auth_policy(self.config.auth_warning_tool_policy)
        destructive_policy = self._normalize_auth_policy(self.config.destructive_tool_auth_policy)

        if self.config.required_destructive_roles or self.config.required_destructive_scopes:
            if not self._principal_satisfies_destructive_requirements(principal):
                requirements = []
                if self.config.required_destructive_roles:
                    requirements.append(f"roles={self.config.required_destructive_roles}")
                if self.config.required_destructive_scopes:
                    requirements.append(f"scopes={self.config.required_destructive_scopes}")
                reason = (
                    f"Destructive tool '{tool_name}' requires an authenticated principal with "
                    + " or ".join(requirements)
                    + "."
                )
                return self._auth_policy_result(
                    action=destructive_policy,
                    reason=reason,
                    rule_id="VANGUARD-AUTH-ROLE-001",
                )

        auth_warnings = self._principal_auth_warnings(principal)
        if auth_warnings:
            reason = (
                f"Destructive tool '{tool_name}' is being called by a principal with auth warnings: "
                + "; ".join(auth_warnings)
            )
            return self._auth_policy_result(
                action=warning_policy,
                reason=reason,
                rule_id="VANGUARD-AUTH-WARNING-001",
            )

        return None

    def _auth_policy_result(self, *, action: str, reason: str, rule_id: str) -> InspectionResult:
        match = RuleMatch(
            rule_id=rule_id,
            rule_name="Auth-aware tool policy",
            severity="HIGH" if action == "BLOCK" else "MEDIUM",
            action=action,
            message=reason,
        )
        if action == "BLOCK":
            return InspectionResult.block(reason=reason, layer=0, rule_matches=[match])
        return InspectionResult.warn(reason=reason, layer=0, rule_matches=[match])

    @staticmethod
    def _normalize_auth_policy(policy: str) -> str:
        return "BLOCK" if str(policy).lower() == "block" else "WARN"

    @staticmethod
    def _is_destructive_tool_name(tool_name: str) -> bool:
        destructive_prefixes = (
            "delete_",
            "remove_",
            "update_",
            "set_",
            "write_",
            "enforce_",
            "block_",
            "reset_",
            "clear_",
            "apply_",
            "push_",
            "exec_",
            "shell_",
        )
        return any(tool_name.startswith(prefix) for prefix in destructive_prefixes)

    @staticmethod
    def _principal_auth_warnings(principal: Optional[AuthPrincipal]) -> list[str]:
        if not principal:
            return []
        raw = principal.attributes.get("auth_warnings")
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, str)]
        return []

    def _principal_satisfies_destructive_requirements(self, principal: Optional[AuthPrincipal]) -> bool:
        if not principal:
            return False

        principal_roles = {role for role in principal.roles if isinstance(role, str)}
        principal_scopes = set(self._principal_token_scopes(principal))

        if self.config.required_destructive_roles and principal_roles.intersection(self.config.required_destructive_roles):
            return True
        if self.config.required_destructive_scopes and principal_scopes.intersection(self.config.required_destructive_scopes):
            return True
        return False

    @staticmethod
    def _principal_token_scopes(principal: Optional[AuthPrincipal]) -> list[str]:
        if not principal:
            return []
        raw = principal.attributes.get("token_scope")
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, str)]
        return []

    def _normalize_message(self, message: Any) -> Any:
        """
        Recursively URL-decodes and Unicode-normalizes (NFKC) all string values
        in a message to prevent encoding-based rule bypasses.
        Loops URL decode until the value stabilizes to handle double/triple encoding.
        """
        if isinstance(message, dict):
            return {k: self._normalize_message(v) for k, v in message.items()}
        elif isinstance(message, list):
            return [self._normalize_message(v) for v in message]
        elif isinstance(message, str):
            # 1. Loop URL decode until stable (handles %252F triple encoding etc.)
            value = message
            for _ in range(20):  # max 20 passes prevents deep-nested exfiltration
                decoded = urllib.parse.unquote(value)
                decoded = decoded.replace("%5c", "\\").replace("%5C", "\\")
                if decoded == value:
                    break
                value = decoded
            # 2. Unicode NFKC (Handles lookalikes where possible)
            value = unicodedata.normalize("NFKC", value)
            # 3. Strip zero-width / invisible characters
            value = ''.join(
                ch for ch in value
                if unicodedata.category(ch) not in ('Cf',)
            )
            # 4. Length safeguard (prevents memory/CPU exhaustion)
            # MED-2 Fix: Raise error on oversize instead of truncating to prevent bypass
            if len(value) > self.config.max_string_len:
                raise ValueError(f"String length {len(value)} exceeds limit {self.config.max_string_len}")
            
            return value
        elif isinstance(message, float):
            # 5. Reject NaN and Infinity to prevent downstream crashes/bypasses
            if math.isnan(message) or math.isinf(message):
                raise ValueError("NaN/Infinity values are not permitted in McpVanguard messages.")
        return message

    # -----------------------------------------------------------------------
    # I/O helpers
    # -----------------------------------------------------------------------

    async def _write_to_server(self, data: str | bytes):
        if not self._server_process or not self._server_process.stdin:
            return
        try:
            # Removed .strip() to prevent unintended payload mutation (P3 Audit Finding)
            if isinstance(data, str):
                buf = (data if data.endswith("\n") else data + "\n").encode()
            else:
                buf = data if data.endswith(b"\n") else data + b"\n"
            
            self._server_process.stdin.write(buf)
            await self._server_process.stdin.drain()
        except Exception as e:
            # MED-1 Fix: Log swallowed errors
            logger.error(f"[Vanguard] Error writing to server: {e}")

    async def _write_to_agent(self, data: str | bytes):
        try:
            # Preserve original whitespace for agent transport
            if isinstance(data, str):
                buf = (data if data.endswith("\n") else data + "\n").encode("utf-8")
            else:
                buf = data if data.endswith(b"\n") else data + b"\n"

            if self.agent_writer:
                self.agent_writer.write(buf)
                await self.agent_writer.drain()
            else:
                sys.stdout.buffer.write(buf)
                sys.stdout.buffer.flush()
        except Exception as e:
            # MED-1 Fix: Log swallowed errors
            logger.error(f"[Vanguard] Error writing to agent: {e}")

    # -----------------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------------

    async def _shutdown(self):
        if self._server_process:
            process = self._server_process
            try:
                if process.stdin:
                    try:
                        process.stdin.close()
                        await asyncio.wait_for(process.stdin.wait_closed(), timeout=0.5)
                    except Exception:
                        pass

                if process.returncode is None:
                    if sys.platform == "win32":
                        process.kill()
                    else:
                        process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        process.kill()
                        await asyncio.wait_for(process.wait(), timeout=2.0)
                else:
                    try:
                        await asyncio.wait_for(process.wait(), timeout=0.5)
                    except Exception:
                        pass
            except Exception:
                pass
            finally:
                transport = getattr(process, "_transport", None)
                if transport is not None:
                    try:
                        transport.close()
                    except Exception:
                        pass
                self._server_process = None

    async def get_stats(self):
        return self._stats


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_proxy(server_command: list[str], config: Optional[ProxyConfig] = None):
    for fd in (0, 1, 2):
        try:
            os.fstat(fd)
        except OSError:
            os.open(os.devnull, os.O_RDWR)

    if HAS_UVLOOP:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    proxy = VanguardProxy(server_command=server_command, config=config)

    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        pass
