"""
ProvnCloud integration scaffolding for McpVanguard.

- RemoteSettingsProvider fetches startup settings from /api/mcp/settings
- ProvnCloudEventReporter batches audit events to /api/mcp/events
- Config persistence lives at ~/.config/mcp-vanguard/provncloud.json
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import uuid

import httpx

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".config" / "mcp-vanguard"
CONFIG_FILE = CONFIG_DIR / "provncloud.json"

DEFAULT_BATCH_SIZE = 10
DEFAULT_FLUSH_INTERVAL_SEC = 5.0
DEFAULT_TIMEOUT = 30.0


@dataclass
class ProvnCloudConfig:
    tenant_id: str = ""
    service_token: str = ""
    bootstrap_url: str = ""
    config_url: str = ""
    events_url: str = ""
    rules_manifest_url: str = ""
    dashboard_url: str = ""
    hmac_key: str = ""
    capabilities: dict[str, bool] = field(default_factory=dict)

    @classmethod
    def from_bootstrap(cls, data: dict[str, Any]) -> "ProvnCloudConfig":
        config_url = data.get("config_url", "")
        return cls(
            tenant_id=data.get("tenant_id", ""),
            bootstrap_url=config_url.replace("/settings", "/bootstrap"),
            config_url=config_url,
            events_url=data.get("events_url", ""),
            rules_manifest_url=data.get("rules_manifest_url", ""),
            dashboard_url=data.get("dashboard_url", ""),
            capabilities=data.get("capabilities", {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "service_token": self.service_token,
            "bootstrap_url": self.bootstrap_url,
            "config_url": self.config_url,
            "events_url": self.events_url,
            "rules_manifest_url": self.rules_manifest_url,
            "dashboard_url": self.dashboard_url,
            "hmac_key": self.hmac_key,
            "capabilities": self.capabilities,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProvnCloudConfig":
        return cls(
            tenant_id=data.get("tenant_id", ""),
            service_token=data.get("service_token", ""),
            bootstrap_url=data.get("bootstrap_url", ""),
            config_url=data.get("config_url", ""),
            events_url=data.get("events_url", ""),
            rules_manifest_url=data.get("rules_manifest_url", ""),
            dashboard_url=data.get("dashboard_url", ""),
            hmac_key=data.get("hmac_key", ""),
            capabilities=data.get("capabilities", {}),
        )


def load_config() -> Optional[ProvnCloudConfig]:
    if not CONFIG_FILE.exists():
        return None
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
            return ProvnCloudConfig.from_dict(json.load(handle))
    except Exception as exc:
        logger.warning("[ProvnCloud] Failed to load config: %s", exc)
        return None


def save_config(cfg: ProvnCloudConfig) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as handle:
        json.dump(cfg.to_dict(), handle, indent=2)
        handle.write("\n")


def clear_config() -> None:
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()


def login_with_token(base_url: str, token: str) -> ProvnCloudConfig:
    bootstrap_url = f"{base_url.rstrip('/')}/api/mcp/bootstrap"
    headers = {"Authorization": f"Bearer {token}"}

    with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
        resp = client.get(bootstrap_url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    cfg = ProvnCloudConfig.from_bootstrap(data)
    cfg.service_token = token
    save_config(cfg)
    return cfg


class RemoteSettingsProvider:
    """
    Fetches team settings from ProvnCloud at startup.
    Settings are applied once; restart is still the safe default.
    """

    def __init__(self, config: ProvnCloudConfig):
        self.cfg = config

    def fetch(self) -> dict[str, Any]:
        if not self.cfg.config_url or not self.cfg.service_token:
            return {}

        headers = {
            "Authorization": f"Bearer {self.cfg.service_token}",
            "Accept": "application/json",
        }

        with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
            resp = client.get(self.cfg.config_url, headers=headers)
            resp.raise_for_status()
            return resp.json()

    def apply_to(self, proxy_config: Any) -> None:
        try:
            settings = self.fetch()
        except Exception as exc:
            logger.warning("[ProvnCloud] Failed to fetch remote settings: %s", exc)
            return

        if "l2_enabled" in settings:
            proxy_config.semantic_enabled = bool(settings.get("l2_enabled"))
        if "l3_enabled" in settings:
            proxy_config.behavioral_enabled = bool(settings.get("l3_enabled"))

        proxy_config.mode = settings.get("mode", proxy_config.mode)
        proxy_config.block_threshold = settings.get("block_threshold", proxy_config.block_threshold)
        proxy_config.warn_threshold = settings.get("warn_threshold", proxy_config.warn_threshold)

        # Preserve richer policy payloads for later use without assuming
        # ProxyConfig already has first-class runtime fields for them.
        proxy_config.provncloud_allowed_tools = settings.get("allowed_tools", [])
        proxy_config.provncloud_denied_tools = settings.get("denied_tools", [])
        proxy_config.provncloud_mcp_enabled = settings.get("mcp_enabled", True)

        self.cfg.hmac_key = settings.get("hmac_key", "")
        save_config(self.cfg)

        logger.info(
            "[ProvnCloud] Remote settings applied (revision: %s)",
            settings.get("config_revision", "unknown"),
        )


class ProvnCloudEventReporter:
    """
    Batched, asynchronous event reporter for ProvnCloud.
    """

    def __init__(self, config: ProvnCloudConfig):
        self.cfg = config
        self._buffer: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._shutdown = False

    def start(self) -> None:
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._flush_loop())

    async def shutdown(self) -> None:
        self._shutdown = True
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self._flush(force=True)

    async def report(self, event: dict[str, Any]) -> None:
        if not self.cfg.events_url or not self.cfg.service_token:
            return

        async with self._lock:
            self._buffer.append(self._prepare_event(event))
            should_flush = len(self._buffer) >= DEFAULT_BATCH_SIZE

        if should_flush:
            await self._flush()

    async def _flush_loop(self) -> None:
        try:
            while not self._shutdown:
                await asyncio.sleep(DEFAULT_FLUSH_INTERVAL_SEC)
                await self._flush()
        except asyncio.CancelledError:
            pass

    async def _flush(self, force: bool = False) -> None:
        if not self.cfg.events_url or not self.cfg.service_token:
            return

        async with self._lock:
            if not self._buffer:
                return
            if not force and len(self._buffer) < DEFAULT_BATCH_SIZE:
                return
            batch = self._buffer[:]
            self._buffer = []

        payload = {"events": batch}
        headers = {
            "Authorization": f"Bearer {self.cfg.service_token}",
            "Content-Type": "application/json",
            "X-Batch-Id": str(uuid.uuid4()),
        }

        try:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
                resp = await client.post(self.cfg.events_url, headers=headers, json=payload)
                resp.raise_for_status()
                logger.debug("[ProvnCloud] Flushed %d events", len(batch))
        except Exception as exc:
            logger.warning("[ProvnCloud] Failed to flush events: %s", exc)

    def _prepare_event(self, event: dict[str, Any]) -> dict[str, Any]:
        tool_args = event.get("tool_args", {})
        tool_args_hmac = ""
        if tool_args and self.cfg.hmac_key:
            payload = json.dumps(tool_args, sort_keys=True).encode("utf-8")
            tool_args_hmac = hmac.new(
                self.cfg.hmac_key.encode("utf-8"),
                payload,
                hashlib.sha256,
            ).hexdigest()

        return {
            "event_id": event.get("event_id"),
            "timestamp": _iso_timestamp(event.get("timestamp", time.time())),
            "session_id": event.get("session_id", ""),
            "principal_id": event.get("principal_id"),
            "auth_type": event.get("auth_type"),
            "server_id": event.get("server_id"),
            "direction": event.get("direction", ""),
            "method": event.get("method"),
            "tool_name": event.get("tool_name", ""),
            "action": event.get("action", ""),
            "layer": f"L{event.get('layer_triggered', 1)}",
            "rule_id": event.get("rule_id"),
            "semantic_score": event.get("semantic_score"),
            "risk_score": event.get("risk_score"),
            "risk_enforcement": event.get("risk_enforcement"),
            "latency_ms": event.get("latency_ms"),
            "blocked_reason": event.get("blocked_reason"),
            "auth_warnings": event.get("auth_warnings", []),
            "tool_args_hmac": tool_args_hmac,
            "mode": event.get("mode"),
            "error_kind": event.get("error_kind"),
            "message_kind": event.get("message_kind"),
            "metadata_policy": event.get("metadata_policy"),
            "policy_revision": event.get("policy_revision"),
        }


def _iso_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
