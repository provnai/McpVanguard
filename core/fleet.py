"""
core/fleet.py
Automated fleet synchronization for McpVanguard policies.
Polls ProvnCloud or a configured remote registry for signed rule updates.
"""

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional, Dict

import httpx
from core import signing
from core.rules_engine import RulesEngine


logger = logging.getLogger("vanguard.fleet")


class FleetSyncWorker:
    """
    Background worker that periodically polls a remote fleet registry
    for signed security signatures and hot-reloads the RulesEngine.
    """

    def __init__(
        self,
        fleet_url: str,
        rules_dir: str = "rules",
        interval_secs: int = 60,
        allow_unsigned: bool = False,
    ):
        self.fleet_url = fleet_url.rstrip("/")
        self.rules_dir = Path(rules_dir)
        self.interval_secs = interval_secs
        self.allow_unsigned = allow_unsigned
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the background sync loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info(f"FleetSync: Started polling {self.fleet_url} every {self.interval_secs}s")

    async def stop(self):
        """Stop the background sync loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("FleetSync: Stopped.")

    async def _run_loop(self):
        # Initial delay to avoid spiking during server boot
        await asyncio.sleep(5)
        while self._running:
            try:
                updated = await self.sync_once()
                if updated:
                    count = RulesEngine.get_instance().reload()
                    logger.info(f"FleetSync: Hot-reload triggered. {count} rules now active.")
            except Exception as e:
                logger.error(f"FleetSync: Error during synchronization: {e}")
            
            await asyncio.sleep(self.interval_secs)

    async def sync_once(self) -> bool:
        """
        Perform a single sync pass.
        Returns True if new rules were successfully downloaded and verified.
        """
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            # 1. Fetch Manifest
            try:
                manifest_url = f"{self.fleet_url}/{signing.RULE_MANIFEST}"
                resp = await client.get(manifest_url)
                if resp.status_code == 404:
                    logger.debug("FleetSync: No remote manifest found.")
                    return False
                resp.raise_for_status()
                manifest = resp.json()
            except Exception as e:
                logger.warning(f"FleetSync: Failed to fetch manifest: {e}")
                return False

            # 2. Fetch & Verify Signature
            signature_doc = None
            try:
                sig_url = f"{self.fleet_url}/{signing.RULE_SIGNATURE}"
                resp = await client.get(sig_url)
                if resp.status_code == 200:
                    signature_doc = resp.json()
            except Exception:
                pass

            if not signature_doc and not self.allow_unsigned:
                logger.error("FleetSync: Remote manifest is unsigned and allow_unsigned=False. Aborting sync.")
                return False

            if signature_doc:
                try:
                    trusted_signers = signing.load_trusted_signers()
                    signing.verify_manifest_signature(manifest, signature_doc, trusted_signers)
                    logger.debug("FleetSync: Manifest signature verified.")
                except Exception as e:
                    logger.error(f"FleetSync: Signature verification failed: {e}")
                    return False

            # 3. Check for updates based on SHA256 hashes in manifest
            remote_rules = manifest.get("rules", {})
            download_list: list[str] = []
            
            for filename, entry in remote_rules.items():
                local_file = self.rules_dir / filename
                remote_sha = entry.get("sha256")
                
                if not local_file.exists():
                    download_list.append(filename)
                    continue
                
                local_sha = hashlib.sha256(local_file.read_bytes()).hexdigest()
                if local_sha != remote_sha:
                    download_list.append(filename)

            if not download_list:
                logger.debug("FleetSync: Local rules are already up to date.")
                return False

            # 4. Download changed rules
            logger.info(f"FleetSync: Downloading {len(download_list)} updated rule(s) from {self.fleet_url}")
            for filename in download_list:
                rule_url = f"{self.fleet_url}/{filename}"
                resp = await client.get(rule_url)
                resp.raise_for_status()
                content = resp.content
                
                # Double-verify against manifest hash
                expected_sha = remote_rules[filename]["sha256"]
                actual_sha = hashlib.sha256(content).hexdigest()
                if actual_sha != expected_sha:
                    logger.error(f"FleetSync: Integrity mismatch for {filename} (expected {expected_sha}, got {actual_sha})")
                    return False
                
                # Stage to disk
                self.rules_dir.mkdir(parents=True, exist_ok=True)
                local_file = self.rules_dir / filename
                local_file.write_bytes(content)
                logger.info(f"FleetSync: Updated {filename}")

            # 5. Persist the manifest and signature for offline persistence
            # (Matches `vanguard update` behavior)
            (self.rules_dir / signing.RULE_MANIFEST).write_text(json.dumps(manifest, indent=2))
            if signature_doc:
                (self.rules_dir / signing.RULE_SIGNATURE).write_text(json.dumps(signature_doc, indent=2))

            return True


# Provider function for use in sse_server lifespan
_worker: Optional[FleetSyncWorker] = None

async def start_fleet_sync(config: dict, rules_dir: str):
    global _worker
    fleet_url = os.getenv("VANGUARD_FLEET_URL")
    if not fleet_url:
        logger.info("VANGUARD_FLEET_URL not set; skipping automated fleet synchronization.")
        return

    interval = int(os.getenv("VANGUARD_FLEET_SYNC_INTERVAL", "60"))
    allow_unsigned = os.getenv("VANGUARD_ALLOW_UNSIGNED_FLEET", "false").lower() == "true"
    
    _worker = FleetSyncWorker(
        fleet_url=fleet_url,
        rules_dir=rules_dir,
        interval_secs=interval,
        allow_unsigned=allow_unsigned,
    )
    await _worker.start()

async def stop_fleet_sync():
    global _worker
    if _worker:
        await _worker.stop()
        _worker = None
