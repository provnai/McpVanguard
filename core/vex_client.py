"""
core/vex_client.py — VEX Protocol API Client
Handles the asynchronous handoff of blocked payloads to the VEX Rust API.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import httpx
from typing import Optional

logger = logging.getLogger("vanguard.vex")

# ─── Configuration ─────────────────────────────────────────────────────────────

VEX_API_URL = os.getenv("VANGUARD_VEX_URL", os.getenv("VANGUARD_VEX_API_URL", "http://localhost:8000/api/v1"))
VEX_JWT = os.getenv("VANGUARD_VEX_KEY", os.getenv("VANGUARD_VEX_JWT", ""))
_agent_id: Optional[str] = os.getenv("VANGUARD_VEX_AGENT_ID", None)

# ─── Agent Management ────────────────────────────────────────────────────────

async def _get_or_create_agent() -> Optional[str]:
    """Retrieve the existing agent ID or create a new Vanguard Auditor agent."""
    global _agent_id
    if _agent_id:
        return _agent_id
    
    if not VEX_JWT:
        logger.debug("No VEX JWT configured. Interception handoff is disabled.")
        return None

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{VEX_API_URL}/agents",
                headers={"Authorization": f"Bearer {VEX_JWT}"},
                json={"name": "Vanguard Security Auditor Proxy"}
            )
            resp.raise_for_status()
            data = resp.json()
            
            # Extract ID from response (adjusting for typical REST ID shapes)
            _agent_id = data.get("id") or data.get("agent_id")
            if _agent_id:
                logger.info("Successfully created/retrieved VEX Auditor Agent: %s", _agent_id)
                return _agent_id
            else:
                logger.error("VEX API /agents responded successfully but no ID was found.")
                return None
    except httpx.HTTPStatusError as e:
        logger.error("VEX /agents HTTP Error: %d - %s", e.response.status_code, e.response.text)
        return None
    except Exception as e:
        logger.error("Failed to connect to VEX API to create agent: %s", e)
        return None

# ─── Interception Handoff ────────────────────────────────────────────────────

def submit_blocked_call(payload: dict, session_id: str = "vanguard-session") -> None:
    """
    Fire-and-forget submission of a blocked tool call to the VEX API.
    Spawns a background task so the Vanguard proxy loop is NEVER blocked.
    """
    if not VEX_JWT:
        return

    # Spawn the async task independently
    asyncio.create_task(_execute_and_listen(payload, session_id))


async def _execute_and_listen(payload: dict, session_id: str):
    """Handles the 2-step POST/SSE flow with the VEX job queue."""
    agent_id = await _get_or_create_agent()
    if not agent_id:
        return

    prompt_str = json.dumps(payload, indent=2)
    vex_payload = {
        "prompt": f"Audit this intercepted tool call payload from Vanguard:\n\n{prompt_str}",
        "context_id": session_id,
        "enable_adversarial": True,
        "enable_self_correction": False,
        "max_debate_rounds": 3
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"Authorization": f"Bearer {VEX_JWT}"}
            
            # Step 1: POST execution job
            resp = await client.post(
                f"{VEX_API_URL}/agents/{agent_id}/execute",
                headers=headers,
                json=vex_payload
            )
            resp.raise_for_status()
            data = resp.json()
            job_id = data.get("job_id") or data.get("id")
            
            if not job_id:
                logger.error("VEX API execution succeeded but returned no job_id.")
                return

            logger.info("VEX Handoff successful. Waiting for CHORA EvidenceCapsule on job: %s", job_id)
            
            # Step 2: Listen to SSE stream for the final receipt
            async with client.stream("GET", f"{VEX_API_URL}/jobs/{job_id}/stream", headers=headers) as stream:
                async for line in stream.aiter_lines():
                    line = line.strip()
                    if not line or not line.startswith("data:"):
                        continue
                        
                    event_data = line[5:].strip()
                    if event_data == "[DONE]":
                        break
                        
                    try:
                        parsed = json.loads(event_data)
                        status = parsed.get("status")
                        
                        # Once the job completes or fails, log the cryptographic EvidenceCapsule
                        if status in ("completed", "failed", "halted", "success"):
                            logger.info(
                                "🛡️ CHORA Receipt Recorded for Vanguard Block (Job %s):\n%s", 
                                job_id, 
                                json.dumps(parsed, indent=2)
                            )
                            break
                    except json.JSONDecodeError:
                        continue
                        
    except httpx.HTTPStatusError as e:
        logger.error("VEX Execute HTTP Error: %d - %s", e.response.status_code, e.response.text)
    except Exception as e:
        logger.error("Error during VEX execute and listen flow: %s", e)
