"""
core/semantic.py — Layer 2: Semantic Intent Scoring

Calls a local Ollama LLM to rate the intent of ambiguous tool calls on a 0.0–1.0
risk scale. Runs in a ThreadPoolExecutor so it never blocks the async proxy loop.

Thresholds (from .env):
    VANGUARD_SEMANTIC_THRESHOLD_BLOCK = 0.80  → BLOCK
    VANGUARD_SEMANTIC_THRESHOLD_WARN  = 0.50  → WARN
    VANGUARD_SEMANTIC_ENABLED         = true  → enable the layer
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import httpx

from core.models import InspectionResult, RuleMatch

logger = logging.getLogger("vanguard.semantic")

# ─── Config ──────────────────────────────────────────────────────────────────

OLLAMA_URL = os.getenv("VANGUARD_OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("VANGUARD_OLLAMA_MODEL", "phi4-mini")
OPENAI_API_KEY = os.getenv("VANGUARD_OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("VANGUARD_OPENAI_MODEL", "gpt-4o-mini")
THRESHOLD_BLOCK = float(os.getenv("VANGUARD_SEMANTIC_THRESHOLD_BLOCK", "0.80"))
THRESHOLD_WARN = float(os.getenv("VANGUARD_SEMANTIC_THRESHOLD_WARN", "0.50"))
ENABLED = os.getenv("VANGUARD_SEMANTIC_ENABLED", "false").lower() == "true"
ENABLE_FAIL_CLOSED = os.getenv("VANGUARD_SEMANTIC_FAIL_CLOSED", "true").lower() == "true"
TIMEOUT = float(os.getenv("VANGUARD_SEMANTIC_TIMEOUT_SECS", "5.0"))

# Shared thread pool — keeps async loop unblocked
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vanguard-semantic")

# ─── Prompt ───────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a security classifier for an AI agent security system.

Your job: given an MCP tool call (JSON), output ONLY a JSON object with:
  {"score": <float 0.0–1.0>, "reason": "<one sentence>"}

Score meaning:
  0.0 = completely benign (reading a normal file, listing directory)
  0.5 = suspicious but ambiguous (unusual path, odd arguments)
  1.0 = clearly malicious (exfiltration, shell injection, jailbreak)

Rules:
- Output ONLY valid JSON. No markdown fences. No explanation outside JSON.
- Be concise in reason (max 15 words).
- When genuinely uncertain, score 0.4.
"""

# ─── Core scoring function (runs in thread) ───────────────────────────────────

def _score_sync(tool_call_json: str) -> tuple[float, str]:
    """Blocking call to Ollama or OpenAI — run in executor."""
    prompt = f"Rate this MCP tool call:\n{tool_call_json}"

    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            if OPENAI_API_KEY:
                # Use OpenAI if an API key is provided
                resp = client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {OPENAI_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": OPENAI_MODEL,
                        "messages": [
                            {"role": "system", "content": _SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.0,
                        "response_format": {"type": "json_object"},
                    },
                )
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"].strip()
            else:
                # Fallback to local Ollama
                resp = client.post(
                    f"{OLLAMA_URL}/api/chat",
                    json={
                        "model": OLLAMA_MODEL,
                        "messages": [
                            {"role": "system", "content": _SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        "stream": False,
                        "options": {"temperature": 0.0},
                    },
                )
                resp.raise_for_status()
                content = resp.json()["message"]["content"].strip()

            # Strip markdown fences if model disobeys
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]

            parsed = json.loads(content)
            score = float(parsed.get("score", 0.0))
            reason = str(parsed.get("reason", "semantic scorer"))
            return max(0.0, min(1.0, score)), reason

    except httpx.ConnectError:
        logger.warning("Remote API not reachable")
        if ENABLE_FAIL_CLOSED:
            return 1.0, "semantic api unreachable (fail-closed)"
        return 0.0, "api unreachable"
    except httpx.TimeoutException:
        logger.warning("Remote API timeout after %.1fs", TIMEOUT)
        if ENABLE_FAIL_CLOSED:
            return 1.0, "semantic api timeout (fail-closed)"
        return 0.0, "api timeout"
    except Exception as exc:
        logger.warning("Semantic scorer error: %s", exc)
        if ENABLE_FAIL_CLOSED:
             return 1.0, f"FAIL-CLOSED: {exc}"
        return 0.0, f"scorer error: {exc}"


# ─── Public async API ─────────────────────────────────────────────────────────

async def score_intent(message: dict) -> Optional[InspectionResult]:
    """
    Asynchronously score the intent of a tool call message.

    Returns an InspectionResult if semantic scoring is enabled and the score
    exceeds a threshold, otherwise returns None (pass-through).

    Args:
        message: A parsed JSON-RPC message dict.

    Returns:
        InspectionResult with action BLOCK or WARN, or None to pass-through.
    """
    if not ENABLED:
        return None

    # Only score tool calls (method: "tools/call")
    if message.get("method") != "tools/call":
        return None

    loop = asyncio.get_event_loop()
    tool_call_json = json.dumps(message, indent=2)

    try:
        score, reason = await asyncio.wait_for(
            loop.run_in_executor(_executor, _score_sync, tool_call_json),
            timeout=TIMEOUT + 1.0,
        )
    except asyncio.TimeoutError:
        logger.warning("Semantic scoring timed out (async wrapper)")
        return None

    logger.debug("Semantic score=%.3f reason=%s", score, reason)

    if score >= THRESHOLD_BLOCK:
        return InspectionResult(
            allowed=False,
            action="BLOCK",
            layer_triggered=2,
            rule_matches=[
                RuleMatch(
                    rule_id="SEM-BLOCK",
                    description=f"Semantic scorer: {reason}",
                    severity="HIGH",
                )
            ],
            semantic_score=score,
            block_reason=f"Semantic intent score {score:.2f} ≥ {THRESHOLD_BLOCK} — {reason}",
        )

    if score >= THRESHOLD_WARN:
        return InspectionResult(
            allowed=True,
            action="WARN",
            layer_triggered=2,
            rule_matches=[
                RuleMatch(
                    rule_id="SEM-WARN",
                    description=f"Semantic scorer: {reason}",
                    severity="MEDIUM",
                )
            ],
            semantic_score=score,
        )

    return None  # Below thresholds — pass-through


async def check_ollama_health() -> bool:
    """Returns True if the backend is running and the configured model is available."""
    if OPENAI_API_KEY:
        return True  # Avoid healthchecking OpenAI directly for now
        
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            data = resp.json()
            models = [m["name"] for m in data.get("models", [])]
            return any(OLLAMA_MODEL in m for m in models)
    except Exception:
        return False
