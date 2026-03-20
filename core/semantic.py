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
# OpenAI / Cloud Config
OPENAI_API_KEY = os.getenv("VANGUARD_OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("VANGUARD_OPENAI_MODEL", "gpt-4o-mini")
OPENAI_BASE_URL = os.getenv("VANGUARD_OPENAI_BASE_URL", "https://api.openai.com/v1")

# MiniMax Config
MINIMAX_API_KEY = os.getenv("VANGUARD_MINIMAX_API_KEY")
MINIMAX_MODEL = os.getenv("VANGUARD_MINIMAX_MODEL", "MiniMax-M2.5")
MINIMAX_BASE_URL = os.getenv("VANGUARD_MINIMAX_BASE_URL", "https://api.minimax.io/v1")

# Generic / Custom Provider (Mistral, DeepSeek, Groq, local vLLM, etc.)
CUSTOM_API_KEY = os.getenv("VANGUARD_SEMANTIC_CUSTOM_KEY")
CUSTOM_MODEL = os.getenv("VANGUARD_SEMANTIC_CUSTOM_MODEL")
CUSTOM_BASE_URL = os.getenv("VANGUARD_SEMANTIC_CUSTOM_URL")

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

def _extract_json(content: str) -> dict:
    """Robustly extract JSON from model output, handling markdown fences and filler."""
    content = content.strip()
    
    # 1. Handle common markdown fences
    if "```" in content:
        try:
            # Extract content between the first set of fences
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:].strip()
            elif content.startswith("\n"):
                content = content.strip()
        except IndexError:
            pass

    # 2. Find the first '{' and last '}' to prune conversational filler
    start = content.find("{")
    end = content.rfind("}")
    if start != -1 and end != -1 and end > start:
        content = content[start:end+1]

    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse LLM JSON. Content: %r", content)
        raise ValueError(f"Invalid JSON response from LLM: {exc}")


def _call_cloud_provider(client: httpx.Client, base_url: str, api_key: str, model: str, prompt: str) -> str:
    """Helper to call any OpenAI-compatible cloud provider."""
    # Ensure base_url doesn't end in /chat/completions
    url = base_url.rstrip("/")
    if not url.endswith("/chat/completions"):
        url = f"{url}/chat/completions"
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
    }
    
    # OpenAI supports response_format: json_object, others might not
    if "openai.com" in url:
        payload["response_format"] = {"type": "json_object"}
        payload["temperature"] = 0.0

    resp = client.post(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _score_sync(tool_call_json: str) -> tuple[float, str]:
    """Blocking call to available providers — run in executor."""
    prompt = f"Rate this MCP tool call:\n{tool_call_json}"

    retries = 3
    last_exc = None
    
    for attempt in range(retries):
        try:
            with httpx.Client(timeout=TIMEOUT) as client:
                content = ""
                
                # Provider Selection Priority
                if CUSTOM_API_KEY and CUSTOM_BASE_URL and CUSTOM_MODEL:
                    logger.debug("Using Custom Provider (Attempt %d): %s", attempt + 1, CUSTOM_BASE_URL)
                    content = _call_cloud_provider(client, CUSTOM_BASE_URL, CUSTOM_API_KEY, CUSTOM_MODEL, prompt)
                
                elif OPENAI_API_KEY:
                    logger.debug("Using OpenAI Provider (Attempt %d)", attempt + 1)
                    content = _call_cloud_provider(client, OPENAI_BASE_URL, OPENAI_API_KEY, OPENAI_MODEL, prompt)
                
                elif MINIMAX_API_KEY:
                    logger.debug("Using MiniMax Provider (Attempt %d)", attempt + 1)
                    content = _call_cloud_provider(client, MINIMAX_BASE_URL, MINIMAX_API_KEY, MINIMAX_MODEL, prompt)
                
                else:
                    # Fallback to local Ollama
                    logger.debug("Using Ollama Fallback (Attempt %d)", attempt + 1)
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
                    content = resp.json()["message"]["content"]

                # Robust extraction of score and reason
                parsed = _extract_json(content)
                score = float(parsed.get("score", 0.0))
                reason = str(parsed.get("reason", "semantic scorer"))
                return max(0.0, min(1.0, score)), reason

        except (httpx.ConnectError, httpx.TimeoutException, json.JSONDecodeError, ValueError) as exc:
            last_exc = exc
            logger.warning("Semantic scorer attempt %d failed: %s", attempt + 1, exc)
            if attempt < retries - 1:
                # Exponential backoff: 0.5s, 1.0s
                time.sleep(0.5 * (2 ** attempt))
            continue
        except Exception as exc:
            # Critical unrecoverable error
            logger.error("Critical semantic scorer error: %s", exc)
            if ENABLE_FAIL_CLOSED:
                 return 1.0, f"FAIL-CLOSED: {exc}"
            return 0.0, f"scorer error: {exc}"

    # If all retries fail
    if ENABLE_FAIL_CLOSED:
        return 1.0, f"FAIL-CLOSED: All {retries} semantic attempts failed. Final error: {last_exc}"
    return 0.0, f"scorer error: {last_exc}"


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


async def check_semantic_health() -> bool:
    """Returns True if the configured backend is responsive."""
    # Cloud providers: assume healthy if keys are set (minimal check)
    if CUSTOM_API_KEY or OPENAI_API_KEY or MINIMAX_API_KEY:
        return True

    # Local Ollama: verify connectivity
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False
