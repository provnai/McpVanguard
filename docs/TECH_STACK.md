# McpVanguard — Tech Stack Reference

## Python Core Dependencies

```
# requirements.txt
mcp>=1.0.0                  # Official Anthropic MCP Python SDK (stdio transport)
fastmcp>=0.9.0              # FastMCP — Pythonic MCP server/client scaffolding
uvloop>=0.19.0              # Ultra-fast asyncio event loop (2-4x faster)
pyyaml>=6.0                 # YAML rule file loading
httpx>=0.27.0               # Async HTTP client (for Ollama API calls)
redis>=5.0.0                # Redis client (cluster state)
typer>=0.12.0               # CLI framework (for `vanguard` CLI tool)
rich>=13.0.0                # Beautiful terminal output (tables, progress bars)
pytest>=8.0.0               # Test framework
pytest-asyncio>=0.23.0      # Async test support
```

## Why Each Library Was Chosen

### `mcp` (Official SDK)
- Maintained by Anthropic
- Native `stdio` transport — zero-config for local proxy
- Handles JSON-RPC framing, message ID tracking, error types
- Source: https://github.com/modelcontextprotocol/python-sdk

### `fastmcp`
- Now part of the official MCP SDK (absorbed in 2024)
- Simplest way to create MCP servers AND intercept/proxy calls
- Wrap any Python function into an MCP tool in 3 lines
- Used for our mock MCP servers in `mcp_servers/`

### `uvloop`
- Drop-in replacement for asyncio's event loop
- Written in Cython, based on libuv (same as Node.js)
- 2–4× faster I/O throughput
- One line to enable: `asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())`
- Critical for hitting our <10ms latency target

### `pyyaml`
- Loads static signature rule files from `rules/` directory AND the deterministic `safe_zones.yaml`.
- While kernel-backed Safe Zones (`openat2`, etc.) handle path isolation, YAML rules handle complex payload matching.
- YAML is human-readable → community can contribute rules via PRs
- No schema validation needed for MVP (add `jsonschema` later)

### `httpx`
- Async HTTP client for calling the Ollama REST API (Layer 2 scoring)
- Supports connection pooling — keeps Ollama session warm
- Can also be used for any webhook calls


### `typer`
- Builds the `vanguard` CLI (`vanguard start`, `vanguard submit`, `vanguard update`)
- Auto-generates `--help` documentation
- Built on top of Click

### `rich`
- Makes terminal output beautiful (tables, colored output, spinners)
- Used for displaying audit logs, block notifications, challenge results

---

## AI / LLM Stack (Layer 2)

### Ollama (Primary — Recommended for enterprise deployment)
**Install:** https://ollama.ai (macOS/Linux/Windows)
```bash
# One-time setup
ollama pull phi4-mini     # 2.5GB download — best accuracy
# OR
ollama pull llama3.2:1b   # 0.8GB download — fastest
```

**Why Ollama:**
- Zero-config REST API at `localhost:11434`
- Every developer or auditor can install it without coding
- Model management is automatic
- Free, local, private

**Vanguard integration:**
```python
# core/semantic.py
import httpx

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "phi4-mini"  # configurable via vanguard.yaml

async def score_intent(tool_call: dict) -> float:
    prompt = f"Tool: {tool_call['method']} | Params: {tool_call['params']}"
    async with httpx.AsyncClient() as client:
        r = await client.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "system": SECURITY_SCORER_SYSTEM_PROMPT,
            "format": "json",
            "stream": False
        }, timeout=5.0)
    return r.json()["score"]
```

### llama-cpp-python (Alternative — for embedded/prod)
```bash
pip install llama-cpp-python
```
- Runs GGUF models directly in Python (no Ollama process needed)
- Slightly more complex setup but fully self-contained
- Use when deploying in a Docker container on Railway

---



## Local Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/provnai/McpVanguard

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Ollama (for Layer 2 semantic scoring)
# Download from https://ollama.ai
ollama pull llama3.2:1b

# 5. Set up environment variables
cp .env.example .env

# 6. Run the proxy (wrapping a real MCP server)
python -m vanguard start --server "npx @modelcontextprotocol/server-filesystem ."


# 8. Run tests
pytest tests/ -v
```

### `.env.example`
```

OLLAMA_MODEL=llama3.2:1b              # or phi4-mini
VANGUARD_LOG_LEVEL=INFO
VANGUARD_SEMANTIC_ENABLED=false        # Set true to enable Layer 2
VANGUARD_BEHAVIORAL_ENABLED=true
VANGUARD_MAX_STRING_LEN=65536          # Safeguard against oversized payloads
```
