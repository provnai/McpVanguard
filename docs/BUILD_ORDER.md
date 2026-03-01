# 🗺️ McpVanguard — Build Order Checklist

> This is the canonical build document. Work top to bottom. Tick as you go.
> Cross-reference: [ARCHITECTURE.md](ARCHITECTURE.md) · [TECH_STACK.md](TECH_STACK.md) · [HOSTING.md](HOSTING.md)

---

## ⚙️ Phase 1 — Foundation: Make It Real ✅
**Goal:** A working proxy that intercepts and blocks real MCP calls.

### Step 1 — Environment & Dependencies
- [x] Create virtual environment
- [x] Install all deps: `pip install mcp fastmcp uvloop pyyaml httpx supabase typer rich pytest pytest-asyncio`
- [x] Freeze deps: `pip freeze > requirements.txt`

### Step 2 — Core Module Scaffold
- [x] `core/models.py` — Pydantic models for JSON-RPC
- [x] `core/session.py` — session state machine
- [x] `core/__init__.py`, `core/__main__.py`

### Step 3 — Rules Engine (Layer 1)
- [x] `core/rules_engine.py` — YAML rule loader
- [x] `rules/filesystem.yaml`, `rules/commands.yaml`, `rules/network.yaml`, `rules/jailbreak.yaml`, `rules/privilege.yaml`
- [x] Write unit tests: `tests/test_rules.py` (32/32 PASSED)

### Step 4 — The Proxy
- [x] `core/proxy.py` with async stdio interceptor
- [x] Layer 1 integration complete
- [x] Audit logging to `audit.log`

### Step 5 — CLI
- [x] `core/cli.py` — `vanguard start/info/version`

### Step 6 — Mock Servers
- [x] `mcp_servers/vulnerable_fs_server.py`

### Step 7 — Tests
- [x] `tests/test_proxy.py` (Integration)
- [x] `tests/test_rules.py` (Unit)

---

## 🏟️ Phase 2 — The Gauntlet: Gamification ✅
**Goal:** First 3 challenge levels working end-to-end.

### Step 8-11 — Arena Build
- [x] `arena/challenges/level_1.py`, `level_2.py`, `level_3.py`
- [x] `arena/hunter.py` — real-time PoE collector
- [x] `mcp_servers/vulnerable_shell_server.py`

### Step 12-14 — Automation
- [x] GitHub Issue Templates for submissions
- [x] GitHub Actions for testing and PoE validation
- [x] Post-exploit script suite (`scripts/`)

---

## 🌐 Phase 3 — The Website ✅
**Goal:** Landing page + live leaderboard.

### Step 15-17 — Web Build
- [x] Supabase project and schema setup
- [x] Next.js 16 + Tailwind frontend (`web/`)
- [x] Real-time leaderboard with Supabase subscriptions
- [x] Deployment config (`vercel.json`)

---

## 🚀 Phase 4 — Package & Launch ✅
**Goal:** Distribution-ready.

### Step 18-20 — Packaging
- [x] `pyproject.toml` finalized
- [x] `README.md`, `LICENSE`, `CONTRIBUTING.md`
- [ ] User Actions: Connection to Vercel/Supabase, Secret setup, PyPI upload.

---

## 🧠 Phase 5 — Intelligence Layer ✅
**Goal:** Layer 2 (Semantic) + Layer 3 (Behavioral).

### Step 21 — Ollama Integration (Layer 2)
- [x] `core/semantic.py` — Async Ollama scorer
- [x] Integrated into `VanguardProxy`
- [x] CLI flags for `--semantic` and `--ollama-model`
- [x] `tests/test_semantic.py`

### Step 22 — Full Behavioral Analysis (Layer 3)
- [x] `core/behavioral.py` — Sliding window detectors (Scraping, Enum, PrivEsc, Payload, Flood)
- [x] Integrated into `VanguardProxy`
- [x] `tests/test_behavioral.py`

### Step 23 — Update & Maintenance
- [x] `vanguard update` command (CLI stub)
- [x] `.env.example` intelligence variables

### Step 24 — Expert Arena
- [x] `arena/challenges/level_4.py`, `level_5.py`, `level_6.py`
- [x] `mcp_servers/memory_server.py`, `search_server.py`, `toolbox_server.py`
- [x] All 58 tests across all layers PASSED ✅

---

## 🌐 Phase 6 — Ecosystem Integration ✅
**Goal:** Align with the Provnai "Immune System for AI" mission.

### Step 25 — Provnai Release
- [x] Rebranded to **Provnai** initiative
- [x] Updated all URLs to `github.com/provnai/McpVanguard`
- [x] Unlocked all Expert-level challenges in Web UI
- [x] Synchronized points and descriptions across the stack

---

## ✅ Final Definition of Done
- [x] Layer 1, 2, and 3 are functional and integrated.
- [x] Arena has 6 production-grade challenges.
- [x] Website is ready for Vercel deployment.
- [x] Full test suite (Unit + Integration) passes.
