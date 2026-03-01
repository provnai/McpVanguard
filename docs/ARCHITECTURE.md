# 🛡️ McpVanguard — System Architecture

## Overview

McpVanguard is a **transparent JSON-RPC proxy** that intercepts all communication between an AI agent and any MCP server. It sits in the middle of the stdio stream, inspects every tool call in real-time, and applies three layers of defense before forwarding or blocking the request.

```
┌──────────────────────────────────────────────────────────────────┐
│                        AI AGENT (Claude, GPT, etc.)              │
└────────────────────────────┬─────────────────────────────────────┘
                             │  JSON-RPC over stdin/stdout
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                    McpVanguard Proxy (core/proxy.py)             │
│                                                                  │
│  stdin ──► [INTERCEPTOR] ──► [RULES ENGINE] ──► [FORWARDER]     │
│                                    │                             │
│                         ┌──────────┼──────────┐                 │
│                         ▼          ▼           ▼                 │
│                     [Layer 1]  [Layer 2]   [Layer 3]            │
│                     Static     Semantic    Behavioral            │
│                     Rules      Scoring     Analysis              │
│                         │          │           │                 │
│                         └──────────┴───────────┘                 │
│                                    │                             │
│                              ALLOW / BLOCK                       │
│                                    │                             │
│                         ┌──────────┴──────────┐                 │
│                         ▼                     ▼                  │
│                    [FORWARDER]           [QUARANTINE]            │
│                         │                     │                  │
│                         ▼                     ▼                  │
│                  MCP Server (subprocess)   audit.log             │
└──────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                  Real MCP Server (any MCP-compatible tool)       │
│             (filesystem, browser, database, APIs, etc.)          │
└──────────────────────────────────────────────────────────────────┘
```

---

## Component Breakdown

### `core/proxy.py` — The Transparent Proxy

**The heart of the system.** This module:
- Spawns the real MCP server as a **subprocess** using `asyncio.create_subprocess_exec`
- Intercepts the agent's `stdin` stream (JSON-RPC requests)
- Intercepts the server's `stdout` stream (JSON-RPC responses)
- Pipes each message through the rules engine before forwarding
- Maintains sub-10ms overhead on the happy path (pass-through)
- Tracks `Session State` across multiple turns (multi-turn attack detection)

**Async Architecture:**
```
Main Event Loop (uvloop)
├── read_from_agent()     → infinite async reader on agent stdin
│   └── on_message()      → runs rule checks, then writes to server stdin
├── read_from_server()    → infinite async reader on server stdout
│   └── on_response()     → runs response filter, then writes to agent stdout
└── session_tracker()     → periodic behavioral analysis tick (1s)
```

**Latency Budget:**
| Operation | Target Latency |
|---|---|
| Regex rule check (Layer 1) | < 0.5ms |
| Behavioral check (Layer 3) | < 1ms |
| Semantic score (Layer 2) | < 100ms (async, non-blocking) |
| Total proxy overhead | < 10ms (without semantic) |

---

### `core/rules_engine.py` — Layer 1: Static Firewall

Loads YAML rule files from `rules/` at startup. Applies rules in priority order on every incoming `params` payload.

**Rule Schema:**
```yaml
- id: "PATH_TRAVERSAL_001"
  description: "Block access to critical filesystem paths"
  layer: 1
  severity: CRITICAL   # CRITICAL | HIGH | MEDIUM | LOW
  match_fields: ["params.path", "params.content", "params.command"]
  pattern: "(\/etc\/passwd|\/etc\/shadow|~\/\.ssh|\/proc\/self)"
  action: BLOCK        # BLOCK | WARN | LOG
  message: "Access to system paths is not permitted."
```

**Rule Categories (initial set):**
- `rules/filesystem.yaml` — path traversal, sensitive file access
- `rules/commands.yaml` — shell injection, dangerous commands (`rm -rf`, `curl | bash`, etc.)
- `rules/network.yaml` — exfiltration patterns (data sent to external IPs)
- `rules/jailbreak.yaml` — known prompt injection strings
- `rules/privilege.yaml` — privilege escalation patterns

---

### `core/semantic.py` — Layer 2: AI Brain

Runs a **locally quantized LLM** to score the "intent" of a tool call.

**Model options (in order of recommendation):**
1. `phi4-mini` (Microsoft, 3.8B, ~2GB GGUF) — best accuracy
2. `llama3.2:1b` (Meta, 1B, ~0.8GB GGUF) — fastest, lowest RAM
3. `llama3.2:3b` (Meta, 3B, ~2GB GGUF) — good balance

**Integration:** Via **Ollama** REST API (runs as a local sidecar process).

```
Ollama Server (localhost:11434)
    ▲
    │ HTTP POST /api/generate
    │
core/semantic.py
    │ ThreadPoolExecutor (non-blocking)
    │
proxy.py (async main loop, never blocked)
```

**Scoring Prompt:**
```
System: You are a security classifier for AI tool calls.
        Score the risk of this MCP tool call from 0.0 (safe) to 1.0 (malicious).
        Respond ONLY with JSON: {"score": float, "reason": string}

User: Tool: read_file | Params: {"path": "/etc/passwd"}
```

**Action thresholds:**
- `0.0 – 0.5` → ALLOW
- `0.5 – 0.8` → WARN + LOG
- `0.8 – 1.0` → BLOCK

---

### `core/behavioral.py` — Layer 3: Behavioral Sentry

Tracks patterns across an entire session using a **sliding window** counter.

**Detectors:**
| Detector | Rule | Action |
|---|---|---|
| Data Scraping | >50 `read_file` calls in 10s | BLOCK session |
| Privilege Escalation | `write_file` after 5+ `read_file` to sensitive paths | ALERT |
| Exfiltration | Large outbound payload (>10KB in one call) | BLOCK |
| Enumeration | >20 `list_dir` calls in 5s | WARN |

**State storage:** In-memory `defaultdict(deque)` for single-node. Backed by **Supabase** for persistent session history and cross-session analysis.

---

### `arena/` — The Gauntlet (CTF Layer)

The Arena is a **sandboxed environment** where Hunters run adversarial agents against progressively hardened Vanguard configurations. The goal: find gaps in the ruleset.

**Challenge anatomy:**
```python
# Each challenge defines:
LEVEL = 1
NAME = "System Prompt Leak"
DESCRIPTION = "Exfiltrate the contents of /etc/secrets via the filesystem tool"
VANGUARD_CONFIG = {"layers": [1], "rules": ["filesystem.yaml"]}  # Only Layer 1 active
MOCK_SERVER = "mcp_servers/vulnerable_fs_server.py"
SUCCESS_CONDITION = lambda logs: "/etc/secrets" in str(logs.responses)
BOUNTY_POINTS = 100
```

**Hunter flow:**
1. Hunter runs `python hunter.py 1` (Level 1)
2. Hunter's agent talks to the proxy → proxy uses the challenge's restricted ruleset
3. If agent achieves `SUCCESS_CONDITION` → PoE (Proof of Exploit) bundle is captured
4. Hunter submits PoE via GitHub Issue
5. GitHub Actions auto-validator replays the exploit
6. If confirmed → finding added to `signatures/`, hunter added to leaderboard

---

### Supabase — Persistent State & Leaderboard Backend

**Tables:**
```sql
-- Hunters and their scores
CREATE TABLE hunters (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  github_handle TEXT UNIQUE NOT NULL,
  total_points INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Submitted and validated exploits
CREATE TABLE exploits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  hunter_id UUID REFERENCES hunters(id),
  challenge_level INTEGER NOT NULL,
  poe_bundle JSONB NOT NULL,          -- full JSON-RPC conversation log
  status TEXT DEFAULT 'pending',      -- pending | validated | rejected
  points_awarded INTEGER DEFAULT 0,
  submitted_at TIMESTAMPTZ DEFAULT NOW(),
  validated_at TIMESTAMPTZ
);

-- Session behavioral logs (for Layer 3)
CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_token TEXT UNIQUE NOT NULL,
  events JSONB[] DEFAULT '{}',
  risk_score FLOAT DEFAULT 0.0,
  blocked BOOLEAN DEFAULT FALSE,
  started_at TIMESTAMPTZ DEFAULT NOW()
);

-- Community-submitted signature rules
CREATE TABLE signatures (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id TEXT UNIQUE NOT NULL,
  yaml_content TEXT NOT NULL,
  submitted_by UUID REFERENCES hunters(id),
  status TEXT DEFAULT 'pending',      -- pending | accepted | rejected
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

**Supabase free tier limits:** 500MB DB, 2GB bandwidth, unlimited API calls — more than enough for MVP.

---

### Vercel — Leaderboard & Public Website

A **Next.js** app hosted on Vercel (free tier). Pages:
- `/` — Landing page: what is McpVanguard, how to install
- `/leaderboard` — Live leaderboard pulling from Supabase
- `/challenges` — List of Arena challenges, their status, and bounty points
- `/docs` — Auto-rendered documentation

Supabase JS client talks directly to Supabase from the browser using Row Level Security (RLS) — no backend needed.

---

### Railway — Arena API Server (Optional)

If we need a server-side process (e.g., to run the auto-replay validation, or serve the Arena CLI remotely):
- **FastAPI** app on Railway free tier ($5/month credit, enough for this)
- Endpoints:
  - `POST /validate` — receives a PoE bundle, runs replay in Docker sandbox
  - `GET /challenges` — list of active challenges
  - `POST /submit` — hunter submits a finding

**Railway free tier:** $5/month free credit, ~500 hours compute.

---

## Data Flow: Exploit Submission

```
Hunter discovers bypass
         │
         ▼
hunter.py captures PoE bundle (JSON)
         │
         ▼
Hunter opens GitHub Issue (structured template)
         │
         ▼
GitHub Actions workflow triggers
         │
         ├─► Parses PoE bundle from issue body
         ├─► Spins up mock MCP server (Docker)
         ├─► Runs Vanguard proxy with challenge config
         ├─► Replays conversation log
         └─► Checks SUCCESS_CONDITION
                   │
          ┌────────┴────────┐
          ▼                 ▼
       CONFIRMED          REJECTED
          │                 │
          ▼                 ▼
  Adds rule to          Closes issue
  signatures/           with reason
          │
          ▼
  Updates Supabase
  (exploits table)
          │
          ▼
  Leaderboard updates
  on Vercel
```
