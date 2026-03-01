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
│                  MCP Server          audit.log & VEX API         │
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

**State storage:** In-memory `defaultdict(deque)` for single-node. Backed by **Redis** for persistent cluster-wide session history and analysis.

---

### `core/vex_client.py` — VEX Protocol Flight Recorder
 
 Vanguard optionally integrates with the **VEX Protocol**, serving as an immutable flight recorder for blocked actions.
 
 **Data Flow: Interception & Anchoring**
 
 ```
 AI Agent attempts malicious action
          │
          ▼
 Vanguard L1/L2/L3 blocks the payload
          │
          ├─► Emits JSON-RPC Error to Agent
          └─► Fires Async Payload to VEX Server
                    │
                    ▼
          VEX API & CHORA Gate
          (Hashes payload, anchors to Bitcoin network)
                    │
                    ▼
          Returns SSE Receipt (EvidenceCapsule)
          to Vanguard Audit Log
 ```
 
 This cryptographically guarantees that all intercepted malicious intents are mathematically verifiable by Enterprise Auditors, achieving absolute non-repudiation.
