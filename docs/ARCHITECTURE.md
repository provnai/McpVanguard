# McpVanguard — System Architecture

## Overview

McpVanguard is a **transparent JSON-RPC proxy** that intercepts all communication between an AI agent and any MCP server. It sits in the middle of the stdio stream, inspects every tool call in real-time, and applies three layers of defense before forwarding or blocking the request.

```
┌──────────────────────────────────────────────────────────────────┐
│              AGENT (Local CLI or Remote via SSE)                 │
└────────────────────────────┬─────────────────────────────────────┘
                             │  JSON-RPC (stdio or HTTP/SSE)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                    McpVanguard Proxy Engine                      │
│                                                                  │
│  [Transport Layer] ──► [RULES ENGINE] ──► [SUBPROCESS PUMP]      │
│  (Stdio/SSE Bridge)                │                             │
│                         ┌──────────┼──────────┐                 │
│                         ▼          ▼           ▼                 │
│                     [Layer 1]  [Layer 2]   [Layer 3]            │
│                     Safe Zones Semantic    Behavioral            │
│                     & Rules    Scoring     & Entropy             │
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
│                  Real MCP Server Subprocess                      │
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
Main Event Loop
├── [Transport] ──────────┐
│   ├── read_agent()      │ → asyncio.StreamReader (stdio or sse_bridge)
│   └── write_agent()     │ → asyncio.StreamWriter (stdio or sse_bridge)
├── [Subprocess]          │
│   ├── read_server()     │ → server stdout pump
│   └── write_server()    │ → server stdin pump
└── [Rules Engine]        │ → L1/L2/L3 sequential inspection
```

**Latency Budget (under concurrent load):**
| Operation | Measured P99 |
|---|---|
| Regex rule check (Layer 1) | ~16ms |
| Behavioral check (Layer 3) | <5ms |
| Semantic score (Layer 2) | async, non-blocking |
| Total proxy overhead | ~156ms under max load |

---

### `core/rules_engine.py` & `core/jail.py` — Layer 1: Deterministic Safe Zones

McpVanguard's first layer of defense has evolved from pure regex matching to **OS-level deterministic isolation**.

**1. Kernel-Backed Safe Zones (`safe_zones.yaml`)**
Before inspecting payload strings, Vanguard intercepts tool calls (like `read_file` or `write_file`) and forces the operating system to canonicalize and jail the requested paths:
- **Linux (`openat2`)**: Uses syscall 437 with `RESOLVE_BENEATH` to guarantee a path cannot escape its defined root directory, crushing TOCTOU and symlink attacks.
- **Windows (`GetFinalPathNameByHandleW`)**: Opens a file handle to evaluate the true canonical path, defeating 8.3 shortnames (`PROGRA~1`), junction points, and DOS device paths (`\\.\`).

**2. Static Signature Firewall (`rules/*.yaml`)**
If a request is within bounds (or has no specific Safe Zone defined), it falls back to the static firewall. Contains **50+ signatures** across 5 categories.

**Rule Categories:**
- `rules/filesystem.yaml` — null bytes, Unix/Windows sensitive paths
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

### `core/behavioral.py` — Layer 3: Entropy & Behavioral Sentry

Tracks patterns across an entire session using a **sliding window** counter and performs **real-time data analysis**.

**1. Shannon Entropy ($H(X)$) Scouter**
To detect precise data exfiltration, Vanguard calculates the Shannon Entropy of payload samples (up to 8KB) before returning them to the agent:
- **$H > 7.5$**: Almost certainly cryptographic keys or compressed data. Immediately blocked (`BEH-006`).
- **$H > 6.0$**: Highly dense/structured data. Applies a vast virtual penalty multiplier to the rate limiter, aggressively clamping the session.

**2. Sliding Window Detectors:**
| Detector | Rule | Action |
|---|---|---|
| Data Scraping | >50 `read_file` calls in 10s | BLOCK session |
| Privilege Escalation | `write_file` after 5+ `read_file` to sensitive paths | ALERT |
| Flood Exfiltration | Large outbound payload (>10KB in one call) | BLOCK |
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
 
 This means any auditor can independently verify all intercepted actions without relying on local log trust.

---

### `core/sse_server.py` — The Cloud Gateway

The `SSE Bridge` transforms Vanguard into an internet-reachable server. It uses **Starlette** as the ASGI web server and the **MCP Python SDK's `SseServerTransport`** to bridge HTTP traffic into Vanguard's JSON-RPC inspection pipeline.

**Data Flow:**
1.  **Agent** connects to `GET /sse/`.
2.  **Starlette** establishes a persistent SSE stream.
3.  **Vanguard** spawns the target MCP server subprocess.
4.  **Agent** sends tool calls via `POST /messages`.
5.  **SSE Bridge** pipes the POST body into `VanguardProxy` for rules inspection.
6.  **Vanguard** proxies the "Allowed" call to the server and reels the response back via the SSE stream.
