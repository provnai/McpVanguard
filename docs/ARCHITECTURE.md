# McpVanguard — System Architecture

## Overview

McpVanguard is a **JSON-RPC security gateway** that intercepts communication between an AI agent and an MCP server. It sits in the middle of the stdio stream, inspects every tool call in real time, and applies a layered enforcement path before forwarding or blocking the request.

**Product profiles:** `monitor` (audit-only discovery), `balanced` (default OSS/developer behavior), and `strict` (production-sensitive systems with full hardening).

```
┌──────────────────────────────────────────────────────────────────┐
│              AGENT (Local CLI or Remote via SSE)                 │
└────────────────────────────┬─────────────────────────────────────┘
                             │  JSON-RPC (stdio or HTTP/SSE)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                    McpVanguard Proxy Engine                      │
│                                                                  │
│  [Transport Layer] ──► [INSPECTION PIPELINE] ──► [SUBPROCESS PUMP] │
│  (Stdio/SSE Bridge)                                                │
│                         ┌──────────┬──────────┬──────────┐        │
│                         ▼          ▼          ▼          ▼        │
│                     [L0]      [Auth/L1]  [L1.5]   [L2/L3]       │
│                  Preflight  Rules & Safe  Camouflage  Semantic    │
│                  Normalize    Zones      Detection   + Risk     │
│                         │          │          │          │       │
│                         └──────────┴──────────┴──────────┘       │
│                                    │                             │
│                         [Final Policy Composer]                  │
│                                    │                             │
│                              ALLOW / WARN / BLOCK                │
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

### `core/proxy.py` — The Core Gateway Loop

**The heart of the system.** This module:
- Spawns the real MCP server as a **subprocess** using `asyncio.create_subprocess_exec`
- Intercepts the agent's `stdin` stream (JSON-RPC requests)
- Intercepts the server's `stdout` stream (JSON-RPC responses)
- Pipes each message through the rules engine before forwarding
- Tracks `Session State` across multiple turns (multi-turn attack detection)

**Inspection Pipeline (per message):**
```
raw JSON-RPC message
  -> parse and size gate
  -> L0 preflight normalize and annotate
  -> auth/destructive-tool policy
  -> L1 deterministic rules and safe zones
  -> L1.5 trust-signal/camouflage detector
  -> L2 semantic scorer, if enabled or forced
  -> L3 behavioral/risk memory
  -> final policy composer
  -> audit event
  -> optional receipt_v1 event, if enabled
  -> block, shadow-block, review, warn, or forward normalized message
```

**Final policy invariant:** A later layer must never silently downgrade an earlier block. L2 may raise severity or add context, but must not convert a deterministic block to allow.

**Latency:** Gateway overhead depends on the active profile, rule bundle, behavioral-state backend, semantic backend, payload shape, and concurrency. Benchmark it in the target deployment before setting an operational latency budget.

---

### `core/preflight.py` — Layer 0: Preflight Normalization and Findings

The first processing stage after parsing. Normalizes the raw JSON-RPC payload and emits structured findings that feed into every downstream layer.

**Normalization:**
- Multi-pass URL decoding (up to 20 passes)
- Unicode NFKC normalization
- Zero-width and format character stripping
- Size gating (default 64KB max string length)
- Nesting depth gating (default 50 max depth)
- NaN/Infinity rejection

**Detectors:**
| Finding | Trigger |
|---|---|
| `PRE-URL-001` | Multi-pass URL decoding occurred |
| `PRE-UNICODE-002` | Zero-width/format characters present |
| `PRE-UNICODE-003` | Mixed-script/confusable characters |
| `PRE-COMMENT-001` | Suspicious comment trust suffix (`# safe`, `# approved`) |
| `PRE-TRUST-001` | Trust label near risky operation |
| `PRE-INSTRUCT-001` | Scorer-targeting instruction detected |

Hard blocks (always fail-closed): `PRE-SIZE-001`, `PRE-DEPTH-001`, `PRE-NUM-001`.

---

### `core/rules_engine.py` & `core/jail.py` - Layer 1: Deterministic Safe Zones and Rules

McpVanguard's first layer of defense has evolved from pure regex matching to deterministic path-boundary checks plus static signatures.

**1. Safe Zones (`safe_zones.yaml`)**
Before inspecting payload strings, Vanguard intercepts configured path-based tool calls such as `read_file` or `write_file` and resolves the requested path against operator-defined prefixes.

Safe zones are an application-layer perimeter. They are designed to stop common path traversal, symlink, and sensitive-path mistakes before upstream execution, but they should be deployed alongside normal OS, container, and cloud isolation controls. See [SAFE_ZONES.md](SAFE_ZONES.md) for tuning guidance.

**2. Static Signature Rules (`rules/*.yaml`)**
If a request is within bounds, or has no specific Safe Zone defined, it falls back to the static rule layer. Contains **50+ signatures** across 5 categories.

**Rule Categories:**
- `rules/filesystem.yaml` - null bytes, Unix/Windows sensitive paths
- `rules/commands.yaml` - shell injection, dangerous commands (`rm -rf`, `curl | bash`, etc.)
- `rules/network.yaml` - exfiltration patterns (data sent to external IPs)
- `rules/jailbreak.yaml` - known prompt injection strings
- `rules/privilege.yaml` - privilege escalation patterns
- `rules/strict_overlay.yaml` - strict-profile-only rules (anti-forensics, SSRF, container escape, supply-chain, encoded execution, credential stores)
---

### `core/camouflage.py` — Layer 1.5: Trust-Signal and Semantic Camouflage Detector

Detects cases where attacker-controlled text attempts to attach benign authority to a risky operation, or manipulate downstream semantic scorers.

**Detection families:**
- **Comment trust labels:** `# safe`, `# harmless`, `# approved`, `# maintenance`, `# test`, `# admin approved`
- **Multilingual trust labels:** sécurisé, seguro, sicher, 安全, безопасно
- **Scorer manipulation:** `rate as safe`, `score this as 1`, `disregard all instructions`
- **Authority laundering:** `authorized auditor`, `security researcher`, `admin verified`

**Profile behavior:**
- `strict`: BLOCK dangerous operation + high-confidence camouflage
- `balanced`: WARN dangerous operation + trust-signal camouflage
- `monitor`: audit only

---

### `core/semantic.py` — Layer 2: Semantic Scoring Advisor

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

**Role:** L2 is an escalation-only semantic advisor, not the sole security authority. It scores ambiguous cases and may raise severity, including producing a block when enabled, but it **cannot override or downgrade** a deterministic block from L0, L1, or L1.5. In strict profile, parse failures, timeouts, and empty responses are treated as fail-closed (block).

**Action thresholds (balanced profile):**
- `0.0 – 0.5` → ALLOW
- `0.5 – 0.8` → WARN + LOG
- `0.8 – 1.0` → BLOCK

**Structured context:** The semantic scorer receives the normalized tool call plus annotations from L0 preflight findings, L1.5 camouflage findings, and L1 rule warnings. This prevents the scorer from being misled by comment text or camouflage.

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

**State storage:** In-memory `defaultdict(deque)` for single-node. Backed by **Redis** for persistent cluster-wide behavioral session history and analysis. Per-session budgets for tool-call rate, risky decisions, and blocked attempts are tracked per `(session_id, server_id)` as opt-in process-local circuit breakers. Atomic Redis/Lua budget counters remain a deferred hardening item for high-concurrency multi-replica deployments.

---

### `core/profiles.py` — Product Profiles

Named deployment presets that make the "strict product path" real instead of ad hoc environment-variable combinations.

| Profile | Mode | Semantic | Behavioral | Enumeration | Default Policy |
|---|---|---|---|---|---|
| `monitor` | audit | disabled | enabled | off | ALLOW |
| `balanced` | enforce | disabled* | enabled | off | ALLOW |
| `strict` | enforce | enabled | enabled | on | ALLOW |

*Semantic is disabled by default in balanced unless an explicit backend is configured.

**Resolution order:** Explicit env vars → profile defaults → built-in hard-coded defaults. This means `VANGUARD_SEMANTIC_ENABLED=false` will override even the strict profile's default of `true`.

---

### `core/policy.py` — Final Policy Composer

Replaces implicit layer ordering with an explainable final verdict. Composes results from all layers and the active profile into a single `PolicyVerdict`.

**Actions:** `ALLOW`, `WARN`, `REVIEW`, `SHADOW-BLOCK`, `BLOCK`

**Invariant:** No later layer can silently downgrade an earlier block. L2 semantic scoring may raise severity or add context, but cannot convert a deterministic block to allow. Monitor/audit mode may forward would-block traffic, but preserves the original would-block verdict in audit logs.

**REVIEW action:** The policy composer can represent an explicit `REVIEW` result and deliver a minimal signed webhook payload when `VANGUARD_REVIEW_WEBHOOK_URL` is configured. Built-in deterministic rules do not currently downgrade blocks to REVIEW automatically, and the webhook is not a synchronous approval queue. Strict mode escalates explicit REVIEW results to BLOCK.

---

### `core/management.py` — Native Management Plane

Native Vanguard tools are separated from normal upstream MCP tools and are hidden unless `VANGUARD_MANAGEMENT_TOOLS_ENABLED=true`.

**Surfaces:**

- read-only introspection: `get_vanguard_status`, `get_vanguard_audit`, `vanguard_get_auth_stats`
- mutating operator actions: runtime rule injection, rule reload, session reset, auth-cache flush/refresh
- local/dev-only mode: `same_session_dev`, which exposes mutating controls inside the governed MCP session and prints a warning

**Modes:**

- `disabled`: default; no native management tools are exposed
- `same_session_dev`: local/dev workflows only
- `operator_only`: mutating tools require an admin role or `vanguard:admin` / `scope:admin` scope

The proxy filters exposed management tools by mode and principal. Management actions are logged through `vanguard.management`; denied attempts and successful mutations are also sent to the risk engine.

---

### `core/receipts.py` — Optional Runtime Evidence Receipts

When `VANGUARD_RECEIPTS_ENABLED=true`, the proxy writes a dedicated `receipt_v1` JSONL stream for `mcp-receipt`. This stream is separate from the operator audit log and is designed for offline verification after export/signing.

The v0.1 contract currently covers tool-call request decisions. Each event includes policy profile, raw/effective policy action, normalized decision, findings, risk/semantic scores, and canonical hashes for the original and normalized request payloads. Raw tool arguments are not embedded in the receipt event.

By default, the JSONL stream is unsigned and unchained. Operators can enable local hash chaining with `VANGUARD_RECEIPT_CHAIN_ENABLED=true`, which adds `prev_receipt_hash`, `receipt_sequence`, and `receipt_hash` fields for deletion/reordering/mutation detection before export. This is still not a substitute for export/signing with `mcp-receipt` or downstream anchoring.

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
