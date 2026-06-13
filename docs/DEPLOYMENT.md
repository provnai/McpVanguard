# McpVanguard - Deployment Guide
**Release target**: `2.1.x` runtime hardening patch line.

After the GitHub release and PyPI publication are complete, this document applies to the published `2.1.x` line.

McpVanguard is a security gateway that sits between your AI agents (LangChain, CrewAI, Claude Desktop) and your MCP servers.

It adds a layered enforcement path - L0 preflight normalization, L1 deterministic Safe Zones and rules, L1.5 camouflage detection, L2 semantic scoring (escalation-only advisor), and L3 behavioral analysis - without requiring any changes to your existing agent or server code.

**Product profiles** control how aggressively each layer enforces:
- `monitor` — audit-only discovery; logs violations but forwards traffic
- `balanced` — default OSS behavior; blocks high-confidence threats, warns on ambiguity
- `strict` — production hardening; enables all layers, fail-closed semantic, blocks enumeration

This guide covers how to deploy Vanguard in different environments.

### Install Modes

The base package keeps Redis and Google RE2 optional so local users can install quickly while hosted operators can opt into the stronger deployment stack they need.

```bash
# Base local/gateway install
pip install mcp-vanguard

# Redis-backed L3 state for multi-instance deployments
pip install "mcp-vanguard[redis]"

# RE2-backed regex engine where the wheel is available
pip install "mcp-vanguard[re2]"

# Full hosted/deployment extra set
pip install "mcp-vanguard[full]"
```

If `google-re2` is unavailable, McpVanguard falls back to Python `re` with the existing timeout-based rule-evaluation protections. If Redis is not installed or `VANGUARD_REDIS_URL` is not set, L3 behavioral state remains in memory and is single-instance only.

### 0. Define Your Safe Zones (L1 Perimeter)
Before deploying, define exact directory bounds for your MCP tools in `rules/safe_zones.yaml`. Vanguard applies deterministic path-boundary checks before upstream execution; it should be paired with normal OS, container, or cloud isolation for production workloads. See [SAFE_ZONES.md](SAFE_ZONES.md) for tuning guidance.

Vanguard is transport-agnostic and supports two main deployment modes:
1.  **Local Stdio Mode**: For CLI-based agents running on the same machine.
2.  **Cloud SSE Mode**: For remote agents connecting over the internet (Railway/Docker).

### Interception Flow (Stdio):
`Agent Process` <-> (`stdio`) <-> **`McpVanguard`** <-> (`stdio`) <-> `MCP Server Process`

### Interception Flow (SSE):
`Remote Agent` <-> (`HTTPS/SSE`) <-> **`McpVanguard (SSE Bridge)`** <-> (`stdio`) <-> `MCP Server Process`

Because Vanguard communicates via JSON-RPC 2.0 over `stdin`/`stdout`, your agent believes it is talking directly to the server.

### 1. Profile-Aware Deployment

Choose a profile before starting. The profile determines default enforcement behavior, semantic enablement, and behavioral settings.

```bash
# Monitor mode — audit only, good for initial evaluation
vanguard start --profile monitor --server "npx -y @modelcontextprotocol/server-filesystem /var/data"

# Balanced mode — default OSS behavior (recommended for developers)
vanguard start --profile balanced --server "npx -y @modelcontextprotocol/server-filesystem /var/data"

# Strict mode — full hardening (recommended for production-sensitive systems)
vanguard start --profile strict --server "npx -y @modelcontextprotocol/server-filesystem /var/data"
```

Environment variables override profile defaults:
```bash
VANGUARD_PROFILE=strict VANGUARD_SEMANTIC_ENABLED=false vanguard start ...
```
This runs strict profile but disables semantic scoring (useful if no backend is available).

### 2. Local Stdio Mode

To wrap a local MCP server, use the `start` command:

```bash
vanguard start --profile balanced --server "npx -y @modelcontextprotocol/server-filesystem /var/data"
```

### 3. Cloud SSE Mode (Gateway)

To expose Vanguard as an internet-reachable security gateway (e.g., on Railway), use the `sse` command:

```bash
vanguard sse --profile balanced --server "npx -y @modelcontextprotocol/server-filesystem /var/data" --port 8080
```

### Safe Hosted Baseline

For public or non-loopback bindings such as `0.0.0.0`, treat transport authentication as mandatory.

```bash
export VANGUARD_API_KEY="your-long-random-secret"
vanguard sse --profile strict --host 0.0.0.0 --port 8080 --server "npx -y @modelcontextprotocol/server-filesystem /var/data"
```

`strict` profile is deployment-safe by default on hosted transports:

- non-loopback startup fails closed unless `VANGUARD_API_KEY` or OAuth/JWKS auth is configured
- bearer claim-policy mismatches default to `block`
- `Origin` is required when `VANGUARD_ALLOWED_ORIGINS` is configured
- Streamable HTTP session binding, request rate limits, concurrency caps, and session caps remain enabled by default
- optional per-session budgets can circuit-break sessions that exceed tool-call, risky-call, or blocked-attempt limits
- startup prints a hosted posture summary with profile, bind scope, auth mode, origin policy, claim policy, session binding, and Redis/shared-state status

`balanced` profile remains usable for demos and staged rollouts. It will still start on a public bind without auth, but prints a loud warning so operators can discover unsafe deployments without breaking local experimentation.

**Staged rollout recommendation:**
1. **Week 1-2:** Deploy `monitor` profile. Review audit logs to understand your traffic patterns.
2. **Week 3-4:** Switch to `balanced` profile. Fix any false positives that block benign developer workflows.
3. **Month 2+:** For sensitive production agents, switch to `strict` profile. Ensure Redis is configured for multi-instance behavioral state.

When tuning false positives, use the structured `policy_explanation` field in JSON audit logs. It records the primary layer, rule family, raw/effective policy action, whether the upstream server was called, and an operator hint. See [BLOCK_DECISIONS.md](BLOCK_DECISIONS.md).

### Capability-Aware Behavioral Tracking

Layer 3 classifies tool calls into coarse capabilities such as `filesystem_read`, `filesystem_write`, `shell_exec`, `network_request`, `database_query`, `browser_automation`, `credential_adjacent`, and `metadata_sensitive`. This helps behavioral detectors catch renamed tools such as `fetch_document` or `save_document` instead of relying only on literal names like `read_file`.

Capability inference is heuristic unless you provide an explicit override:

```bash
export VANGUARD_TOOL_CAPABILITIES_JSON='{"company_fetch": ["filesystem_read"], "company_save": ["filesystem_write"]}'
```

Use overrides when your MCP server uses domain-specific tool names. Unknown capabilities are recorded as `unknown` and do not create stronger balanced-profile blocking by default.

Repeated `network_request` capability calls produce a Layer 3 WARN/risk signal rather than a default block. Tune the threshold with:

```bash
export VANGUARD_BEH_NETWORK_LIMIT=30
```

### Per-Session Budgets

Per-session budgets are opt-in circuit breakers for deployments that want hard limits around repeated activity. They are tracked per `(session_id, server_id)` so one upstream server cannot consume another server's budget.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `VANGUARD_MAX_TOOL_CALLS_PER_MINUTE` | `0` | Maximum `tools/call` requests per session/server in a rolling 60-second window. `0` disables the budget. |
| `VANGUARD_MAX_RISKY_CALLS_PER_SESSION` | `0` | Maximum WARN/REVIEW/SHADOW-BLOCK/BLOCK decisions per session/server before later risky calls are blocked. `0` disables the budget. |
| `VANGUARD_MAX_BLOCKED_ATTEMPTS_PER_SESSION` | `0` | Maximum BLOCK/SHADOW-BLOCK decisions per session/server before the session is circuit-broken and later tool calls are blocked. `0` disables the budget. |

Budget blocks use deterministic rule IDs:

- `VANGUARD-BUDGET-001`: tool calls per minute exceeded
- `VANGUARD-BUDGET-002`: risky calls per session exceeded
- `VANGUARD-BUDGET-003`: blocked attempts per session exceeded

Recommended hosted starting point:

```bash
export VANGUARD_MAX_TOOL_CALLS_PER_MINUTE=120
export VANGUARD_MAX_RISKY_CALLS_PER_SESSION=10
export VANGUARD_MAX_BLOCKED_ATTEMPTS_PER_SESSION=3
```

Tune these limits in `monitor` or `balanced` before enforcing in `strict`. High-volume automation, crawling, migrations, and incident-response workflows may need higher limits or narrower safe-zone/profile tuning.

### Redis And Shared State

If `VANGUARD_REDIS_URL` is unset, behavioral state, risk state, and session-budget state are process-local. This is suitable for local development, single-process demos, and single-replica deployments.

For hosted multi-replica deployments, configure Redis so L3 behavioral state and session tracking can be shared across instances. Without Redis, each replica only sees the traffic it handles.

Current Redis-backed L3 state is suitable for shared behavioral visibility, but risk-engine state and session-budget counters are still process-local. Atomic Redis/Lua budget counters are a deferred hardening item. For strict, high-concurrency hosted deployments, validate limits under realistic concurrency before relying on budgets as the only abuse-control layer.

For private-network MCP servers exposed through Anthropic MCP tunnels, route the tunnel to McpVanguard first and then forward to the private upstream MCP server. Tunnels reduce network exposure. McpVanguard enforces the execution boundary. See [ANTHROPIC_MCP_TUNNELS.md](ANTHROPIC_MCP_TUNNELS.md).

McpVanguard is tracking the MCP 2026-07-28 release candidate. The current `2.1.x` line includes additive routing-header consistency checks when `Mcp-Method` / `Mcp-Name` are present and treats request `_meta` as security-relevant input. See [MCP_2026_07_28_RC_COMPATIBILITY.md](MCP_2026_07_28_RC_COMPATIBILITY.md).

## 2. L2 Semantic Scalability (Cloud LLM Integration)

Running local LLMs (like Ollama) for Vanguard's L2 Semantic Intelligence is great for absolute privacy, but difficult to scale across thousands of concurrent agent sessions.

Vanguard supports cloud LLM backends for remote, high-throughput semantic scoring. Provider priority: **Universal Custom > OpenAI > MiniMax > Ollama** (first available API key wins).

For a local or offline setup, see [docs/LOCAL_SEMANTIC_MODE.md](LOCAL_SEMANTIC_MODE.md).

### When To Use Local Semantic Mode

Use local or offline semantic scoring when you care most about:

- regulated or sensitive data paths
- low-latency local development
- air-gapped labs or isolated staging
- keeping prompts and tool-call context off third-party APIs

If your team cannot reliably operate the model runtime, a trusted hosted OpenAI-compatible backend is usually the better first step.

For practical defaults and recommended operator profiles, see [docs/LOCAL_SEMANTIC_MODE.md](LOCAL_SEMANTIC_MODE.md).

**Universal Custom Provider (e.g. DeepSeek, Groq):**
```bash
export VANGUARD_SEMANTIC_ENABLED=true
export VANGUARD_SEMANTIC_CUSTOM_KEY="your-api-key"
export VANGUARD_SEMANTIC_CUSTOM_MODEL="deepseek-chat"
export VANGUARD_SEMANTIC_CUSTOM_URL="https://api.deepseek.com/v1"
```

**OpenAI Configuration:**
```bash
export VANGUARD_SEMANTIC_ENABLED=true
export VANGUARD_OPENAI_API_KEY="sk-..."
export VANGUARD_OPENAI_MODEL="gpt-4o-mini"
```

**MiniMax Configuration:**
```bash
export VANGUARD_SEMANTIC_ENABLED=true
export VANGUARD_MINIMAX_API_KEY="your-minimax-key"
export VANGUARD_MINIMAX_MODEL="MiniMax-M2.5"
```

> MiniMax provides an OpenAI-compatible API. See [MiniMax API docs](https://platform.minimax.io/docs/api-reference/text-openai-api) for details.

**Ollama Configuration:**
```bash
export VANGUARD_SEMANTIC_ENABLED=true
export VANGUARD_OLLAMA_URL="http://localhost:11434"
export VANGUARD_OLLAMA_MODEL="phi4-mini"
```

**Local OpenAI-Compatible Server (LM Studio, llama.cpp, etc.):**
```bash
export VANGUARD_SEMANTIC_ENABLED=true
export VANGUARD_SEMANTIC_CUSTOM_URL="http://127.0.0.1:1234/v1"
export VANGUARD_SEMANTIC_CUSTOM_MODEL="your-local-model"
export VANGUARD_SEMANTIC_CUSTOM_KEY="local-placeholder"
```

## 3. L3 Horizontal Scaling (Redis State Management)

Vanguard's L3 Behavioral Engine tracks sliding windows of agent activity (e.g., detecting if an agent calls `read_file` 50 times in 10 seconds).

By default, this is stored in RAM. If you are load-balancing multiple Vanguard instances, you **must** use Redis so that state is shared across instances.

**Configuration:**
```bash
export VANGUARD_BEHAVIORAL_ENABLED=true
export VANGUARD_REDIS_URL="redis://your-elasticache-endpoint:6379/0"

# Optional: Adjust Shannon Entropy thresholds for exfiltration detection
export VANGUARD_ENTROPY_HIGH="6.0"    # Triggers massive rate-limit penalty
export VANGUARD_ENTROPY_BLOCK="7.5"   # Immediate block (likely encryption keys)
```

*When the Redis URL is provided, Vanguard uses Redis-backed behavioral state for shared tracking across instances. The exact storage strategy is implementation-specific and may evolve.*

> [!IMPORTANT]
> **PRODUCTION REQUIREMENT**: For horizontal scaling or persistent behavioral state across restarts, Redis is **required**. Without Redis, Vanguard uses in-memory state which is lost on restart and not shared across instances, potentially allowing multi-turn horizontal bypasses.

## 4. The VEX + CHORA Integration (Flight Recorder)

When Vanguard blocks an agent's tool call, it can optionally forward the payload to VEX for immutable audit recording.

Vanguard integrates asynchronously with the **VEX API**. Whenever an action is blocked, Vanguard can send the payload to the VEX server for downstream hashing, anchoring, and evidence receipt workflows.

**Configuration:**
```bash
export VANGUARD_VEX_URL="https://api.vexprotocol.com"
export VANGUARD_VEX_KEY="your-vex-api-jwt"
```

## 5. Audit Logging & Rotation

Vanguard logs every blocked, warned, and allowed request.
Logs are automatically rotated when they reach 10MB to prevent disk exhaustion (keeping the 5 most recent backups).

**Configuration:**
```bash
export VANGUARD_LOG_FILE="/var/log/vanguard/audit.log"
export VANGUARD_AUDIT_FORMAT="json" # Set to 'json' for SIEM ingest (Elastic, Splunk)
```

JSON audit logs include `policy_explanation` for inspected requests. This field is intended for operators and SIEM pipelines; agent-facing error messages remain intentionally brief unless `VANGUARD_EXPOSE_BLOCK_REASON=true` is set.

### Management Plane Separation

Native Vanguard management tools are not part of the normal product surface unless explicitly enabled:

```bash
export VANGUARD_MANAGEMENT_TOOLS_ENABLED=true
export VANGUARD_MANAGEMENT_PLANE_MODE=operator_only
```

Supported management-plane modes:

- `disabled`: default; native management tools are not exposed and calls fail closed
- `same_session_dev`: local/dev only; exposes read and mutating tools in the governed MCP session and prints a startup warning
- `operator_only`: exposes read-only tools broadly but exposes/permits mutating tools only when the caller has an admin role or `vanguard:admin` / `scope:admin` scope

Production guidance:

- Keep `VANGUARD_MANAGEMENT_TOOLS_ENABLED=false` for ordinary governed agent sessions.
- Use `operator_only` only when the transport/auth layer reliably supplies operator identity and scopes.
- Prefer CLI/operator workflows such as signed rule updates, baseline bundle generation, server verification, and capability verification for production maintenance.
- Every management action is logged through the management logger; denied and successful mutating actions are also recorded in the risk engine.

### Runtime Receipts For mcp-receipt

McpVanguard can optionally emit a dedicated `receipt_v1` JSONL stream for the standalone `mcp-receipt` verifier. This is separate from the human/SIEM audit log and is disabled by default.

```bash
export VANGUARD_RECEIPTS_ENABLED=true
export VANGUARD_RECEIPT_LOG_FILE="/var/log/vanguard/receipts.jsonl"
export VANGUARD_RECEIPT_REDACTION_MODE="partial"
# Optional local tamper-evidence before export/signing
export VANGUARD_RECEIPT_CHAIN_ENABLED=true
# Optional McpVanguard extension hashes/capability labels
export VANGUARD_RECEIPT_EXTENSIONS_ENABLED=true
```

The receipt stream contains canonical request hashes, normalized-message hashes, policy decisions, profile metadata, rule findings, and runtime context. It does not write raw tool arguments into the receipt event. Use `mcp-receipt` to export, sign, and verify these events offline.

Important evidence boundaries:

- Raw JSONL receipts are not signed evidence by themselves.
- `VANGUARD_RECEIPT_CHAIN_ENABLED=true` adds `prev_receipt_hash`, `receipt_sequence`, and `receipt_hash` fields so local deletion, reordering, and mutation can be detected before export.
- Receipt chaining is local tamper evidence, not a substitute for signing or external anchoring.
- `VANGUARD_RECEIPT_EXTENSIONS_ENABLED=true` adds McpVanguard extension metadata such as policy-explanation hashes and tool-capability labels without embedding full raw policy explanations.
- `receipt_v1` currently records request-side tool-call decisions. `response_hash` remains reserved/nullable unless response-side receipt support is explicitly added in a future schema.
- ProvnCloud/VEX anchoring can prove that a signed/exported evidence packet existed at an anchoring time; it does not prove the underlying host was uncompromised or that an unsigned local JSONL file was complete before export.

Retention and rotation guidance:

- Treat receipt JSONL files as append-only evidence buffers.
- Rotate by closing the current file, exporting/signing it with `mcp-receipt`, then starting a new file.
- Do not edit chained receipt files in place; edits break `receipt_hash` verification.
- If a chained stream is restarted after appending to an older unchained file, McpVanguard marks the new chained record with `chain_restart=true`.
- Keep retention policy aligned with your audit/SIEM requirements; McpVanguard does not currently delete receipt files automatically.

## Summary

With these environment variables configured, Vanguard can intercept threats via static rules, semantically score complex payloads via OpenAI/MiniMax/Ollama, track behavior via Redis, and log defense actions for operational review.

Before promoting a profile change, run the packaged benchmark corpora and interpret the results using [BENCHMARKS.md](BENCHMARKS.md).

### Operator Warnings For Semantic Mode

- Local model quality can drift after backend or model upgrades.
- Thresholds that look good on the benchmark corpora can still produce long-tail false positives in production.
- Semantic scoring adds latency and can block when enabled; keep timeout and fail-closed behavior aligned with your deployment goals.
- If you change the backend or threshold profile, rerun the adversarial and false-positive corpora before promoting the change.

---

## 6. SSE Authentication

When running `vanguard sse` in a public-facing deployment, protect your endpoint with an API key:

```bash
export VANGUARD_API_KEY="your-long-random-secret"
```

Clients must send the key in every request:
```http
X-Api-Key: your-long-random-secret
# or
Authorization: Bearer your-long-random-secret
```

The `/health` endpoint is exempt and always accessible for Railway/cloud health-checks.

In `strict` profile, public/non-loopback binds refuse to start unless API-key auth or OAuth/JWKS auth is configured. For OAuth/JWKS deployments, set `VANGUARD_AUTH_MODE=oauth` and provide one of `VANGUARD_JWKS_FILE`, `VANGUARD_JWKS_JSON`, `VANGUARD_JWKS_URL`, or `VANGUARD_OAUTH_DISCOVERY_URL`.

> **Deep Health Probes**: The `/health` endpoint performs live connectivity checks against Redis and the configured Semantic LLM backend, returning a `200 OK` only if all critical layers are accessible. It falls back to `503 Service Unavailable` if dependencies fail, enabling Railway to safely kill unresponsive containers during a rolling deploy.

---

## 7. Advanced / Debug Options

| Variable | Default | Description |
| :--- | :--- | :--- |
| `VANGUARD_SESSION_TTL` | `86400` | Session expiry in seconds (24h). Stale sessions are auto-evicted. |
| `VANGUARD_MAX_STREAMABLE_SESSIONS` | `100` | Maximum active Streamable HTTP `/mcp` sessions per process. |
| `VANGUARD_EXPOSE_BLOCK_REASON` | `false` | Set to `true` to include detailed block reasons in JSON-RPC error responses. Off by default to avoid leaking rule internals to agents. |
| `VANGUARD_MAX_TOOL_CALLS_PER_MINUTE` | `0` | Optional per-session/server rolling tool-call rate budget. |
| `VANGUARD_MAX_RISKY_CALLS_PER_SESSION` | `0` | Optional per-session/server budget for WARN/REVIEW/SHADOW-BLOCK/BLOCK decisions. |
| `VANGUARD_MAX_BLOCKED_ATTEMPTS_PER_SESSION` | `0` | Optional per-session/server blocked-attempt circuit breaker. |

---

## 8. Signature Updates

Keep your threat signatures up to date by running:

```bash
vanguard update
```

This fetches the latest YAML rule files from the official `provnai/McpVanguard` repository on GitHub and overwrites your local `rules/` directory.
