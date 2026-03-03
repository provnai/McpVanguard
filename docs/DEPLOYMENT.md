# McpVanguard: Enterprise Deployment Guide

McpVanguard is designed to operate as a transparent security proxy between your AI Agents (LangChain, CrewAI, AutoGen) and your MCP application servers.

By sitting perfectly in the middle of standard `stdio` communication, Vanguard adds three powerful layers of defense—Regex, Semantic Intelligence, and Behavioral Analysis—without requiring any modifications to your existing agent code.

This guide outlines how a CISO or Infrastructure Team can deploy McpVanguard into a production environment.

Vanguard is transport-agnostic and supports two main deployment modes:
1.  **Local Stdio Mode**: For CLI-based agents running on the same machine.
2.  **Cloud SSE Mode**: For remote agents connecting over the internet (Railway/Docker).

### Interception Flow (Stdio):
`Agent Process` ↔ (`stdio`) ↔ **`McpVanguard`** ↔ (`stdio`) ↔ `MCP Server Process`

### Interception Flow (SSE):
`Remote Agent` ↔ (`HTTPS/SSE`) ↔ **`McpVanguard (SSE Bridge)`** ↔ (`stdio`) ↔ `MCP Server Process`

Because Vanguard communicates via JSON-RPC 2.0 over `stdin`/`stdout`, your agent believes it is talking directly to the server.

### 1. Local Stdio Mode

To wrap a local MCP server, use the `start` command:

```bash
vanguard start --server "npx -y @modelcontextprotocol/server-filesystem /var/data"
```

### 2. Cloud SSE Mode (Gateway)

To expose Vanguard as an internet-reachable security gateway (e.g., on Railway), use the `sse` command:

```bash
vanguard sse --server "npx -y @modelcontextprotocol/server-filesystem /var/data" --port 8080
```

## 2. L2 Semantic Scalability (OpenAI Integration)

Running local LLMs (like Ollama) for Vanguard's L2 Semantic Intelligence is great for absolute privacy, but difficult to scale across thousands of concurrent agent sessions.

Vanguard supports falling back to OpenAI's API for remote, high-throughput semantic scoring.

**Configuration:**
```bash
# Enable Semantic Layer
export VANGUARD_SEMANTIC_ENABLED=true

# Provide OpenAI Credentials (Vanguard will automatically use this instead of Ollama)
export VANGUARD_OPENAI_API_KEY="sk-..."
export VANGUARD_OPENAI_MODEL="gpt-4o-mini"
```

## 3. L3 Horizontal Scaling (Redis State Management)

Vanguard's L3 Behavioral Engine tracks sliding windows of agent activity (e.g., detecting if an agent calls `read_file` 50 times in 10 seconds).

By default, this is stored in RAM. If you are load-balancing multiple Vanguard instances, you **must** use Redis so that state is shared across instances.

**Configuration:**
```bash
export VANGUARD_BEHAVIORAL_ENABLED=true
export VANGUARD_REDIS_URL="redis://your-elasticache-endpoint:6379/0"
```

*When the Redis URL is provided, Vanguard automatically switches to using sorted sets for cluster-wide behavioral tracking.*

## 4. The VEX + CHORA Integration (Flight Recorder)

When Vanguard blocks an agent's tool call, it needs to cryptographically prove that the block was justified. 

Vanguard integrates asynchronously with the **VEX API**. Whenever an action is blocked, Vanguard fires the payload to the VEX Server. The VEX Server hashes the payload, anchors it to the Bitcoin blockchain via the CHORA Gate, and streams a verifiable `EvidenceCapsule` back to your audit logs.

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
```

## Summary

With these environment variables configured, Vanguard is ready for enterprise scale. It will intercept threats via static rules, semantically score complex payloads via OpenAI, track cluster-wide behavior via Redis, and cryptographically log all defense actions via VEX.

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

---

## 7. Advanced / Debug Options

| Variable | Default | Description |
| :--- | :--- | :--- |
| `VANGUARD_SESSION_TTL` | `86400` | Session expiry in seconds (24h). Stale sessions are auto-evicted. |
| `VANGUARD_EXPOSE_BLOCK_REASON` | `false` | Set to `true` to include detailed block reasons in JSON-RPC error responses. Off by default to avoid leaking rule internals to agents. |

---

## 8. Signature Updates

Keep your threat signatures up to date by running:

```bash
vanguard update
```

This fetches the latest YAML rule files from the official `provnai/McpVanguard` repository on GitHub and overwrites your local `rules/` directory.
