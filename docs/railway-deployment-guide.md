# Deploying McpVanguard on Railway

McpVanguard is a real-time security gateway for the Model Context Protocol (MCP). Deploying it on Railway gives you a managed, cloud-native gateway that intercepts and blocks malicious AI agent tool calls before they reach your infrastructure.

## One-Click Deployment

Deploy the full McpVanguard stack in one click:

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/mcpvanguard?referralCode=4AXmAG&utm_medium=integration&utm_source=template&utm_campaign=generic)

## Prerequisites

- A [Railway Account](https://railway.app/)
- The MCP server command you want to protect (e.g., `npx @modelcontextprotocol/server-filesystem /app/data`)
- *(Optional)* `receipt_v1` JSONL emission for offline-verifiable runtime evidence with `mcp-receipt`

---

## Step-by-Step Configuration

### 1. Required Variables

You **must** set the following variables for McpVanguard to start successfully:

| Variable | Description |
|----------|-------------|
| `MCP_SERVER_COMMAND` | The MCP server command Vanguard will wrap and protect. e.g. `npx @modelcontextprotocol/server-filesystem /app/data` |
| `VANGUARD_API_KEY` | A secret key to protect your SSE endpoint. Clients must send this in the `X-Api-Key` header. Generate a strong random string. Required for public `strict` deployments. |
| `VANGUARD_PROFILE` | `balanced` | Set to `monitor` for audit-only discovery or `strict` for production-sensitive systems. |
| `VANGUARD_MODE` | `enforce` | Optional lower-level mode. Set to `audit` for shadow-mode evaluation if you are not using the `monitor` profile. |

### Safe Railway Baseline

Railway services receive a public URL, so treat the gateway as hosted by default:

- use `balanced` while validating traffic and safe-zone tuning
- set `VANGUARD_API_KEY` before exposing the service to real clients
- switch to `strict` for production-sensitive systems only after auth, safe zones, and expected benign workflows have been validated
- add `VANGUARD_ALLOWED_ORIGINS` when browser clients are expected; in `strict`, configured origins are required on incoming browser requests

In `strict`, McpVanguard refuses to start on Railway's public bind path unless API-key auth or OAuth/JWKS auth is configured. Startup logs also include a hosted posture summary showing profile, bind scope, auth state, origin policy, claim policy, session binding, and Redis/shared-state status.

### 2. Security & AI Intelligence (Optional)

Fine-tune the behavior of the security engine and connect your AI brain:

| Variable | Default | Description |
|----------|---------|-------------|
| `VANGUARD_LOG_LEVEL` | `INFO` | Logging verbosity. Set to `DEBUG` for full request traces. |
| `VANGUARD_AUDIT_FORMAT` | `text` | Choose `json` for direct ingestion into SIEM tools like ELK or Splunk. |
| `VANGUARD_SEMANTIC_ENABLED` | `true` | Enable Layer 2 semantic intent scoring. |
| `VANGUARD_SEMANTIC_CUSTOM_URL`| - | Use any OpenAI-compatible backend (DeepSeek, Groq, Mistral, vLLM). |
| `VANGUARD_SEMANTIC_CUSTOM_KEY`| - | Your API key for the custom provider. |
| `VANGUARD_SEMANTIC_CUSTOM_MODEL`| - | e.g., `deepseek-chat` or `llama3-70b-8192`. |
| `VANGUARD_EXPOSE_BLOCK_REASON` | `false` | Set to `true` to include detailed block reasons in JSON-RPC error responses. |
| `VANGUARD_SEMANTIC_THRESHOLD_BLOCK` | `0.8` | Semantic scoring threshold above which a request is blocked. |
| `VANGUARD_SEMANTIC_THRESHOLD_WARN` | `0.5` | Semantic scoring threshold above which a request is flagged as a warning. |
| `VANGUARD_MAX_STRING_LEN` | `65536` | Protection against ReDoS/Memory exhaustion. Strings longer than this are truncated before inspection. |

### When To Use Local Semantic Mode

If your deployment handles regulated data, needs low-latency local development, or must stay air-gapped, prefer a local or private OpenAI-compatible backend instead of a public API. The recommended profiles are documented in [docs/LOCAL_SEMANTIC_MODE.md](LOCAL_SEMANTIC_MODE.md).

### Operator Warnings

- Semantic model quality can drift over time after backend upgrades.
- Thresholds tuned on the benchmark corpora can still produce long-tail false positives in production.
- If you change the backend or threshold profile, rerun the adversarial and false-positive corpora before promoting the change.

### 3. Layer 3: Behavioral Analysis & Entropy Governor (Optional)

McpVanguard tracks per-session patterns to detect anomalous agent behavior and calculates Shannon Entropy to detect data exfiltration.

| Variable | Default | Description |
|----------|---------|-------------|
| `VANGUARD_BEHAVIORAL_ENABLED` | `true` | Enable/disable Layer 3 behavioral analysis. |
| `VANGUARD_BEH_READ_LIMIT` | `50` | Maximum `read_file` calls per session before flagging. |
| `VANGUARD_BEH_LIST_LIMIT` | `20` | Maximum `list_dir` calls per session before flagging. |
| `VANGUARD_ENTROPY_HIGH` | `6.0` | $H(X)$ Threshold to apply a massive virtual rate limit penalty to the session. |
| `VANGUARD_ENTROPY_BLOCK` | `7.5` | $H(X)$ Threshold to immediately block a tool call (likely cryptographic keys/compressed data). |
| `VANGUARD_THROTTLE_ENABLED` | `true` | Enable hard 1 byte/sec throttle when entropy bucket is empty. |

### 4. Horizontal Scaling: Redis (Optional)

By default, McpVanguard stores behavioral session state in-memory. This works perfectly for single-replica deployments (the default).

If you need **multiple replicas** for high-availability, add an official Railway **Redis** service to your project. McpVanguard will automatically detect `VANGUARD_REDIS_URL` and share session state across all instances.

| Variable | Description |
|----------|-------------|
| `VANGUARD_REDIS_URL` | Auto-injected by Railway when you add a Redis service. Enables distributed session tracking across replicas. |

### 5. Runtime Receipts (Optional)

For offline-verifiable runtime evidence, enable McpVanguard's dedicated `receipt_v1` JSONL stream. This stream is separate from the human/SIEM audit log and is intended to be exported, signed, and verified by the standalone `mcp-receipt` tooling.

| Variable | Description |
|----------|-------------|
| `VANGUARD_RECEIPTS_ENABLED` | Set to `true` to emit `receipt_v1` events. Disabled by default. |
| `VANGUARD_RECEIPT_LOG_FILE` | Path for the JSONL receipt stream, e.g. `/var/log/vanguard/receipts.jsonl`. |
| `VANGUARD_RECEIPT_REDACTION_MODE` | Redaction mode for receipt emission. Defaults to `partial`. |

The receipt stream contains canonical request hashes, normalized-message hashes, policy decisions, profile metadata, rule findings, and runtime context. Raw tool arguments are not embedded in the receipt event.

---

## Verifying Your Deployment

Once deployed, Railway assigns you a public URL (e.g., `https://mcpvanguard-yourproject.up.railway.app`).

Verify the service is running:
```bash
curl https://your-project.up.railway.app/health
# Expected: {
#   "status": "ok",
#   "version": "2.1.x",
#   "layers": {"l1_rules": "ok", "l2_semantic": "ok", "l3_behavioral": "ok"},
#   "timestamp": 1711022400.0
# }
```

---

## Connecting Your AI Agent

To connect an AI agent (Claude Desktop, LangChain, OpenAI Agents, etc.) to your Railway deployment:

```json
{
  "mcpServers": {
    "vanguard-remote": {
      "url": "https://your-project.up.railway.app/sse",
      "headers": {
        "X-Api-Key": "your-vanguard-api-key"
      }
    }
  }
}
```

Every tool call the agent makes will be intercepted, inspected, and either allowed or blocked by Vanguard before it reaches your MCP server.

---

## Advanced: External Evidence Backend

McpVanguard can also forward blocked-call evidence to an external evidence backend when `VANGUARD_VEX_URL` and `VANGUARD_VEX_KEY` are configured. Treat this as an optional integration path rather than a requirement for the Railway template.

```
[AI Agent (Vercel / OpenAI)] 
    -> [McpVanguard on Railway] - inspects and enforces MCP tool-call policy
        -> [External evidence backend] - optionally records submitted audit evidence
```

The repository includes a Railway-focused integration harness for this topology. Treat its results as environment-specific evidence, not a latency or audit-finality guarantee. See the [certification harness](https://github.com/provnai/McpVanguard/blob/main/tests/benchmarks/railway_cloud_certification.py) for the exact scenarios.

**To set it up:**
1. Deploy or configure your evidence backend separately.
2. Copy its public URL from your Railway dashboard or provider console.
3. Set `VANGUARD_VEX_URL` on your McpVanguard service to that URL.
4. Set `VANGUARD_VEX_KEY` to the backend credential expected by that deployment.

The external evidence backend receives submitted blocked-call evidence while Vanguard performs local policy blocking at the edge.

---

## Health Verification

The instance is pre-configured with a `/health` endpoint:

```bash
GET /health
-> {
  "status": "ok",
  "version": "2.1.2",
  "layers": {"l1_rules": "ok", "l2_semantic": "ok", "l3_behavioral": "ok"},
  "timestamp": 1711022400.0
}
```

Railway uses this for readiness checks during deployment orchestration.

---

## Support

- [Open an Issue](https://github.com/provnai/McpVanguard/issues)
- [Full Documentation](https://github.com/provnai/McpVanguard)
- [Provnai Research Initiative](https://provnai.com)
- [Runtime receipts](DEPLOYMENT.md#runtime-receipts-for-mcp-receipt)
