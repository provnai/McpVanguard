# Deploying McpVanguard on Railway 🛡️🚉

McpVanguard is a real-time AI security proxy for the Model Context Protocol (MCP). Deploying it on Railway gives you a fully managed, cloud-native security gateway that intercepts and blocks malicious AI agent tool calls before they reach your infrastructure.

## One-Click Deployment

Deploy the full McpVanguard stack in one click:

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/PCkNLS?referralCode=4AXmAG&utm_medium=integration&utm_source=template&utm_campaign=generic)

## Prerequisites

- A [Railway Account](https://railway.app/)
- The MCP server command you want to protect (e.g., `npx @modelcontextprotocol/server-filesystem /app/data`)
- *(Optional)* A [VEX Protocol](https://github.com/provnai/vex) deployment for cryptographic audit logging

---

## Step-by-Step Configuration

### 1. Required Variables

You **must** set the following variables for McpVanguard to start successfully:

| Variable | Description |
|----------|-------------|
| `MCP_SERVER_COMMAND` | The MCP server command Vanguard will wrap and protect. e.g. `npx @modelcontextprotocol/server-filesystem /app/data` |
| `VANGUARD_API_KEY` | A secret key to protect your SSE endpoint. Clients must send this in the `X-Api-Key` header. Generate a strong random string. |

### 2. Security & Proxy Settings (Optional)

Fine-tune the behavior of the security engine:

| Variable | Default | Description |
|----------|---------|-------------|
| `VANGUARD_LOG_LEVEL` | `INFO` | Logging verbosity. Set to `DEBUG` for full request traces. |
| `VANGUARD_EXPOSE_BLOCK_REASON` | `false` | Set to `true` to include detailed block reasons in JSON-RPC error responses. Leave `false` in production to avoid leaking rule internals. |
| `VANGUARD_BLOCK_THRESHOLD` | `0.8` | Semantic scoring threshold above which a request is blocked (Layer 2, requires Ollama). |
| `VANGUARD_WARN_THRESHOLD` | `0.5` | Semantic scoring threshold above which a request is flagged as a warning. |
| `VANGUARD_MAX_STRING_LEN` | `65536` | Protection against ReDoS/Memory exhaustion. Strings longer than this are truncated before inspection. |

### 3. Layer 3: Behavioral Analysis (Optional)

McpVanguard tracks per-session patterns to detect anomalous agent behavior (e.g., an agent that reads 500 files in a minute).

| Variable | Default | Description |
|----------|---------|-------------|
| `VANGUARD_BEHAVIORAL_ENABLED` | `true` | Enable/disable Layer 3 behavioral analysis. |
| `VANGUARD_BEH_READ_LIMIT` | `50` | Maximum `read_file` calls per session before flagging. |
| `VANGUARD_BEH_LIST_LIMIT` | `20` | Maximum `list_dir` calls per session before flagging. |

### 4. Horizontal Scaling: Redis (Optional)

By default, McpVanguard stores behavioral session state in-memory. This works perfectly for single-replica deployments (the default).

If you need **multiple replicas** for high-availability, add an official Railway **Redis** service to your project. McpVanguard will automatically detect `REDIS_URL` and share session state across all instances.

| Variable | Description |
|----------|-------------|
| `REDIS_URL` | Auto-injected by Railway when you add a Redis service. Enables distributed session tracking across replicas. |

### 5. VEX Protocol: Cryptographic Audit Logging (Optional)

For immutable, cryptographically anchored audit trails of every blocked attack, integrate with a [VEX Protocol](https://github.com/provnai/vex) deployment.

| Variable | Description |
|----------|-------------|
| `VANGUARD_VEX_URL` | Your VEX server URL. e.g. `https://vex-production.up.railway.app` |
| `VANGUARD_VEX_KEY` | Your VEX agent JWT for authentication. |

> 💡 You can deploy your own VEX instance alongside McpVanguard for a complete Cloud-to-Cloud security stack. See [Deploying VEX on Railway](https://github.com/provnai/vex/blob/main/docs/railway.md).

---

## Verifying Your Deployment

Once deployed, Railway assigns you a public URL (e.g., `https://mcpvanguard-yourproject.up.railway.app`).

Verify the service is running:
```bash
curl https://your-project.up.railway.app/health
# Expected: {"status": "ok", "version": "1.1.4"}
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

## Advanced: McpVanguard + VEX (Cloud-to-Cloud Topology)

The most powerful enterprise configuration runs **both** McpVanguard and VEX natively on Railway:

```
[AI Agent (Vercel / OpenAI)] 
    → [McpVanguard on Railway] — blocks attacks in <1ms
        → [VEX on Railway]    — cryptographically anchors every blocked call to Postgres
```

This topology is **Railway Partnership Certified** — validated with a 250-iteration burst test achieving 100% block rate and 100% audit finality. See the [certification report](https://github.com/provnai/McpVanguard/blob/main/tests/benchmarks/railway_cloud_certification.py) for full details.

**To set it up:**
1. Deploy [VEX on Railway](https://railway.com/deploy/N9-iqS?referralCode=4AXmAG) separately.
2. Copy the VEX public URL from your Railway dashboard.
3. Set `VANGUARD_VEX_URL` on your McpVanguard service to that URL.
4. Set `VANGUARD_VEX_KEY` to your VEX JWT.

VEX handles all the PostgreSQL logging, Merkle-tree anchoring, and CHORA evidence capsule generation remotely — while Vanguard performs fast local policy blocking at the edge.

---

## Health Checks

The template is pre-configured with a `/health` endpoint:

```bash
GET /health
→ {"status": "ok", "version": "1.1.4"}
```

Railway uses this for readiness checks before routing traffic to new deployments.

---

## Support

- 🐛 [Open an Issue](https://github.com/provnai/McpVanguard/issues)
- 📚 [Full Documentation](https://github.com/provnai/McpVanguard)
- 🌐 [Provnai Research Initiative](https://provnai.com)
- 🤝 [VEX Protocol](https://github.com/provnai/vex/blob/main/docs/railway.md)
