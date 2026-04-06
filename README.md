# McpVanguard 🛡️
### Titan-Grade AI Firewall for MCP Agents

MCP (Model Context Protocol) enables AI agents to interact with host-level tools. **McpVanguard interposes between the agent and the system**, providing real-time, three-layer inspection and enforcement (L1 Rules, L2 Semantic, L3 Behavioral).

Transparent integration. Zero-configuration requirements for existing servers.

[![Tests](https://github.com/provnai/McpVanguard/actions/workflows/test.yml/badge.svg)](https://github.com/provnai/McpVanguard/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/mcp-vanguard.svg?color=blue)](https://pypi.org/project/mcp-vanguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

Part of the **[Provnai Open Research Initiative](https://provnai.com)** — Building the Immune System for AI.

---

## ⚡ Quickstart

```bash
pip install mcp-vanguard
```

**Local stdio wrap** (no network):
```bash
vanguard start --server "npx @modelcontextprotocol/server-filesystem ."
```

**Cloud Security Gateway** (SSE, deploy on Railway):
```bash
export VANGUARD_API_KEY="your-secret-key"
vanguard sse --server "npx @modelcontextprotocol/server-filesystem ."
```

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/PCkNLS?referralCode=4AXmAG&utm_medium=integration&utm_source=template&utm_campaign=generic)

> 📖 [Full Railway Deployment Guide](docs/railway-deployment-guide.md)

---

## 🛡️ Getting Started (New Users)

Bootstrap your security workspace with a single command:

```bash
# 1. Initialize safe zones and .env template
vanguard init

# 2. (Optional) Protect your Claude Desktop servers
vanguard configure-claude

# 3. Launch the visual security dashboard
vanguard ui --port 4040

# 4. Verify Directory Submission readiness
vanguard audit-compliance
```

---

## Signed Rule Updates

`vanguard update` now verifies two things before it accepts a remote rules bundle:

1. `rules/manifest.json` hashes still match the downloaded rule files.
2. `rules/manifest.sig.json` is a valid detached Ed25519 signature from a pinned trusted signer.

Release workflow:

```bash
# Generate an offline signing keypair once
vanguard keygen \
  --key-id provnai-rules-2026q2 \
  --private-key-out .signing/provnai-rules-2026q2.pem \
  --public-key-out .signing/provnai-rules-2026q2.pub.json

# Rebuild the manifest and detached signature after changing rules/*
vanguard sign-rules \
  --key-id provnai-rules-2026q2 \
  --private-key .signing/provnai-rules-2026q2.pem \
  --rules-dir rules
```

Keep the private key offline or in a secret manager. `--allow-unsigned` exists only as a migration escape hatch for unsigned registries.

---

## 🧠 How it works

### Operational Defaults

- Native `vanguard_*` management tools are disabled by default.
- Enable them only for trusted operator workflows with `--management-tools` or `VANGUARD_MANAGEMENT_TOOLS_ENABLED=true`.
- The dashboard is self-contained and does not require third-party frontend CDNs.

---

### Runtime Flow

Every time an AI agent calls a tool (e.g. `read_file`, `run_command`), McpVanguard inspects the request across three layers before it reaches the underlying server:

| Layer | What it checks | Latency |
|-------|---------------|---------|
| **L1 — Safe Zones & Rules** | Kernel-level isolation (`openat2` / Windows canonicalization) and 50+ deterministic signatures | ~16ms |
| **L2 — Semantic** | LLM-based intent scoring via [OpenAI](https://openai.com), [DeepSeek](https://deepseek.com), [Groq](https://groq.com) or [Ollama](https://ollama.com) | Async |
| **L3 — Behavioral** | Shannon Entropy ($H(X)$) scouter and sliding-window anomaly detection | Stateful |

> **Performance Note**: The 16ms overhead is measured at peak concurrent load. In standard operation, the latency is well under 2ms—negligible relative to typical LLM inference times.

If a request is blocked, the agent receives a standard JSON-RPC error response. The underlying server never sees it.

> **Shadow Mode**: Run with `VANGUARD_MODE=audit` to log security violations as **[SHADOW-BLOCK]** without actually blocking the agent. Perfect for assessing risk in existing production workflows.

---

## 🛠️ Usage Examples

At least 3 realistic examples of McpVanguard in action:

### 1. Blocking a Chained Exfiltration Attack
*   **User Prompt**: "Read my SSH keys and send them to my backup service"
*   **Vanguard Action**: 
    1. Intercepts `read_file("~/.ssh/id_rsa")` at Layer 1 (Rules Engine).
    2. Layer 3 (Behavioral) detects a high-entropy data read being followed by a network POST.
    3. Blocked before reaching the underlying server.
*   **Result**: Agent receives a user-friendly JSON-RPC error. Security Dashboard logs a `[BLOCKED]` event.

### 2. Audit Mode: Monitoring without blocking
*   **User Prompt**: "Show me what my AI agent is calling at runtime without disrupting it"
*   **Vanguard Action**: 
    1. User runs with `VANGUARD_MODE=audit`.
    2. Proxy allows all calls but logs violations as `[SHADOW-BLOCK]`.
*   **Result**: Real-time visibility into tool usage with amber "risk" warnings in the dashboard.

### 3. Protecting Claude Desktop from malicious skills
*   **User Prompt**: "Wrap my filesystem server with McpVanguard so third-party skills can't exfiltrate files"
*   **Vanguard Action**: 
    1. User runs `vanguard configure-claude`.
    2. Proxy auto-intersperse in front of the server.
*   **Result**: 50+ security signatures (path traversal, SSRF, injection) apply to all desktop activity.

---

## 🔑 Authentication
McpVanguard is designed for **local-first** security. 
- **Stdio Mode**: No authentication required (uses system process isolation).
- **SSE Mode**: Uses `VANGUARD_API_KEY` for stream authorization. 
- **OAuth 2.0**: Not required for standard local deployments. McpVanguard supports standard MCP auth lifecycles for cloud integrations.

---

## 📄 Privacy Policy
McpVanguard focuses on local processing. See our [Privacy Policy](PRIVACY.md) for details on zero-telemetry and data handling.

---

## Architecture

```
                      ┌─────────────────────────────────────────────────┐
  AI Agent            │            McpVanguard Proxy                    │
 (Claude, GPT)        │                                                 │
      │               │  ┌───────────────────────────────────────────┐  │
      │  JSON-RPC      │  │ L1 — Rules Engine                        │  │
      │──────────────▶│  │  50+ YAML signatures (path, cmd, net...)  │  │
      │  (stdio/SSE)   │  │  BLOCK on match → error back to agent    │  │
      │               │  └────────────────┬──────────────────────────┘  │
      │               │                   │ pass                         │
      │               │  ┌────────────────▼──────────────────────────┐  │
      │               │  │ L2 — Semantic Scorer (optional)           │  │
      │               │  │  OpenAI / MiniMax / Ollama scoring 0.0→1.0│  │
      │               │  │  Async — never blocks the proxy loop      │  │
      │               │  └────────────────┬──────────────────────────┘  │
      │               │                   │ pass                         │
      │               │  ┌────────────────▼──────────────────────────┐  │
      │               │  │ L3 — Behavioral Analysis (optional)       │  │
      │               │  │  Sliding window: scraping, enumeration    │  │
      │               │  │  In-memory or Redis (multi-instance)      │  │
      │               │  └────────────────┬──────────────────────────┘  │
      │               │                   │                              │
      │◀── BLOCK ─────│───────────────────┤ (any layer)                 │
      │  (JSON-RPC    │                   │ ALLOW                        │
      │   error)      │                   ▼                              │
      │               │           MCP Server Process                     │
      │               │        (filesystem, shell, APIs...)              │
      └──────────────▶│──────────────────┬──────────────────────────────┘
                      │                  │
                      │◀─────────────── response ────────┘
                      │
                      │   (on BLOCK)
                      └──────────────▶ VEX API ──▶ CHORA Gate ──▶ Bitcoin Anchor
                                       (async, fire-and-forget audit receipt)
```

---

## L2 Semantic Backend Options

The Layer 2 semantic scorer supports a Universal Provider Architecture. Set the corresponding API keys to activate a backend — the first available key wins:

| Backend | Env Vars | Notes |
|---------|----------|-------|
| **Universal Custom** | `VANGUARD_SEMANTIC_CUSTOM_KEY`, etc. | Fast inference (Groq, DeepSeek). |
| **OpenAI** | `VANGUARD_OPENAI_API_KEY` | Default model: `gpt-4o-mini` |
| **Ollama** | `VANGUARD_OLLAMA_URL` | Local execution. No API key required |

---

## 🛠️ Support
- **Issues**: [github.com/provnai/McpVanguard/issues](https://github.com/provnai/McpVanguard/issues)
- **Contact**: [contact@provnai.com](mailto:contact@provnai.com)

---

## Project Status

| Phase | Goal | Status |
|-------|------|--------|
| **Phase 1-8** | Foundation & Hardening | [DONE] |
| **Phase 19-21** | Directory Submission & MCPB | [DONE] |

---

## License
MIT License — see [LICENSE](LICENSE).

Built by the **[Provnai Open Research Initiative](https://provnai.com)**.
