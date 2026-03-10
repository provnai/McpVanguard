# 🛡️ McpVanguard
### A security proxy for AI agents that use MCP

MCP (Model Context Protocol) lets AI agents like Claude or GPT call tools on your computer — reading files, running commands, browsing the web. **McpVanguard sits in between**, inspecting every tool call before it reaches your system and blocking anything that looks malicious.

No changes to your agent. No changes to your server. Just wrap it.

[![Tests](https://github.com/provnai/McpVanguard/actions/workflows/test.yml/badge.svg)](https://github.com/provnai/McpVanguard/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/mcp-vanguard.svg?color=blue)](https://pypi.org/project/mcp-vanguard/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
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

## 🧠 How it works

Every time an AI agent calls a tool (e.g. `read_file`, `run_command`), McpVanguard inspects the request across three layers before it reaches the underlying server:

| Layer | What it checks | Latency |
|-------|---------------|---------|
| **L1 — Rules** | 50+ static signatures: path traversal, reverse shells, SSRF, prompt injection | ~16ms |
| **L2 — Semantic** | LLM-based intent scoring for ambiguous requests | Async |
| **L3 — Behavioral** | Sliding-window anomaly detection (e.g. reading 500 files in 60 seconds) | Stateful |

> **On latency**: 16ms is the overhead at peak concurrent load. In practice it's well under the 1–2 second LLM response time — imperceptible to the agent.

If a request is blocked, the agent receives a standard JSON-RPC error response. The underlying server never sees it.

---

## 🛡️ What gets blocked

- **Filesystem attacks**: Path traversal (`../../etc/passwd`), null bytes, restricted paths (`~/.ssh`), Unicode homograph evasion
- **Command injection**: Pipe-to-shell, reverse shells, command chaining via `;` `&&` `\n`, expansion bypasses
- **Network abuse**: SSRF, cloud metadata endpoints (AWS/GCP/Azure), hex/octal encoded IPs
- **Prompt injection**: Jailbreak patterns, instruction-ignore sequences, hidden unicode characters
- **Privilege escalation**: SUID binary creation, `LD_PRELOAD` injection, crontab manipulation

---

## 📊 VEX Protocol — Immutable Audit Log

When McpVanguard blocks an attack, it can send a cryptographically-signed report to the **[VEX Protocol](https://github.com/provnai/vex)**. VEX anchors that report to the Bitcoin blockchain via the CHORA Gate.

This means an auditor can independently verify *exactly what was blocked and why* — without relying on your local logs.

```bash
export VANGUARD_VEX_URL="https://api.vexprotocol.com"
export VANGUARD_VEX_KEY="your-agent-jwt"
vanguard sse --server "..." --behavioral
```

---

## 🏗️ Architecture

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
      │               │  │  Ollama / OpenAI intent scoring 0.0→1.0   │  │
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
      │               └──────────────────┬──────────────────────────────┘
      │                                  │
      │◀─────────────── response ────────┘
      │
      │   (on BLOCK)
      └──────────────▶ VEX API ──▶ CHORA Gate ──▶ Bitcoin Anchor
                       (async, fire-and-forget audit receipt)
```

---

## 🗺️ Project Status

| Phase | Goal | Status |
|-------|------|--------|
| **Phase 1** | Foundation (Proxy, CLI, Defensive Rules) | ✅ Done |
| **Phase 2** | Intelligence (L2 Semantic, L3 Behavioral) | ✅ Done |
| **Phase 3** | Flight Recorder (VEX & CHORA Integration) | ✅ Done |
| **Phase 4** | Distribution (stable PyPI release) | ✅ Done |
| **Phase 5** | Production Hardening (v1.1.3 stability) | ✅ Done |
| **Phase 6** | **Security Audit Remediation (v1.1.4 hardening)** | ✅ Done |
| **Phase 7** | Agent Identity & VEX v0.2 Spec | 🔄 In Progress |

---

## 📚 Resources

- [Deployment Guide](docs/DEPLOYMENT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)
- [Ecosystem Report](https://github.com/provnai/provnai)

---

## 📄 License

Apache License 2.0 — see [LICENSE](LICENSE).

Built by the **[Provnai Open Research Initiative](https://provnai.com)**.
*"Verifying the thoughts and actions of autonomous agents."*
