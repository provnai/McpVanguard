# 🛡️ McpVanguard
### The Interception & Verification Layer for MCP Agents

**McpVanguard** is an open-source security proxy and active firewall for the **Model Context Protocol (MCP)**. It acts as a real-time "Reflex System" between AI agents and their tools, protecting the host system from malicious intent, prompt injection, and data exfiltration.

Part of the **[Provnai Open Research Initiative](https://provnai.com)** — Building the **Immune System for AI**.

[![Tests](https://github.com/provnai/McpVanguard/actions/workflows/test.yml/badge.svg)](https://github.com/provnai/McpVanguard/actions/workflows/test.yml)
[![PyPI version](https://badge.fury.io/py/mcp-vanguard.svg)](https://pypi.org/project/mcp-vanguard/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

**No changes to your agent. No changes to your server. Just wrap it.**

---

## ⚡ Quickstart

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/import?repository=https://github.com/provnai/McpVanguard)

```bash
# 1. Install
pip install mcp-vanguard

# 2. Start as a Cloud Security Gateway (SSE)
# Set an API key to protect your endpoint
export VANGUARD_API_KEY="your-secret-key"
vanguard sse --server "npx @modelcontextprotocol/server-filesystem ."

# 3. Traditional Stdio Wrap (no network, no auth needed)
vanguard start --server "npx @modelcontextprotocol/server-filesystem ."

# 4. Enable VEX Flight Recorder (Immutable Audit)
export VANGUARD_VEX_URL="https://api.vexprotocol.com"
export VANGUARD_VEX_KEY="your-agent-jwt"
vanguard sse --server "..." --behavioral

# 5. Sync latest threat signatures from GitHub
vanguard update
```

---

## 🧠 The Interception Layer

McpVanguard sits at the **Interception Layer** of the Provnai stack. It prevents the gap between **Cognitive Intent** (what the agent thinks) and **Environmental Execution** (what actually happens to your PC).

### 3-Layer Defense-in-Depth

| Layer | Component | Defense Mechanism | Performance |
|-------|-----------|-------------------|-------------|
| **L0** | **Cloud Gateway** | SSE/Network Bridge with optional API key auth | <5ms |
| **L1** | **Static Rules** | 80+ security signatures across 5 categories | <1ms |
| **L2** | **Semantic Intelligence** | Local Ollama LLM intent classification | Async |
| **L3** | **Behavioral Analysis** | Sliding-window anomaly detection (Scraping/Enum) | Stateful |

### Rule Categories (Layer 1)

*   **Filesystem**: Path traversal, null bytes, restricted roots (`/etc/`, `~/.ssh/`), Cyrillic homograph detection.
*   **Command**: Pipe-to-shell, reverse shells, semicolon/`&&`/newline command chaining, expansion bypasses.
*   **Network**: SSRF, cloud metadata endpoints (AWS/GCP/Azure), IPv6 and hex/octal encoded IPs.
*   **Jailbreak**: Prompt extraction, instruction-ignore patterns, unicode hidden characters.
*   **Privilege**: SUID binary creation, `LD_PRELOAD` injection, crontab manipulation.

---

## 🛡️ VEX Protocol Integration (Flight Recorder)

McpVanguard integrates natively with the **VEX Protocol**. 
Whenever the proxy blocks a malicious action (L1/L2/L3), it instantly processes a "fire-and-forget" payload directly to the VEX API. 

The VEX Server cryptographically hashes the blocked intent, runs it through the CHORA Gate, and anchors an immutable receipt (PoE) to the Bitcoin blockchain.

*Enterprise auditors can mathematically prove exactly why an agent was blocked without relying entirely on local log trust.*

---

## 🏗️ How It Works

```text
                    ┌─────────────────────────────┐         ┌──────────────┐
     AI Agent       │     McpVanguard Proxy        │        │   VEX API    │
  (Claude, GPT)     │                             │──Async─▶│ (CHORA Gate) │
        │           │  ┌──────────────────────┐   │         └──────────────┘
        │──JSON-RPC▶│  │  L1: Rules Engine    │   │                │
        │           │  │  L2: Semantic Scorer  │   │                ▼
        │           │  │  L3: Behavioral Logic │   │      [Bitcoin Anchor]
        │           │  └──────────────────────┘   │
        │◀─ BLOCK ──│        or ALLOW ───────────▶│      MCP Server
        │  (Status  │                             │ (filesystem, shell...)
        │   Code)   └─────────────────────────────┘
```

Traffic is inspected on every message, in both directions. Blocked messages return a standard JSON-RPC error response — the server never sees the attack.

---

## 🗺️ Project Status

| Phase | Goal | Status |
|-------|------|--------|
| **Phase 1** | Foundation (Proxy, CLI, Defensive Rules) | ✅ DONE |
| **Phase 2** | Intelligence (L2 Semantic OpenAI, L3 Behavioral Redis Scaling) | ✅ DONE |
| **Phase 3** | Flight Recorder (VEX & CHORA Integration) | ✅ DONE |
| Phase 4 | Distribution (v1.0.0 Stable, PyPI, WSL Verified) | ✅ DONE |

---

## 📚 Resources

*   **[Full Documentation](https://provnai.dev)**
*   **[Ecosystem Report](https://github.com/provnai/provnai)**
*   **[Contributing Guide](CONTRIBUTING.md)**
*   **[Deployment Guide](docs/DEPLOYMENT.md)**
*   **[Architecture](docs/ARCHITECTURE.md)**

---

## 📄 License

Apache License 2.0 — see [LICENSE](LICENSE).

Built by the **Provnai Open Research Initiative**.
*"Verifying the thoughts and actions of autonomous agents."*
