# 🛡️ McpVanguard
### The Interception & Verification Layer for MCP Agents

**McpVanguard** is an open-source security proxy and active firewall for the **Model Context Protocol (MCP)**. It acts as a real-time "Reflex System" between AI agents and their tools, protecting the host system from malicious intent, prompt injection, and data exfiltration.

Part of the **[Provnai Open Research Initiative](https://provnai.com)** — Building the **Immune System for AI**.

[![Tests](https://github.com/provnai/McpVanguard/actions/workflows/test.yml/badge.svg)](https://github.com/provnai/McpVanguard/actions/workflows/test.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

**No changes to your agent. No changes to your server. Just wrap it.**

---

## ⚡ Quickstart

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/import?template=https://github.com/provnai/McpVanguard)

```bash
# 1. Install
pip install mcp-vanguard

# 2. Start as a Cloud Security Gateway (SSE)
# This allows remote agents to connect over HTTP
vanguard sse --server "npx @modelcontextprotocol/server-filesystem ."

# 3. Traditional Stdio Wrap
vanguard start --server "npx @modelcontextprotocol/server-filesystem ."

# 4. Enable VEX Flight Recorder (Immutable Audit)
export VANGUARD_VEX_URL="https://api.vexprotocol.com"
export VANGUARD_VEX_KEY="your-agent-jwt"
vanguard sse --server "..." --behavioral
```

---

## 🧠 The Interception Layer

McpVanguard sits at the **Interception Layer** of the Provnai stack. It prevents the gap between **Cognitive Intent** (what the agent thinks) and **Environmental Execution** (what actually happens to your PC).

### 3-Layer Defense-in-Depth

| Layer | Component | Defense Mechanism | Performance |
|-------|-----------|-------------------|-------------|
| **L0** | **Cloud Gateway** | SSE/Network Bridge for remote agent access | <5ms |
| **L1** | **Static Rules** | 60+ security signatures across 5 categories | <1ms |
| **L2** | **Semantic Intelligence** | Local Ollama LLM intent classification | Async |
| **L3** | **Behavioral Analysis** | Sliding-window anomaly detection (Scraping/Enum) | Stateful |

### Rule Categories (Layer 1)

*   **Filesystem**: Path traversal, restricted roots (`/etc/`, `~/.ssh/`).
*   **Command**: Pipe-to-shell, reverse shells, privilege escalation.
*   **Network**: Data exfiltration detection, tunnel host blocking.
*   **Jailbreak**: Prompt extraction, instruction-ignore patterns.
*   **Privilege**: SUID binary creation, crontab manipulation.

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
*  ## 📄 License

Apache License 2.0 — see [LICENSE](LICENSE).

Built by the **Provnai Open Research Initiative**.
*"Verifying the thoughts and actions of autonomous agents."*
