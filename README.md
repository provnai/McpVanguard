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

```bash
# 1. Install
pip install mcp-vanguard

# 2. Wrap any MCP server (e.g., filesystem server)
vanguard start --server "npx @modelcontextprotocol/server-filesystem ."

# 3. Enable advanced intelligence (Layer 2 + 3)
vanguard start --server "..." --semantic --behavioral
```

---

## 🧠 The Interception Layer

McpVanguard sits at the **Interception Layer** of the Provnai stack. It prevents the gap between **Cognitive Intent** (what the agent thinks) and **Environmental Execution** (what actually happens to your PC).

### 3-Layer Defense-in-Depth

| Layer | Component | Defense Mechanism | Performance |
|-------|-----------|-------------------|-------------|
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

## 🏟️ The Gauntlet — Expert Arena

Battle-test your bypass skills in our gamified security lab. Every release includes 6 production-grade challenges.

| Level | Name | Difficulty | Focal Layer | Points | Status |
|:---:|:---|:---:|:---:|:---:|:---:|
| 1 | System Prompt Leak | ★☆☆☆☆ | L1 (Rules) | 100 | ✅ ACTIVE |
| 2 | Shell Escape | ★★☆☆☆ | L1 (Rules) | 150 | ✅ ACTIVE |
| 3 | The Decoy | ★★★☆☆ | L3 (Behavioral) | 250 | ✅ ACTIVE |
| 4 | The Whisperer | ★★★★☆ | L2 (Semantic) | 500 | ✅ ACTIVE |
| 5 | Semantic Bypass | ★★★★☆ | L2 (Semantic) | 600 | ✅ ACTIVE |
| 6 | Slow Burn | ★★★★★ | L3 (Behavioral) | 750 | ✅ ACTIVE |

```bash
# Start a challenge
python arena/hunter.py 1 --handle your-github-handle
```

🏆 **[View Leaderboard](https://vanguard.provnai.com/leaderboard)** | 🏟️ **[Browse Challenges](https://vanguard.provnai.com/challenges)**

---

## 🏗️ How It Works

```text
                    ┌─────────────────────────────┐
     AI Agent       │     McpVanguard Proxy        │      MCP Server
  (Claude, GPT)     │                             │   (filesystem, shell...)
        │           │  ┌──────────────────────┐   │
        │──JSON-RPC▶│  │  L1: Rules Engine    │   │
        │           │  │  L2: Semantic Scorer  │   │
        │           │  │  L3: Behavioral Logic │   │
        │           │  └──────────────────────┘   │
        │◀─ BLOCK ──│        or ALLOW ───────────▶│
        │  (Status  │                             │
        │   Code)   └─────────────────────────────┘
```

Traffic is inspected on every message, in both directions. Blocked messages return a standard JSON-RPC error response — the server never sees the attack.

---

## 🗺️ Project Status

| Phase | Goal | Status |
|-------|------|--------|
| **Phase 1** | Foundation (Proxy, CLI, 32 Tests) | ✅ DONE |
| **Phase 2** | The Gauntlet (Levels 1-3, Hunter) | ✅ DONE |
| **Phase 3** | Web (Next.js Leaderboard) | ✅ DONE |
| **Phase 4** | Distribution (PyPI, README) | ✅ DONE |
| **Phase 5** | Intelligence (L2Semantic, L3Behavioral) | ✅ DONE |
| **Phase 6** | Ecosystem (Provnai Rebranding) | ✅ DONE |

---

## 📚 Resources

*   **[Full Documentation](https://provnai.dev)**
*   **[Ecosystem Report](https://github.com/provnai/ecosystem)**
*   **[Contributing Guide](CONTRIBUTING.md)**
*  ## 📄 License

Apache License 2.0 — see [LICENSE](LICENSE).

Built by the **Provnai Open Research Initiative**.
*"Verifying the thoughts and actions of autonomous agents."*
