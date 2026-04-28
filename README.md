[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/provnai-mcpvanguard-badge.png)](https://mseep.ai/app/provnai-mcpvanguard)

# McpVanguard
### Security Gateway for MCP Agents

MCP (Model Context Protocol) lets AI agents interact with tools that can read files, execute commands, and access external systems. **McpVanguard sits between the agent and the MCP server**, inspecting traffic in real time and enforcing security policy before sensitive calls reach the underlying tool.

McpVanguard is designed to work in both:

- **local-first mode**, where it wraps stdio MCP servers on a developer machine
- **gateway mode**, where it exposes hardened SSE and Streamable HTTP endpoints for hosted or shared deployments

Transparent integration. Existing MCP servers do not need to be rewritten.

## Release Candidate Highlights

The current release candidate is **`2.0.0-rc1`**.

This release packages a major security and platform expansion around McpVanguard's gateway role:

- hardened Streamable HTTP `/mcp` support and stricter session handling
- metadata poisoning inspection on `initialize` and `tools/list`
- cross-server isolation with `server_id` traceability
- server integrity and capability drift controls
- MCP-38 taxonomy and benchmark tooling
- a stronger JWT/JWKS auth foundation for hosted gateway deployments
- signed-manifest, provenance, artifact-signature, and Sigstore-backed trust verification

See [CHANGELOG.md](CHANGELOG.md) for the full release summary and history.

[![Tests](https://github.com/provnai/McpVanguard/actions/workflows/test.yml/badge.svg)](https://github.com/provnai/McpVanguard/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/mcp-vanguard.svg?color=blue)](https://pypi.org/project/mcp-vanguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

Part of the **[Provnai Open Research Initiative](https://provnai.com)** - Building the Immune System for AI.

---

## Quickstart

```bash
pip install mcp-vanguard
```

**Local stdio wrap**:

```bash
vanguard start --server "npx @modelcontextprotocol/server-filesystem ."
```

**Cloud security gateway**:

```bash
export VANGUARD_API_KEY="your-secret-key"
vanguard sse --server "npx @modelcontextprotocol/server-filesystem ."
```

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/PCkNLS?referralCode=4AXmAG&utm_medium=integration&utm_source=template&utm_campaign=generic)

See the deployment docs for operational details and the changelog for the exact verified scope.

## Getting Started

Bootstrap a local workspace:

```bash
# 1. Initialize safe zones and .env template
vanguard init

# 2. (Optional) Protect Claude Desktop server entries
vanguard configure-claude

# 3. Launch the local security dashboard
vanguard ui --port 4040

# 4. Run compliance/readiness checks
vanguard audit-compliance
```

## How It Works

Every tool call is inspected before it reaches the upstream MCP server.

| Layer | Purpose | Notes |
|---|---|---|
| **L1 - Rules** | Deterministic blocking using jail boundaries and signatures | Fast path |
| **L2 - Semantic** | Optional intent scoring | Async |
| **L3 - Behavioral** | Session and sequence-aware anomaly checks | Stateful |

### Architecture

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

If a request is blocked, the agent gets a standard JSON-RPC error response and the underlying server never sees the call.

### L2 Semantic Backend Options

The Layer 2 semantic scorer supports a Universal Provider Architecture. Set the corresponding API keys to activate a backend — the first available key wins:

| Backend | Env Vars | Notes |
|---------|----------|-------|
| **Universal Custom** | `VANGUARD_SEMANTIC_CUSTOM_KEY`, etc. | Fast inference (Groq, DeepSeek). |
| **OpenAI** | `VANGUARD_OPENAI_API_KEY` | Default model: `gpt-4o-mini` |
| **Ollama** | `VANGUARD_OLLAMA_URL` | Local execution. No API key required |


### Current Platform Capabilities

- transport hardening for SSE and Streamable HTTP
- metadata poisoning protection on the server-to-agent path
- cross-server behavioral isolation
- server integrity and capability drift verification
- JWT/JWKS-backed gateway auth for configured bearer deployments
- benchmark and taxonomy tooling for measurable security coverage
- signed trust surfaces for manifests, provenance, artifact signatures, and Sigstore bundles

## 🛠️ Usage Examples

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


## Authentication

McpVanguard is **local-first**, but it also supports stronger hosted gateway controls.

- **Stdio mode**: no network auth required
- **SSE / Streamable HTTP mode**: supports `VANGUARD_API_KEY`
- **Bearer / JWT mode**: supports verified JWT/JWKS validation, issuer/audience/claim/scope checks, and auth-aware policy on the hosted gateway path

## Integrity and Trust

The current release candidate includes:

- signed upstream server manifests
- capability baselines and drift checks
- provenance verification hooks
- detached artifact-signature verification
- Sigstore bundle verification with:
  - certificate identity and OIDC issuer constraints
  - Fulcio claim constraints
  - GitHub-compatible repository/ref/SHA/trigger/workflow-name checks
  - offline transparency-evidence validation

This should be described as **server integrity**, **baseline verification**, and **trust verification**, not as a full SBOM platform.

## Validation and Verification

The current repository verification baseline is:

- **`308 passed`**

Coverage includes:

- transport and session hardening
- metadata inspection
- auth and policy enforcement
- integrity and capability drift
- Sigstore / provenance / supplier trust paths
- benchmarks and taxonomy coverage
- cross-server isolation
- conformance integration

## Project Status

- Practical hardening roadmap: complete
- Current `2.0.0-rc1` release scope: complete and verified
- Full long-horizon research roadmap: intentionally broader than the current release and not represented as fully complete

| Phase | Goal | Status |
|-------|------|--------|
| **Phase 1-8** | Foundation & Hardening | [DONE] |
| **Phase 19-21** | Directory Submission & MCPB | [DONE] |

## 📄 Privacy Policy
McpVanguard focuses on local processing. See our [Privacy Policy](PRIVACY.md) for details on zero-telemetry and data handling.


## Support

- Issues: [github.com/provnai/McpVanguard/issues](https://github.com/provnai/McpVanguard/issues)
- Contact: [contact@provnai.com](mailto:contact@provnai.com)

## License

MIT License - see [LICENSE](LICENSE).

Built by the **[Provnai Open Research Initiative](https://provnai.com)**.
