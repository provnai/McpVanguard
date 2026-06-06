# McpVanguard

Security gateway for MCP agents and tool servers.

McpVanguard sits between an AI agent and an MCP server, normalizes and inspects tool traffic in real time, and enforces a layered policy before sensitive calls reach the underlying tool. It runs locally in front of stdio servers or as a hosted gateway over SSE and Streamable HTTP.

**Product profiles** — `monitor`, `balanced`, `strict` — let you adopt incrementally: start with audit-only discovery, move to balanced enforcement, then enable strict hardening for production-sensitive systems.

Existing MCP servers do not need to be rewritten.

[![Tests](https://github.com/provnai/McpVanguard/actions/workflows/test.yml/badge.svg)](https://github.com/provnai/McpVanguard/actions/workflows/test.yml)
[![CodeQL](https://github.com/provnai/McpVanguard/actions/workflows/codeql.yml/badge.svg)](https://github.com/provnai/McpVanguard/actions/workflows/codeql.yml)
[![Security Audit](https://github.com/provnai/McpVanguard/actions/workflows/security-audit.yml/badge.svg)](https://github.com/provnai/McpVanguard/actions/workflows/security-audit.yml)
[![SBOM](https://github.com/provnai/McpVanguard/actions/workflows/sbom.yml/badge.svg)](https://github.com/provnai/McpVanguard/actions/workflows/sbom.yml)
[![PyPI version](https://img.shields.io/pypi/v/mcp-vanguard.svg?color=blue)](https://pypi.org/project/mcp-vanguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

## Why Developers Use It

MCP workflows are powerful, but once tools touch files, shells, or networks, guardrails matter.

McpVanguard adds a runtime enforcement boundary so you can:

- keep normal tool traffic flowing
- block unsafe calls before execution
- inspect and debug policy decisions with audit logs
- adopt incrementally without rewriting existing MCP servers

## What It Does

McpVanguard is for developers and platform teams who want explicit policy enforcement around MCP workflows.

- inspect MCP tool calls before execution
- block unsafe filesystem, command, and network patterns
- enforce auth, role, and scope requirements for sensitive tools
- inspect server metadata before it reaches downstream models
- track repeated suspicious behavior over time
- emit audit and telemetry signals for blocked, warned, and allowed traffic

## Quick Verification Scenario

Use one raw path and one guarded path against the same MCP server.

- safe file read passes in both paths
- path traversal attempt is blocked in the guarded path
- risky network request is blocked in the guarded path
- metadata poisoning attempts are filtered or blocked before model exposure

This gives you a fast signal that policy is active and enforcement behaves as expected.

## Use Cases

- protect local desktop or developer-machine MCP servers without rewriting them
- add a hosted gateway in front of shared MCP servers
- compare raw versus guarded behavior for risky tool workflows
- add policy enforcement to high-risk file, shell, and network-access tools

## Quickstart

Install the package:

```bash
pip install mcp-vanguard
```

Wrap a local stdio MCP server:

```bash
# Balanced profile (default OSS/developer behavior)
vanguard start --profile balanced --server "npx @modelcontextprotocol/server-filesystem ."

# Strict profile (production hardening)
vanguard start --profile strict --server "npx @modelcontextprotocol/server-filesystem ."
```

Run as a hosted gateway:

```bash
export VANGUARD_API_KEY="your-secret-key"
vanguard sse --profile balanced --server "npx @modelcontextprotocol/server-filesystem ."
```

Deploy on Railway:

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/mcpvanguard?referralCode=4AXmAG&utm_medium=integration&utm_source=template&utm_campaign=generic)

Need a complete deployment walkthrough? See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and [docs/railway-deployment-guide.md](docs/railway-deployment-guide.md).

## Getting Started

Bootstrap a local workspace:

```bash
# 1. Initialize safe zones and .env template
vanguard init

# 2. Optionally update Claude Desktop server entries
vanguard configure-claude

# 3. Launch the local security dashboard
vanguard ui --port 4040

# 4. Run compliance and readiness checks
vanguard audit-compliance
```

## How It Works

McpVanguard uses five core inspection layers, `L0` through `L3` plus `L1.5`, with auth policy and a final policy composer around them. Every tool call is inspected before it reaches the upstream MCP server.

| Layer | Purpose | Notes |
|---|---|---|
| **L0 - Preflight** | Normalize and annotate (URL decode, NFKC, strip zero-width, size/depth gates) | Always on |
| **Auth** | OAuth scope enforcement and destructive-tool policy | Role-aware |
| **L1 - Rules** | Deterministic blocking using signatures and safe boundaries | Fast path |
| **L1.5 - Camouflage** | Detect trust-signal camouflage and scorer manipulation | Profile-sensitive |
| **L2 - Semantic** | Optional intent scoring (advisor, cannot downgrade blocks) | Async |
| **L3 - Behavioral** | Session and sequence-aware anomaly checks | Stateful |
| **Policy Composer** | Final verdict: ALLOW / WARN / REVIEW / SHADOW-BLOCK / BLOCK | Explainable |

The five core inspection layers are `L0`, `L1`, `L1.5`, `L2`, and `L3`. Auth policy and the final policy composer sit around that core path.

If a request is blocked, the agent receives a standard JSON-RPC error and the upstream server never sees the call. The audit log records the primary reason and all supporting findings.

Safe zones are deterministic path-boundary checks, not a substitute for OS sandboxing or container isolation. Before enforcing production traffic, tune `rules/safe_zones.yaml` for the directories your MCP tools are actually allowed to touch. See [docs/SAFE_ZONES.md](docs/SAFE_ZONES.md).

## Deployment Model

McpVanguard is best understood as a security gateway for MCP workflows.

- **Local-first mode**: wraps stdio MCP servers on a developer machine
- **Gateway mode**: exposes hardened SSE and Streamable HTTP endpoints for hosted or shared deployments

Typical path:

```text
AI Agent -> McpVanguard -> MCP Server -> Tools / Files / External Systems
```

## Current Capabilities

- hardened SSE and Streamable HTTP transport paths
- metadata poisoning inspection on `initialize` and `tools/list`
- JWT, JWKS, issuer, audience, claim, and scope checks for bearer-auth deployments
- server integrity and capability drift verification
- cross-server isolation and `server_id` traceability
- signed-manifest, provenance, detached signature, and Sigstore-backed trust verification
- benchmark and taxonomy tooling for measurable coverage
- optional `receipt_v1` JSONL emission for offline-verifiable runtime evidence with `mcp-receipt`

## Benchmarks

McpVanguard includes packaged benchmark corpora for adversarial and benign MCP traffic. Use them to compare profiles before deployment:

```bash
vanguard benchmark-run --profile monitor
vanguard benchmark-run --profile balanced
vanguard benchmark-run --profile strict
```

The benchmark results are a release and tuning signal, not a promise of universal detection or zero false positives. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for interpretation guidance and the recommended release gate.

## Authentication Modes

McpVanguard is local-first and supports stronger hosted-gateway controls when needed.

- **stdio mode**: no network auth required
- **SSE / Streamable HTTP mode**: supports `VANGUARD_API_KEY`
- **Bearer / JWT mode**: supports verified JWT/JWKS validation, issuer/audience/claim/scope checks, and auth-aware policy on the hosted gateway path

## Semantic Backend Options

The optional Layer 2 semantic scorer supports multiple backends. The first configured backend wins.

| Backend | Env Vars | Notes |
|---|---|---|
| **Universal Custom** | `VANGUARD_SEMANTIC_CUSTOM_KEY`, related custom vars | Fast inference providers such as Groq or DeepSeek |
| **OpenAI** | `VANGUARD_OPENAI_API_KEY` | Default model: `gpt-4o-mini` |
| **Ollama** | `VANGUARD_OLLAMA_URL` | Local execution, no API key required |

For a more detailed local/offline setup guide, see [docs/LOCAL_SEMANTIC_MODE.md](docs/LOCAL_SEMANTIC_MODE.md).

## Integrity and Trust

McpVanguard includes:

- signed upstream server manifests
- capability baselines and drift checks
- provenance verification hooks
- detached artifact-signature verification
- Sigstore bundle verification with identity and issuer constraints

This should be described as server integrity, baseline verification, and trust verification, not as a full SBOM platform.

## Project Status

- `2.1.0` is the layered enforcement release candidate on this branch
- layered enforcement path (`L0 -> L1 -> L1.5 -> L2 -> L3 -> Policy Composer`) is implemented and covered by local verification
- product profiles (`monitor` / `balanced` / `strict`) are the supported deployment modes for this release line
- broader research-only features (GPU attestation, hardware-rooted provenance, zero-FP claims) are intentionally outside the core OSS release scope

See [CHANGELOG.md](CHANGELOG.md) for the release history and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for deployment details.

## Privacy

McpVanguard focuses on local inspection and gateway enforcement. See [PRIVACY.md](PRIVACY.md) for current privacy and data-handling details.

## Support

- Issues: [github.com/provnai/McpVanguard/issues](https://github.com/provnai/McpVanguard/issues)
- Contact: [contact@provnai.com](mailto:contact@provnai.com)
- Security: see [SECURITY.md](SECURITY.md)

## FAQ

**Does this replace my MCP server?**  
No. McpVanguard sits in front of your existing MCP server and enforces policy before calls reach it.

**Do I need to rewrite tools or agent code?**  
Usually no. Most setups start by routing one workflow through McpVanguard.

**Is this only for hosted setups?**  
No. It supports local-first stdio wrapping and hosted gateway modes.

## License

MIT License - see [LICENSE](LICENSE).

Built by [Provnai](https://provnai.com).
