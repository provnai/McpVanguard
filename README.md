# McpVanguard

Security gateway for MCP agents and tool servers.

McpVanguard sits between an AI agent and an MCP server, inspects tool traffic in real time, and enforces policy before sensitive calls reach the underlying tool. It can run locally in front of stdio servers or as a hosted gateway over SSE and Streamable HTTP.

Existing MCP servers do not need to be rewritten.

[![Tests](https://github.com/provnai/McpVanguard/actions/workflows/test.yml/badge.svg)](https://github.com/provnai/McpVanguard/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/mcp-vanguard.svg?color=blue)](https://pypi.org/project/mcp-vanguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

## What It Does

McpVanguard is designed for teams that want a real enforcement boundary around MCP-based agent workflows.

- inspect MCP tool calls before execution
- block unsafe filesystem, command, and network patterns
- enforce auth, role, and scope requirements for sensitive tools
- inspect server metadata before it reaches downstream models
- track repeated suspicious behavior over time
- emit audit and telemetry signals for blocked, warned, and allowed traffic

## Use Cases

- protect local desktop or developer-machine MCP servers without rewriting them
- add a hosted gateway in front of shared MCP servers
- test raw versus guarded behavior for risky tool workflows
- add policy enforcement to high-risk file, shell, and network-access tools

## Quickstart

Install the package:

```bash
pip install mcp-vanguard
```

Wrap a local stdio MCP server:

```bash
vanguard start --server "npx @modelcontextprotocol/server-filesystem ."
```

Run as a hosted gateway:

```bash
export VANGUARD_API_KEY="your-secret-key"
vanguard sse --server "npx @modelcontextprotocol/server-filesystem ."
```

Deploy on Railway:

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/PCkNLS?referralCode=4AXmAG&utm_medium=integration&utm_source=template&utm_campaign=generic)

## Getting Started

Bootstrap a local workspace:

```bash
# 1. Initialize safe zones and .env template
vanguard init

# 2. Optionally protect Claude Desktop server entries
vanguard configure-claude

# 3. Launch the local security dashboard
vanguard ui --port 4040

# 4. Run compliance and readiness checks
vanguard audit-compliance
```

## How It Works

Every tool call is inspected before it reaches the upstream MCP server.

| Layer | Purpose | Notes |
|---|---|---|
| **L1 - Rules** | Deterministic blocking using signatures and safe boundaries | Fast path |
| **L2 - Semantic** | Optional intent scoring | Async |
| **L3 - Behavioral** | Session and sequence-aware anomaly checks | Stateful |

If a request is blocked, the agent receives a standard JSON-RPC error and the upstream server never sees the call.

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

## Authentication

McpVanguard is local-first, but it also supports stronger hosted-gateway controls.

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

## Integrity and Trust

McpVanguard includes:

- signed upstream server manifests
- capability baselines and drift checks
- provenance verification hooks
- detached artifact-signature verification
- Sigstore bundle verification with identity and issuer constraints

This should be described as server integrity, baseline verification, and trust verification, not as a full SBOM platform.

## Project Status

- `2.0.0` is the current release line
- the core gateway and integrity features are the main shipped scope
- broader research and future control-plane work are intentionally outside the core release promise

See [CHANGELOG.md](CHANGELOG.md) for the release history and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for deployment details.

## Privacy

McpVanguard focuses on local inspection and gateway enforcement. See [PRIVACY.md](PRIVACY.md) for current privacy and data-handling details.

## Support

- Issues: [github.com/provnai/McpVanguard/issues](https://github.com/provnai/McpVanguard/issues)
- Contact: [contact@provnai.com](mailto:contact@provnai.com)
- Security: see [SECURITY.md](SECURITY.md)

## License

MIT License - see [LICENSE](LICENSE).

Built by [Provnai](https://provnai.com).
