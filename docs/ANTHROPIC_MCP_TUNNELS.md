# McpVanguard With Anthropic MCP Tunnels

Anthropic MCP tunnels let Claude reach MCP servers running inside a private network without opening inbound firewall ports or exposing the upstream server directly to the public internet.

McpVanguard fits behind the tunnel as the runtime enforcement gateway:

```text
Claude / Anthropic
  -> Anthropic MCP tunnel
  -> cloudflared + Anthropic tunnel proxy inside your network
  -> McpVanguard
  -> private MCP server
  -> private files, APIs, databases, browsers, or automation systems
```

The short version:

```text
Tunnels reduce network exposure. McpVanguard enforces the execution boundary.
```

## Why Use Both

The tunnel protects the network path. It does not decide whether a proposed MCP tool call is safe to execute.

McpVanguard adds runtime controls before the private MCP server sees the request:

- L0 normalization and input-shape checks
- L1 deterministic rules and safe-zone boundaries
- L1.5 camouflage / trust-signal detection
- L2 optional semantic advisory scoring
- L3 behavioral and session-risk tracking
- final policy verdicts: `ALLOW`, `WARN`, `REVIEW`, `SHADOW-BLOCK`, `BLOCK`
- JSON audit logs, optional receipt streams, and SIEM-friendly decision fields

This matters because a private network path can still carry risky tool calls, prompt-injection-driven requests, path traversal, SSRF attempts, metadata poisoning, credential-adjacent file access, or repeated suspicious automation.

## Recommended Placement

Route each tunneled MCP hostname to McpVanguard, not directly to the private MCP server.

McpVanguard then forwards allowed traffic to the real upstream MCP server:

```bash
export VANGUARD_PROFILE=strict
export VANGUARD_API_KEY="your-long-random-secret"
export VANGUARD_AUDIT_FORMAT=json

vanguard sse \
  --profile strict \
  --host 127.0.0.1 \
  --port 8080 \
  --server "your-private-mcp-server-command"
```

Configure the tunnel proxy to route the MCP server hostname/path to McpVanguard's hosted endpoint, for example:

```text
https://docs.<your-tunnel-domain>/mcp -> http://127.0.0.1:8080/mcp
```

The exact hostname, certificate, and tunnel-token setup belongs to Anthropic's tunnel documentation. The important McpVanguard rule is: the tunnel should terminate into the gateway first, then the gateway should call the private MCP server.

## Security Baseline

Recommended settings for tunneled private-network deployments:

```bash
export VANGUARD_PROFILE=strict
export VANGUARD_AUDIT_FORMAT=json
export VANGUARD_EXPOSE_BLOCK_REASON=false

# Keep transport auth enabled even though the service is reached through a tunnel.
export VANGUARD_API_KEY="your-long-random-secret"

# Optional session circuit breakers.
export VANGUARD_MAX_TOOL_CALLS_PER_MINUTE=120
export VANGUARD_MAX_RISKY_CALLS_PER_SESSION=10
export VANGUARD_MAX_BLOCKED_ATTEMPTS_PER_SESSION=3
```

For multi-replica deployments, configure Redis for shared L3 behavioral state:

```bash
export VANGUARD_REDIS_URL="redis://your-redis:6379/0"
```

Current session-budget counters are process-local. Atomic Redis budget counters are planned hardening work for high-concurrency multi-replica deployments.

## Safe Zones

Tunneled MCP servers often have access to private directories and internal APIs. Configure safe zones before enforcing `strict` profile:

```yaml
- tool: read_file
  allowed_prefixes:
    - /srv/company/docs
    - /srv/company/runbooks
  recursive: true
```

Safe zones are deterministic path-boundary checks. They are not a replacement for OS permissions, containers, network policy, or upstream MCP server auth.

## Auth Boundary

Tunnel access control and upstream MCP authentication are separate responsibilities.

Use McpVanguard transport auth and upstream MCP server auth where appropriate:

- tunnel access limits who can reach the private route
- McpVanguard auth identifies callers at the gateway
- upstream OAuth/bearer auth limits what the private MCP server accepts
- McpVanguard policy decides whether the proposed action should execute

Do not treat the tunnel itself as proof that every tunneled tool call is safe.

## Audit And SIEM

Use JSON audit logs for private-network deployments:

```bash
export VANGUARD_AUDIT_FORMAT=json
export VANGUARD_LOG_FILE=/var/log/vanguard/audit.log
```

JSON audit events include:

- `audit_schema_version`
- `event_category`
- `event_type`
- `event_outcome`
- `event_severity`
- `decision`
- `raw_policy_action`
- `effective_policy_action`
- `policy_explanation`
- `tool_capabilities`

See [BLOCK_DECISIONS.md](BLOCK_DECISIONS.md) for interpreting block decisions and false-positive tuning.

## What This Does Not Claim

This guide does not claim that McpVanguard replaces tunnel security, upstream OAuth, private-network controls, OS sandboxing, or container isolation.

It also does not claim that tunnels provide runtime tool-call safety. Tunnels reduce exposure. McpVanguard enforces the execution boundary.
