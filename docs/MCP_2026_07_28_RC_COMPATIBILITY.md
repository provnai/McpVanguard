# MCP 2026-07-28 Release Candidate Compatibility Note

The MCP 2026-07-28 release candidate introduces a large protocol update: a stateless protocol core, routing headers, heavier use of request `_meta`, `server/discover`, first-class extensions, Tasks, MCP Apps, authorization hardening, cache hints, trace context, and full JSON Schema 2020-12 for tool schemas.

McpVanguard is tracking this release candidate. The current `2.1.x` release line should not be described as full MCP 2026-07-28 support until the final specification is implemented and tested.

## Current Release Posture

McpVanguard currently supports the existing stdio, SSE, and Streamable HTTP gateway paths used by current MCP deployments.

The current release line adds two compatibility-oriented safeguards:

- If hosted Streamable HTTP requests include `Mcp-Method`, McpVanguard rejects requests where the header disagrees with the JSON-RPC body `method`.
- If hosted Streamable HTTP `tools/call` requests include `Mcp-Name`, McpVanguard rejects requests where the header disagrees with `params.name`.

These checks are additive. Existing clients that do not send the future routing headers are unchanged.

## `_meta` Is Security-Relevant

The release candidate moves more protocol/client context into request `_meta`. McpVanguard treats `_meta` as security-relevant input:

- L0 preflight normalization recursively inspects `_meta`.
- L1 recursive rule matching inspects `params._meta`.
- Agent-facing block reasons remain brief unless explicitly opted in with `VANGUARD_EXPOSE_BLOCK_REASON=true`.

This prevents `_meta` from becoming a bypass lane for encoded paths, scorer-targeting instructions, metadata poisoning, or dangerous values that later influence execution.

## Planned `v2.2.x` Compatibility Track

Full support for the 2026-07-28 specification belongs in a later compatibility release. Planned areas:

- stateless Streamable HTTP request handling
- derived identity/session keys for stateless requests
- `server/discover` inspection and capability caching
- cache-aware capability and metadata drift logic for `ttlMs` and `cacheScope`
- W3C trace context propagation from `_meta` into audit/SIEM fields
- Tasks extension policy model for task handles, updates, cancellation, and task output
- MCP Apps inspection for server-rendered UI templates and UI-initiated JSON-RPC actions
- JSON Schema 2020-12 hardening for `$ref`, `$defs`, `oneOf`, `anyOf`, `allOf`, conditionals, schema depth, and validation time
- conformance and benchmark coverage for the final specification

## Safe Public Wording

Use:

```text
McpVanguard is tracking the MCP 2026-07-28 release candidate and includes additive routing-header and `_meta` inspection safeguards in the `2.1.x` line.
```

Avoid:

```text
McpVanguard fully supports MCP 2026-07-28.
McpVanguard is stateless-MCP complete.
McpVanguard supports MCP Apps and Tasks.
```

Those claims should wait until the final specification is implemented, tested, documented, and released.
