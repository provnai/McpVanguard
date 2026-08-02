# MCP 2026-07-28 Compatibility Baseline

The MCP 2026-07-28 specification introduces a large protocol update: a stateless protocol core, routing headers, heavier use of request `_meta`, `server/discover`, first-class extensions, Tasks, MCP Apps, authorization hardening, cache hints, trace context, and full JSON Schema 2020-12 for tool schemas.

McpVanguard does not claim full MCP 2026-07-28 support. This document is the
current OSS compatibility baseline for the `2.1.x` line and separates shipped
legacy behavior, Phase 0 safeguards, and deliberately unsupported future
behavior.

The current release line deliberately pins the MCP Python SDK to `<2` because
the gateway transport integration is still built around the v1 session API.
The SDK v2 migration is a required prerequisite for the full stateless runtime,
not an optional dependency refresh.

## Status Matrix

| Area | Current status | Boundary |
| --- | --- | --- |
| stdio gateway | Implemented | Existing MCP deployments; legacy stateful behavior |
| SSE / HTTP+SSE gateway | Implemented for existing clients | Legacy transport; not a claim of new-spec transport compliance |
| Stateful Streamable HTTP | Implemented | Uses `Mcp-Session-Id` and session binding |
| `legacy_stateful` protocol profile | Implemented and default | Preserves the current 2.1.x behavior |
| `mcp_2026_07_28_stateless` protocol profile | Reserved and fail-closed | No stateless runtime is implemented in this release |
| `Mcp-Method` / `Mcp-Name` | Phase 0 partial | Conflicts and body/header mismatches are rejected; required-header stateless operation is not shipped |
| Request `_meta` | Phase 0 security coverage | L0/L1 inspect it; full RC identity, trace, and capability semantics are not shipped |
| 2026-only methods | Fail closed | Unsupported methods are rejected before upstream forwarding |
| `server/discover`, Tasks, MRTR, `subscriptions/listen` | Unsupported | No silent forwarding or compatibility claim |
| `ttlMs`, `cacheScope`, trace context | Unsupported | No cache or trace propagation contract is shipped |
| JSON Schema 2020-12 | Partial legacy validation only | Full composition, reference, resource, and timeout coverage is deferred |

The protocol profile is selected with `VANGUARD_MCP_PROTOCOL_PROFILE` or the
CLI option `--protocol-profile`. The default is `legacy_stateful`. Selecting
`mcp_2026_07_28_stateless` is intentionally fail-closed rather than silently
falling back to stateful behavior.

## Current Release Posture

McpVanguard currently supports the existing stdio, SSE, and Streamable HTTP gateway paths used by current MCP deployments.

The current release line adds compatibility-oriented safeguards:

- If hosted Streamable HTTP requests include `Mcp-Method`, McpVanguard rejects requests where the header disagrees with the JSON-RPC body `method`.
- If hosted Streamable HTTP `tools/call` requests include `Mcp-Name`, McpVanguard rejects requests where the header disagrees with `params.name`.
- Conflicting duplicate routing-header values are rejected.
- Known unsupported 2026-only methods are rejected with a fail-closed `501` boundary response and are not forwarded upstream.

These checks are additive. Existing clients that do not send the future routing headers are unchanged.

## `_meta` Is Security-Relevant

The specification moves more protocol/client context into request `_meta`. McpVanguard treats `_meta` as security-relevant input:

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
McpVanguard provides a documented MCP 2026-07-28 compatibility baseline and includes additive routing-header and `_meta` inspection safeguards in the `2.1.x` line.
```

Avoid:

```text
McpVanguard fully supports every MCP 2026-07-28 feature.
McpVanguard is stateless-MCP complete.
McpVanguard supports MCP Apps and Tasks.
```

Those claims should wait until the corresponding feature is implemented, tested, documented, and released.
