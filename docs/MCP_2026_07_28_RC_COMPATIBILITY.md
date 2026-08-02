# MCP 2026-07-28 Compatibility Baseline

The MCP 2026-07-28 specification introduces a large protocol update: a stateless protocol core, routing headers, heavier use of request `_meta`, `server/discover`, first-class extensions, Tasks, MCP Apps, authorization hardening, cache hints, trace context, and full JSON Schema 2020-12 for tool schemas.

McpVanguard does not claim full MCP 2026-07-28 support. This document is the
current OSS compatibility baseline for the `2.1.x` line and separates shipped
legacy behavior, Phase 0 safeguards, and deliberately unsupported future
behavior.

The current release line uses the MCP Python SDK v2 for both the default legacy
stateful gateway path and the opt-in stateless transport path. The legacy
profile remains available for existing clients; the SDK upgrade does not by
itself enable the stateless profile.

## Status Matrix

| Area | Current status | Boundary |
| --- | --- | --- |
| stdio gateway | Implemented | Existing MCP deployments; legacy stateful behavior |
| SSE / HTTP+SSE gateway | Implemented for existing clients | Legacy transport; not a claim of new-spec transport compliance |
| Stateful Streamable HTTP | Implemented | Uses `Mcp-Session-Id` and session binding |
| `legacy_stateful` protocol profile | Implemented and default | Preserves the current 2.1.x behavior |
| `mcp_2026_07_28_stateless` protocol profile | Opt-in transport slice | Ordinary stateless JSON-RPC and local `server/discover` are implemented and tested; Tasks, subscriptions, MRTR, and other extensions remain fail-closed |
| `Mcp-Method` / `Mcp-Name` | Opt-in stateless enforcement | Conflicts and body/header mismatches are rejected; required routing metadata is enforced in the stateless profile |
| Request `_meta` | Stateless trace and security coverage | L0/L1 inspect it; protocol identity is validated, and W3C trace context is carried to redacted audit fields; full RC capability semantics are not shipped |
| 2026-only methods | Fail closed | Unsupported methods are rejected before upstream forwarding |
| `server/discover` | Opt-in local response | Gateway identity and safe zero-TTL/private cache hints are returned; upstream capability inspection remains deferred |
| Tasks, MRTR, `subscriptions/listen` | Unsupported | No silent forwarding or compatibility claim |
| `resultType`, `ttlMs`, `cacheScope` | Opt-in envelope normalization | Stateless responses receive `resultType=complete`; list/read responses default to `ttlMs=0`, `cacheScope=private` when upstream hints are absent; W3C trace context is carried only into redacted audit fields |
| JSON Schema 2020-12 | Bounded tool-schema inspection | Draft 2020-12 syntax is checked; external references are never resolved; size, node, and depth bounds are enforced; full call-time validation remains deferred |

The protocol profile is selected with `VANGUARD_MCP_PROTOCOL_PROFILE` or the
CLI option `--protocol-profile`. The default is `legacy_stateful`. Selecting
`mcp_2026_07_28_stateless` selects a fresh transport/proxy lifecycle per
request, forbids `Mcp-Session-Id`, requires the 2026 request metadata and
routing headers, and does not fall back to the legacy session manager.

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

## Remaining `v2.2.x` Compatibility Track

Full support for the 2026-07-28 specification belongs in a later compatibility release. Planned areas:

- derived identity/session keys for stateless requests
- `server/discover` inspection and capability caching
- cache-aware capability and metadata drift logic beyond the current safe envelope defaults for `ttlMs` and `cacheScope`
- richer W3C trace context propagation and downstream OpenTelemetry export beyond the redacted audit/SIEM fields
- Tasks extension policy model for task handles, updates, cancellation, and task output
- MCP Apps inspection for server-rendered UI templates and UI-initiated JSON-RPC actions
- call-time JSON Schema validation and richer schema diagnostics beyond bounded metadata inspection, including safe local `$ref`/`$defs` handling, composition semantics, and validation-time limits
- conformance and benchmark coverage for the final specification

The stateless transport slice is deliberately not a full-spec claim. It is a
release-gated implementation seam: the default remains `legacy_stateful`, and
the stateless profile must remain covered by the SDK-v2 HTTP test matrix before
any deployment enables it.

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
