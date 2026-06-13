# How To Read McpVanguard Block Decisions

McpVanguard blocks at the MCP execution boundary: after an agent proposes a tool call and before the upstream MCP server executes it.

A block means "this request violates the active policy profile." It does not always mean "the user or agent is malicious." Legitimate admin, security research, incident-response, migration, and diagnostics workflows can look risky until safe zones, profiles, and thresholds are tuned for the deployment.

## Decision Fields

Structured JSON audit logs include `policy_explanation` when a request is inspected by the policy composer.

Key fields:

| Field | Meaning |
|---|---|
| `active_profile` | The profile that shaped enforcement, such as `monitor`, `balanced`, or `strict`. |
| `final_verdict` | The final action after profile/mode adjustment. |
| `primary_layer` | The layer that drove the final verdict, such as `L1`, `L2`, or `L3`. |
| `primary_rule_id` | The main rule or finding behind the verdict. |
| `primary_rule_family` | Coarse family for triage, such as `safe_zone`, `semantic`, `behavioral`, or `auth`. |
| `supporting_findings` | Other warning/block findings that contributed context. |
| `raw_policy_action` | What the layers concluded before profile/mode adjustment. |
| `effective_policy_action` | What McpVanguard actually did after profile/mode adjustment. |
| `profile_effect` | Whether monitor/audit/strict changed the raw verdict. |
| `semantic_role` | Whether semantic scoring was `skipped`, `advisory`, or `escalated`. |
| `upstream_called` | Whether the upstream MCP server received the request. |
| `operator_hint` | Short tuning guidance for the operator. |

When available, audit events also include `tool_capabilities`, a coarse list such as `filesystem_read`, `filesystem_write`, `network_request`, or `unknown`.

Agent-facing JSON-RPC errors stay intentionally brief unless `VANGUARD_EXPOSE_BLOCK_REASON=true` is set. Full explanations belong in operator logs and evidence streams, not necessarily in the model-visible error channel.

## Common Layers

| Layer | What It Usually Means |
|---|---|
| `AUTH` | Transport identity, JWT/JWKS, scope, claim, or destructive-tool policy failed. |
| `L0` | Preflight normalization or input-shape validation found unsafe structure. |
| `L1` | Deterministic rules or safe-zone boundaries blocked the request. |
| `L1.5` | Camouflage or trust-signal manipulation was detected. |
| `L2` | Semantic scoring escalated an ambiguous request. Treat this as advisor context, not the whole boundary. |
| `L3` | Session or behavioral risk triggered, such as repeated reads, enumeration, flooding, or high-entropy extraction. |

## Safe-Zone Blocks

Safe-zone blocks use `VANGUARD-SAFEZONE-001` and usually mean a path-bearing tool attempted to access a path outside the configured workspace.

The `safe_zone` explanation includes:

- requested argument field
- requested path
- allowed-prefix summary
- a reminder that outside-policy access is not automatically malicious

If benign work is blocked:

1. Confirm the MCP tool should be allowed to touch that path.
2. Add the narrowest possible prefix to `rules/safe_zones.yaml`.
3. Re-run the request in `monitor` or `balanced`.
4. Promote to `strict` only after the expected workflow is clean.

Do not disable safe zones globally to fix one workflow. Tune the perimeter to the real tool surface.

## Recommended Rollout

Use profiles as a rollout ladder:

| Phase | Profile | Goal |
|---|---|---|
| Discovery | `monitor` | Log would-block traffic without stopping workflows. |
| Tuning | `balanced` | Enforce high-confidence threats while finding false positives. |
| Production-sensitive | `strict` | Enforce full hardening after safe zones, auth, and expected benign workflows are validated. |

For hosted deployments, always configure transport auth before using public/non-loopback binds. In `strict`, public binds fail closed unless API-key auth or OAuth/JWKS auth is configured.

## Common Benign Workflows That Can Look Risky

These workflows deserve careful tuning rather than blanket allow rules:

- incident-response scripts reading logs and credential-adjacent filenames
- documentation or training material containing exploit strings
- security audit commands that include destructive examples
- migration jobs touching many files quickly
- admin workflows that query internal URLs, cloud metadata-like paths, or private network ranges
- package-maintenance commands that resemble supply-chain hooks

The safest pattern is to start in `monitor`, review `policy_explanation`, tune narrow safe zones and profile settings, then enforce.

## Benchmark Breakdowns

Benchmark reports include aggregate quality metrics and breakdowns such as:

- benign blocks by layer
- benign blocks by rule family
- malicious blocks by layer
- malicious blocks by rule family
- false negatives by expected rule
- expected-vs-actual action confusion matrix

Use these as release and tuning signals. They are corpus-scoped, not universal claims of zero false positives or complete attack coverage.

## Capability Inference

McpVanguard infers coarse capabilities from tool names, descriptions, and observed argument keys/values. This helps L3 behavioral tracking recognize renamed tools such as `fetch_document` or `save_document`.

Inference is heuristic. If your MCP server uses product-specific names, configure explicit overrides:

```bash
export VANGUARD_TOOL_CAPABILITIES_JSON='{"company_fetch": ["filesystem_read"], "company_save": ["filesystem_write"]}'
```

Capability labels help with audit triage and behavioral accounting. They do not replace safe zones, deterministic rules, auth policy, or normal OS/container isolation.

Repeated network-capable calls currently produce behavioral WARN/risk events rather than default blocks. This is intentional: many production agents call APIs frequently, so network capability labels are best used first for egress review, allowlist design, and session-risk monitoring.

Capability fingerprints also preserve inferred `tool_capabilities` for each tool when building server capability manifests. If a pinned manifest later implies a different capability class for the same tool, McpVanguard reports capability drift so operators can review whether the upstream server changed its effective tool surface.
