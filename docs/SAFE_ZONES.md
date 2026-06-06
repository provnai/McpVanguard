# Safe Zones

Safe Zones are McpVanguard's deterministic filesystem perimeter. They define which path prefixes specific MCP tools may access. If a filesystem-related tool tries to read, write, or list outside its configured prefixes, McpVanguard blocks the request before the upstream MCP server sees it.

This is intentionally strict. Safe Zones are often the strongest practical control in front of filesystem MCP servers, but they must be tuned for the deployment.

## Default Example

The repository ships with conservative example paths:

```yaml
- tool: "read_file"
  allowed_prefixes:
    - "/workspace"
    - "C:\\mcp-workspace"
  max_entropy: 7.0
  recursive: true

- tool: "write_file"
  allowed_prefixes:
    - "/workspace/output"
    - "C:\\mcp-workspace\\output"
  recursive: true

- tool: "list_directory"
  allowed_prefixes:
    - "/workspace"
    - "C:\\mcp-workspace"
  recursive: false
```

These paths are examples, not universal defaults for every project. If your MCP server is allowed to work in `C:\Users\alice\project` or `/srv/app`, update `rules/safe_zones.yaml` before enforcing traffic.

## Recommended Rollout

1. Start with `monitor` profile and review audit logs.
2. Set `allowed_prefixes` to the smallest real project directories your tools need.
3. Use separate read and write prefixes when possible.
4. Keep write access narrower than read access.
5. Move to `balanced` only after normal workflows are represented in the safe-zone file.
6. Use `strict` for production-sensitive deployments after Redis and semantic settings are intentional.

## Common Patterns

Developer workspace:

```yaml
- tool: "read_file"
  allowed_prefixes:
    - "/home/dev/project"
  recursive: true

- tool: "write_file"
  allowed_prefixes:
    - "/home/dev/project"
  recursive: true

- tool: "list_directory"
  allowed_prefixes:
    - "/home/dev/project"
  recursive: true
```

Read-mostly documentation bot:

```yaml
- tool: "read_file"
  allowed_prefixes:
    - "/srv/docs"
  recursive: true

- tool: "write_file"
  allowed_prefixes:
    - "/srv/docs/generated"
  recursive: true
```

Hosted single-purpose tool:

```yaml
- tool: "read_file"
  allowed_prefixes:
    - "/app/data"
  recursive: true

- tool: "write_file"
  allowed_prefixes:
    - "/app/output"
  recursive: true
```

## Important Behavior

- Safe-zone blocks are deterministic and happen before semantic scoring can soften the result.
- A safe-zone block is not a false positive if the requested path is outside the operator-defined perimeter.
- If many benign requests are blocked by `VANGUARD-SAFEZONE-001`, your safe-zone file likely does not match the real MCP server workspace.
- If no safe zones are configured for a tool, that tool falls back to the rule and policy layers.
- `recursive: false` means direct children only; use `recursive: true` when nested project access is expected.

## Release Claim Guidance

Safe Zones should be described as configurable filesystem perimeter enforcement. Do not describe them as a complete sandbox for all tool behavior. They constrain path-bearing MCP calls; they do not replace operating-system sandboxing, container hardening, network egress policy, or least-privilege credentials.
