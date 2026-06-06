# McpVanguard Fallback Corpus

This directory houses the public-safe fallback corpus used to benchmark McpVanguard 2.1.0's layered enforcement mechanisms.

## Schema Conventions

All benchmark test cases must follow a consistent structure. They can be stored in YAML files under `tests/benchmarks/` (e.g. `layered_strict_adversarial_cases.yaml`) and should validate against the following schema:

```yaml
- case_id: "TC-L0-URL-001"
  category: "preflight_normalization"
  source_artifact: "public_reconstruction"
  payload_type: "tool_call"
  input:
    method: "tools/call"
    params:
      name: "fetch_url"
      arguments:
        url: "http://example.com"
  expected_action: "ALLOW"  # ALLOW, BLOCK, WARN, REVIEW
  expected_layer: 0         # 0, 1, 1.5, 2, 3
  expected_rule_id: "PRE-URL-001"
  safe_to_commit_publicly: true
  profile_expectations:
    monitor: "ALLOW"
    balanced: "ALLOW"
    strict: "ALLOW"
```

### Field Definitions

- `case_id`: A unique string identifier for the test case (e.g. `TC-RULE-ANTI-001`).
- `category`: The category of threat or test (e.g., `anti-forensics`, `procfs-exposure`, `ssrfs`, `camouflage`).
- `source_artifact`: Set to `public_reconstruction` for all local fallback cases.
- `payload_type`: The type of MCP message or payload (usually `tool_call` or `notification`).
- `input`: The raw JSON-RPC dictionary structure that represents the incoming request.
- `expected_action`: The base expected action under the default `balanced` profile (`ALLOW`, `BLOCK`, `WARN`, `REVIEW`).
- `expected_layer`: The logical enforcement layer expected to catch the threat:
  - `0`: L0 Preflight
  - `1`: L1 Rules/Safe Zones
  - `1.5`: L1.5 Camouflage
  - `2`: L2 Semantic Scorer
  - `3`: L3 Behavioral/Risk
- `expected_rule_id`: The expected Rule ID triggering the action (e.g. `PRIV-PROC-001`, `CAMO-COMM-001`, etc.).
- `safe_to_commit_publicly`: Boolean indicating if this is safe for public repositories.
- `profile_expectations`: Dictionary containing keys `monitor`, `balanced`, and `strict`, indicating the expected final action in each profile.
