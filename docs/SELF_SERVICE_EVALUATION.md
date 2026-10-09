# Try McpVanguard without credentials or customer data

McpVanguard 2.2.2 includes a self-contained check using its existing synthetic
MCP server. It requires Python 3.11 or newer and does not require Node, an LLM,
an API key, or a hosted service. Until 2.2.2 is published, install a wheel built
from this revision instead of substituting the older 2.2.1 package.

```bash
python -m pip install mcp-vanguard==2.2.2
python -m core.demo_verify
```

Run in a disposable virtual environment. The verifier starts the bundled server
once directly and once behind the gateway in balanced mode. It uses temporary,
explicit demo-only safe zones and checks:

- MCP initialization and tool discovery succeed.
- A benign read of the virtual `/docs/readme.txt` succeeds in both paths.
- A synthetic traversal request succeeds on the deliberately vulnerable raw
  path and is rejected by the gateway.
- A canned metadata-URL request succeeds on the raw path and is rejected by the
  gateway. The server returns a fixed string; it never fetches that URL.

Expected output is JSON with `scope: "synthetic-only"` and two sessions containing
`passed: true`. Unexpected behavior exits nonzero. Checks remain active under
`python -O`. Temporary rules and logs are removed when the processes close.

## Check benchmark output

```bash
vanguard benchmark-run --json-output
vanguard benchmark-profiles --json-output
vanguard benchmark-baselines --json-output
vanguard gpu-harden --json-output
vanguard gpu-thresholds --json-output
```

These evaluate bundled, curated corpora. They do not inspect your server or
certify your workflow. The GPU-named commands evaluate synthetic hardening and
threshold cases; they do not demonstrate GPU acceleration or hardware attestation.
Diagnostics may appear on stderr; stdout is the machine-readable report.

## Evaluate your own workflow separately

Use a disposable upstream with synthetic data. Start by observing benign calls
in monitor mode, then configure explicit tool/path policy and test balanced
enforcement. Monitor mode forwards calls and is not containment: do not run
harmful cases against customer systems, credentials, payments, or real targets.

Confirm ordinary work still succeeds, inspect the reason for each blocked call,
and independently instrument the upstream before claiming a rejected request
never reached it. Native filesystem permissions, isolation, and egress controls
remain necessary; gateway safe zones are not an OS sandbox.

Report friction with the package/SDK version, OS, the exact command, and a
sanitized output sample. Do not include secrets, private tool arguments, or
customer data in a public issue. A reproducible developer workflow is useful
evidence; a passing synthetic benchmark alone is not adoption or production proof.
