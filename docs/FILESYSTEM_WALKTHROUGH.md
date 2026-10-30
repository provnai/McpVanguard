# McpVanguard Filesystem Evaluation Kit

**Source-only integration candidate, separate from the runtime/PyPI release.**
These scripts are not in the public `v2.2.2` tag or wheel. Use one reviewed source
revision containing all ten kit files; do not combine revisions or expect the
2.2.2 wheel to include this kit. No runtime version bump is part of this change.

**Evidence boundary:** this Windows-only synthetic scenario observes MCP stdio
outside the official server handler. It does not instrument the handler, prove
arbitrary downstream non-effects, or close Windows junction/TOCTOU races. The
unchanged upstream server's documented Windows limitation still applies. Validation
is maintainer-run; independent cold-run and practitioner acceptance remain pending.

This is separate from the public `mcp-vanguard==2.2.2` synthetic verifier,
`python -m core.demo_verify`, which uses an in-memory upstream. That demo does
not exercise this real-upstream filesystem walkthrough or replace its process-
path evidence. See the [PyPI 2.2.2 package description](https://pypi.org/project/mcp-vanguard/2.2.2/).

The supported walkthrough target is Windows, CPython 3.12.14, Node 24.22.1,
npm 10.9.4, McpVanguard 2.2.2, and the official
`@modelcontextprotocol/server-filesystem@2.1.0`. The fixture rejects other OS,
Python, Node, McpVanguard, and filesystem-server versions rather than silently
presenting them as tested. At the time of this review (2026-10-30), 2.1.0 is the
filesystem package version in the upstream v2.2.0 release. The previous pinned
date version, 2026.8.31, is listed as affected by upstream path-handling
advisories. A successful report fingerprints the installed package files, runner
script, upstream entry point, profile, and ruleset. The package-file digest is
not a signature or the original wheel-archive hash. The scenario requires no LLM,
account, API key, customer data, or hosted service. Fixture gateway/upstream
processes receive a minimal environment rather than the caller's credential-bearing
environment. [Upstream release](https://github.com/modelcontextprotocol/servers/releases/tag/v2.2.0), [filesystem advisory](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-53mr-w429-c597)

The runner requires CPython 3.12.14, Node 24.22.1 and npm 10.9.4; it selects an
available `npm-cli.js` whose adjacent package metadata identifies npm 10.9.4, then
verifies the actual CLI version inside the disposable directory. If multiple npm
installs exist, use `-NpmCli` to supply the intended `npm-cli.js` path. The report
includes hashes for the CLI and its package metadata. Other versions and platforms
are unverified for this integration acceptance test.

The scenario is an assistant reading source documents and writing generated
reports without overwriting the source documents. The script creates dummy files
in a temporary directory; it never asks for an existing project/data directory.
It runs deterministic MCP calls, not an autonomous agent or prompt-injection test.

## Run it

The ten-file kit inventory is the three Python scripts
(`scripts/filesystem_walkthrough.py`, `scripts/filesystem_relay.py`,
`scripts/filesystem_probe.py`), `scripts/run_filesystem_walkthrough.ps1`,
`scripts/filesystem-evaluation/{requirements.in,requirements.lock,package.json,package-lock.json}`,
`tests/test_filesystem_walkthrough.py`, and this guide. The launcher checks every
reported per-file SHA-256 against its local file, including the separate probe.
Hashes are emitted in the report rather than embedded here to avoid a self-hash.

Use a checkout containing the complete evaluation kit; these files are not modules
shipped in the 2.2.2 wheel. The launcher requires PowerShell 5.1 or later.
The validation targets are Windows PowerShell 5.1.26100.9711 (Desktop) and
PowerShell 7.6.5 (Core); other builds are not separately validated.
The full report records the executing PowerShell version and edition.
In either shell, set these paths to the actual CPython
3.12.14 and Node 24.22.1 executables on the machine, then run:

```powershell
$pythonExe = 'C:\Path\To\Python312\python.exe'
$nodeExe = 'C:\Path\To\Node24\node.exe'
& .\scripts\run_filesystem_walkthrough.ps1 -PythonExe $pythonExe -NodeExe $nodeExe
```

For revision-bound evidence, record `git rev-parse HEAD` and run from a clean
checkout of that reviewed commit. The report must identify that same HEAD and
mark all ten kit files as tracked, with hashes matching that checkout. A ZIP-only
extraction has no Git identity; its archive/per-file hashes identify its bytes,
but must not be represented as a revision-bound Git run.

The runner checks Python implementation/version, Node and npm versions, installs the hash-locked Python
requirements and npm lock with lifecycle scripts disabled, and then runs the
fixture. npm is pinned to the public registry with separate empty user/global
config files. The pip install uses an explicit PyPI index and sets
`PIP_CONFIG_FILE=nul` for that subprocess, disabling pip configuration files so
machine-wide/site config cannot silently add another index or alter install
behavior. A first run needs outbound access to `pypi.org` and
`registry.npmjs.org`; only selected OS and proxy environment values are inherited
for package downloads. The runner also passes a minimal environment to the fixture
gateway and upstream. It creates one
GUID-named temporary evaluation directory and removes
that exact directory in `finally`; child processes use it for both `TEMP` and
`TMP`, which the runner restores afterward. A conservative 240-character dependency
path preflight fails early with guidance to use a shorter temp root; Windows' default
`MAX_PATH` is 260 characters and long-path support depends on OS and application
opt-in. [Microsoft path-length guidance](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)
The runner does not leave the virtual environment,
node modules, or fixture data behind. The JSON report includes hashes of both
dependency locks, npm version and CLI digest, and the digest of every kit file.
It also records the Python implementation/build and pip version bootstrapped by
the selected Python distribution. pip is an installer prerequisite, not a locked
project dependency; the actual installed Python packages are still required to
match the hash-locked requirements file. The included locks pin
`mcp-vanguard==2.2.2` and
`@modelcontextprotocol/server-filesystem==2.1.0`, plus their transitive
dependencies. Refresh those locks only after reviewing the new package versions
and their security advisories.

Historical maintainer observation on 2026-10-29, before the separate probe was added: the complete runner took 37.9 seconds on
Windows 11 with CPython 3.12.14, Node 24.22.1 and npm 10.9.4 already installed.
This included a fresh temporary environment, dependency installation and all three
scenarios; it does not include provisioning Python or Node, and is not an independent
or cross-machine timing result. Cold-run timing on another machine remains unknown.

On Windows, a shutdown timeout invokes `taskkill /T /F` for the spawned gateway
process tree. If that command fails or times out, the fallback can terminate only
the gateway process; descendant cleanup in that failure path is not established.
Other platforms use immediate-child cleanup and are unverified.
The sole configured path is gateway (guarded mode only), relay, separate child-side
stdio probe, and the unchanged official filesystem process. The relay records
`relay_received`. The probe records `upstream_probe_ready` only after a successful
initialize response whose required fields validate: `protocolVersion` must be
`2025-11-25` (the only version this kit exercises), `capabilities` must be an object,
and `serverInfo` must contain non-empty string `name` and `version` fields. Optional
fields such as `instructions` and `title` are not required. See the
[supported MCP InitializeResult schema](https://modelcontextprotocol.io/specification/2025-11-25/schema#initializeresult).
The probe records `upstream_process_ingress_received` when a tool request reaches
the probe, `upstream_stdin_forwarded` after writing and flushing its original bytes
to the official process stdin, and `upstream_response_received` on a correlated
response. Ingress means arrival at the external probe, not entry into the official
handler. Missing responses produce `upstream_response_missing` and a failing exit.
Malformed/non-object JSON, duplicate/unexpected IDs, initialization failures and
probe/child failures fail the evaluation. Non-path arguments are
redacted; paths still appear. The gateway audit log is JSON and its policy events
are checked in the fixture's sequential call order because the audit schema does
not include the JSON-RPC request ID. This is test-scoped order correlation, not a
durable per-request join. Do not adapt the fixture to real/private files or use
its logging relay as a production observability component.

Child stdin and client stdout writes run on daemon workers with the remaining
30-second request deadline (also applied by the relay). A stalled write fails the
transport. Cleanup terminates the immediate child, waits up to five seconds, then
kills it if needed and waits up to five more seconds; all worker joins share one
additional second. Thus the local I/O/cleanup budget is 41 seconds plus process
creation, local file I/O and OS scheduling overhead, not a hard real-time guarantee.
Evidence-file I/O and OS process-management failures are outside this bound.

Both relay and probe accept at most eight queued frames, four MiB per complete
newline-terminated frame, and 64 request IDs per run. Oversized/incomplete frames,
queue saturation, or 30 seconds without a complete frame fail the harness.
The runner separately limits its response queue to eight frames and bounds line
reads. These are evaluation-harness limits, not product runtime protections.

Raw writes handle short writes and preserve request bytes. After a timeout, no new
write is started, but an OS write already in progress cannot be rolled back: it
may complete partially or fully after the deadline. The worker then stops rather
than writing the remaining bytes. It owns a duplicate descriptor to avoid reuse of
a closed descriptor. Incomplete/timed-out input writes cannot emit a completed-
forward event. A response received from upstream but stalled on delivery to the
client still counts as received; it is not falsely logged as an upstream missing
response. Any transport failure prevents a passing evaluation.

Blocked reader/writer daemons may survive the bounded joins until their enclosing
relay/probe process exits. Cleanup does not wait on a buffered stream lock held by
such a reader. This is process-scoped harness cleanup, not proof that arbitrary
descendants are terminated. The fixture remains finite synthetic traffic; general
resource-exhaustion resistance and arbitrary downstream non-effects are unproven.

## What the comparison verifies

| Request | Broad native root | Native input/output roots | Same narrow roots + gateway |
| --- | --- | --- | --- |
| Read input/public.txt | Allowed | Allowed | Allowed |
| Write output/report.txt | Allowed | Allowed | Allowed |
| Read private/internal.txt | Allowed | Server rejects | Gateway rejects |
| Write input/no-write.txt | Allowed | Allowed | Gateway rejects |

The gateway uses explicit safe zones: `read_text_file` may read input; `write_file`
may write output. The allowed read is checked against the exact fixture text, and
the allowed write is checked against the actual output-file contents. The broad
and native modes produce four relay observations and four correlated responses;
their permitted input write is checked against its expected contents. The guarded
mode produces exactly one relay observation, probe ingress, stdin-forward and
correlated response for each allowed call ID (2 and 4). Restricted IDs (3 and 5)
have `BLOCK` audit decisions with `upstream_called: false` and no observations or
forwards on this sole configured upstream process path. The protected input
fixture SHA-256 stays unchanged. Every mode requires exactly one ready event and
no missing-response or probe/relay-failure events.
Each mode has its own fresh fixture. The relay is the sole configured
gateway upstream path in this test; the report does not instrument the official
filesystem server's internal handler.

Expected full JSON output: `passed: true`, McpVanguard version and installed-file
digest, runner script digest, repository HEAD as context only, and per-kit-file
Git tracking state (`tracked`, `untracked`, or `unknown`) and SHA-256 digests,
upstream package/version and entry-point digest, Python implementation/build,
pip/Node/npm versions, npm CLI and package-metadata digests, `balanced` profile for
the guarded run only, ruleset digest, policy-audit
correlation method, and the results above. `--summary` is a compact display, not the complete evidence
report. The script refuses ambiguous or mismatched installed McpVanguard metadata
rather than treating a source checkout as a wheel install. Unexpected behavior
exits nonzero, including under `python -O`.

## What this does not establish

Native allowed directories already protect files outside those directories.
Prefer those native restrictions where they satisfy the requirement. This example
demonstrates an additional per-tool/path distinction within permitted directories,
not a unique replacement for native least privilege.

Only `read_text_file` and `write_file` are exercised, using one fixed `balanced`
profile. Other tools, MCP roots updates, symlinks, hard links, filesystem races,
direct access outside the gateway, and hostile upstream servers are not covered.
The test checks the gateway audit decision, relay and external probe observations,
correlated responses from the official process for forwarded calls, and one
synthetic file's hash. Blocked requests were not observed/forwarded on the sole
configured upstream process path and the protected fixture state stayed unchanged.
This is not instrumentation inside the official handler and does not prove
arbitrary downstream non-effects. Do not reuse these two rules as a complete
filesystem policy: review every available tool and mutation path first.
Read-only mounts, OS permissions, a dedicated process identity, or a purpose-built
read-only server may enforce the desired boundary more simply or strongly.

This is not an OS sandbox, downstream-effect certification, independent security
audit, customer pilot, independent adoption result, or comparison against
Docker/IBM gateways. It is a maintainer-produced, reproducible example. The next
useful evidence is whether this distinction solves a real workflow problem with
less friction than its native alternatives, not another passing synthetic case.

Native directory behavior is described in the
[official filesystem server documentation](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem).

### Upstream Windows limitation

The upstream advisory for the filesystem server says the path-race fix is only
partial on Windows: a junction swap can still redirect operations if an
untrusted local process can write to a directory in the allowed path. This
walkthrough does not test or mitigate that race. Use only the fresh disposable
fixture directories here; do not adapt it to sensitive roots or claim that
McpVanguard closes this upstream server limitation. Keep allowed directories
non-writable by untrusted local processes. See the
[upstream Windows advisory details](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-53mr-w429-c597).

## Review and scope status

The kit passed 64 focused tests and clean-extraction end-to-end runs in the
maintainer environment on Windows PowerShell 5.1 and PowerShell 7, using the
pinned Python, Node, npm, McpVanguard, and filesystem-server versions above. It
has not been run by an external operator or reviewed by an independent security
practitioner. These results are internal, reproducible evidence, not independent
validation or a security audit.

This is a source-only evaluation kit, not a McpVanguard runtime/PyPI release.
Before using it with a customer or making stronger security claims:

1. Have another operator follow these instructions from a clean Windows account.
   Record setup-to-result time, machine/runtime versions, the tested commit, and
   the full JSON output. External setup time remains unknown until measured.
2. Check `passed: true`, valid digests for all ten files (including
   `scripts/filesystem_probe.py`), and `tracked` status for every kit file. Retain
   the full report with its tested commit identifier.
3. Have a security practitioner review the tool rules, upstream assumptions,
   audit-to-relay correlation, and residual Windows/path-race limitations before
   making stronger claims.
4. Keep claims bounded to this local filesystem scenario. A passing run does not
   establish bypass resistance, production readiness, independent audit, customer
   adoption, or a general security guarantee.
