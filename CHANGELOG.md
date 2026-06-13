# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.2] - 2026-06-12 (Deployment-Safe Runtime Enforcement Patch)

### Security and Deployment Safety

- **Strict hosted startup guard** (`core/sse_server.py`): `vanguard sse --profile strict` now refuses non-loopback/public binds unless API-key auth or OAuth/JWKS auth is configured.
- **Hosted posture summary** (`core/sse_server.py`): SSE startup now prints profile, bind scope, auth state, origin policy, bearer claim policy, Streamable HTTP session-binding state, and Redis/shared-state status.
- **Strict hosted defaults** (`core/sse_server.py`): strict hosted gateway startup defaults bearer claim-policy mismatches to `block` and requires `Origin` when `VANGUARD_ALLOWED_ORIGINS` is configured, unless the operator explicitly overrides those settings.
- **Structured policy explanations** (`core/policy.py`, `core/proxy.py`): inspected requests now carry a `policy_explanation` object in JSON audit logs with primary layer, rule family, profile effect, upstream-call status, supporting findings, and operator tuning hints.
- **Safe-zone explanation context** (`core/rules_engine.py`): safe-zone blocks now include the requested path field/value and allowed-prefix summary for operator triage.
- **Benchmark false-positive breakdowns** (`core/benchmarks.py`, `core/cli.py`): benchmark reports now include benign/malicious block breakdowns by layer and rule family.
- **Public-safe benchmark IDs** (`core/benchmarks.py`, `core/cli.py`): benchmark cases and evaluations now expose deterministic `public_case_id` and `source_corpus` fields for reproducible public reports without private artifact paths.
- **Benchmark confusion matrices** (`core/benchmarks.py`, `core/cli.py`): benchmark JSON and CLI reports now include expected-vs-actual action matrices plus per-action precision/recall-style counts scoped to the evaluated corpus/profile.
- **Benchmark latency summaries** (`core/benchmarks.py`, `core/cli.py`): benchmark reports now include per-case harness timing and aggregate mean/p50/p95/max latency summaries for selected corpora and profile comparisons.
- **Profile comparison benchmark command** (`core/cli.py`): added `vanguard benchmark-profiles` to compare the same corpus across `monitor`, `balanced`, and `strict`, including per-profile summaries and case-level action deltas.
- **Baseline comparison benchmark command** (`core/cli.py`): added `vanguard benchmark-baselines` for corpus-scoped `no_gateway`, deterministic `l1_only`, synthetic `l2_threshold_only`, and configured-harness comparisons.
- **Capability-aware L3 tracking** (`core/tool_capabilities.py`, `core/behavioral.py`): behavioral detectors now classify coarse tool capabilities so renamed file read/write tools still contribute to scraping and write-after-sensitive-read detection.
- **Network capability risk signal** (`core/behavioral.py`): repeated network-capable calls now emit a Layer 3 WARN and risk-engine event instead of silently blending into generic tool-flood behavior.
- **Per-session budget circuit breakers** (`core/risk.py`, `core/proxy.py`): added opt-in session/server budgets for tool-call rate, risky decisions, and repeated blocked attempts using `VANGUARD_MAX_TOOL_CALLS_PER_MINUTE`, `VANGUARD_MAX_RISKY_CALLS_PER_SESSION`, and `VANGUARD_MAX_BLOCKED_ATTEMPTS_PER_SESSION`.
- **SIEM-friendly audit fields** (`core/models.py`, `core/proxy.py`): JSON audit logs now include additive schema, category, type, outcome, severity, decision, raw policy action, and effective policy action fields for easier downstream parsing.
- **MCP routing-header consistency checks** (`core/sse_server.py`): hosted Streamable HTTP requests that include future `Mcp-Method` or `Mcp-Name` headers now fail closed when those headers disagree with the JSON-RPC body.
- **`_meta` inspection coverage** (`core/preflight.py`, `core/rules_engine.py`): request `_meta` is explicitly covered by L0 regression tests and L1 recursive matching so future stateless MCP metadata cannot become a bypass lane.
- **Richer policy explanations** (`core/policy.py`): policy explanations now include active profile, final verdict, and semantic role in addition to raw/effective actions.
- **Management-plane surface filtering** (`core/management.py`, `core/proxy.py`): native Vanguard tools are now filtered by management-plane mode and caller principal, so `operator_only` exposes mutating tools only to admin-scoped operators.
- **Management action audit/risk trail** (`core/management.py`, `core/risk.py`): successful management actions are logged, denied attempts remain audited, and denied or mutating actions are recorded in the risk engine.
- **Opt-in receipt chaining** (`core/receipts.py`, `core/proxy.py`): runtime receipt JSONL can now include local hash-chain fields for deletion, reordering, and mutation detection before export/signing.
- **Receipt extensions** (`core/receipts.py`, `core/proxy.py`): optional McpVanguard receipt extensions can include policy-explanation hashes and tool-capability labels without embedding full operator explanations.
- **Optional Redis/RE2 packaging** (`pyproject.toml`): Redis and Google RE2 are now optional install extras while `dev` and `full` installs keep the deployment/test stack available.

### Documentation

- Updated README, deployment, architecture, Railway deployment, benchmark, and block-decision documentation with safe hosted baseline, false-positive tuning guidance, capability override guidance, install modes, session-budget controls, SIEM audit fields, Redis shared-state limitations, Anthropic MCP tunnel guidance, MCP 2026-07-28 release-candidate compatibility notes, and management-plane boundaries.
- Added [docs/ANTHROPIC_MCP_TUNNELS.md](docs/ANTHROPIC_MCP_TUNNELS.md) and [docs/MCP_2026_07_28_RC_COMPATIBILITY.md](docs/MCP_2026_07_28_RC_COMPATIBILITY.md).

### Verification

- Full local verification before release prep: `517 passed, 2 skipped`.
- Targeted hosted-header, `_meta`, and receipt/version tests pass locally.
- `git diff --check` passes locally, with only normal Windows CRLF warnings.
- Built release artifacts locally:
  - `dist/mcp_vanguard-2.1.2-py3-none-any.whl`
  - `dist/mcp_vanguard-2.1.2.tar.gz`
- Wheel install smoke passed from the local artifact with `core.__version__ == "2.1.2"`.
- GitHub CI, CodeQL, dependency audit, SBOM, Railway deployment, and PyPI Trusted Publishing remain external release gates after push.

## [2.1.1] - 2026-06-08 (Runtime Hardening Patch)

### Security and Correctness

- **Recursive L1 argument inspection** (`core/rules_engine.py`): Extended deterministic rule inspection beyond the standard MCP argument names so common custom fields such as `file`, `cmd`, nested path-like keys, and array-form commands are inspected before upstream execution.
- **Safe-zone coverage expansion** (`core/rules_engine.py`): Safe-zone enforcement now checks recursive path-like arguments instead of relying only on top-level canonical path fields, reducing bypass risk for custom tool schemas.
- **Semantic fail-closed behavior** (`core/semantic.py`): Layer 2 async timeout handling now preserves configured fail-closed behavior instead of silently degrading to an allow-path decision.
- **Streamable HTTP resource guards** (`core/sse_server.py`): Added request-rate, concurrency, and session-count enforcement around the `/mcp` transport path to match the documented hosted-gateway hardening posture.
- **JSON-RPC validation** (`core/proxy.py`): Non-object JSON-RPC requests now return `-32600 Invalid Request` instead of entering the normal forwarding path.
- **Shared behavioral timing** (`core/behavioral.py`): Redis-backed behavioral windows now use epoch timestamps for safer multi-process/shared-state behavior.

### CI and Tooling

- **Phase 7 scheduled workflow repair** (`scripts/phase7_prepare_log.py`, `scripts/phase7_report.py`): Fixed direct script execution in the scheduled Phase 7 measurement workflow and made generated JSON artifact loading more robust across CI and Windows-local workflows.

### Documentation

- Updated README, deployment, benchmark, architecture, and research documentation to describe the layered enforcement path as the current public release posture rather than a release-candidate promise.
- Added/clarified public research framing for layered MCP enforcement while keeping corpus-scoped metrics, false-positive tradeoffs, and research-only GPU/hardware-attestation work out of the product claim.

### Verification

- Full local verification before release prep: `460 passed, 2 skipped`.
- Targeted Phase 7 report/log tests pass locally.
- GitHub CI, CodeQL, dependency audit, SBOM, Railway deployment, and PyPI Trusted Publishing remain external release gates after push.

## [2.1.0] - 2026-06-05 (Layered Enforcement Release)

### Security

- **Layer 0 Preflight** (`core/preflight.py`): Added explicit preflight normalization layer with structured findings (URL decoding, NFKC, zero-width stripping, mixed-script detection, oversize/depth/NaN gating, comment trust suffix detection, authority laundering, scorer-targeting instructions). Preflight findings feed into audit, telemetry, risk engine, and semantic context.
- **Layer 1.5 Camouflage Detector** (`core/camouflage.py`): Added trust-signal and semantic camouflage detection for shell/SQL/Python/config comment trust labels, multilingual trust labels, scorer manipulation, and authority laundering. Camouflage findings are wired into risk engine and semantic prompt context.
- **Layer 7 Final Policy Composition** (`core/policy.py`): Added explicit policy composer with `PolicyVerdict`, `PolicyAction` (ALLOW/WARN/REVIEW/SHADOW-BLOCK/BLOCK), and `compose_verdict` function. Enforces the invariant that no later layer downgrades an earlier deterministic block. Added minimal `REVIEW` webhook payload path.
- **Product Profiles** (`core/profiles.py`): Added named deployment profiles (`monitor`, `balanced`, `strict`) with immutable defaults. Profile resolution respects explicit environment variable overrides. Strict profile enables semantic by default, blocks enumeration, forces fail-closed semantic behavior, and warns when Redis is absent.
- **Strict Overlay Rules** (`rules/strict_overlay.yaml`): Added strict-only deterministic rules for anti-forensics, procfs exposure, SSRF (localhost + RFC1918), container escape (Docker + Kubernetes), resource exhaustion, supply-chain/package hooks, encoded execution (base64, hex, octal, ROT13), and expanded credential stores (cloud CLI configs, browser stores, keychains).
- **Management Plane Privilege Separation** (`core/management.py`): Added `VANGUARD_MANAGEMENT_PLANE_MODE` (`disabled` / `same_session_dev` / `operator_only`). Mutating management operations require admin scope. All management attempts are auditable and recorded in RiskEngine.
- **L2 Semantic Advisor Hardening** (`core/semantic.py`): Semantic scoring now receives structured context from L0 preflight, L1.5 camouflage, and L1 rule findings. Added provider metadata to results. Parse failures and empty content are treated as fail-closed in strict profile. Added tests proving L2 cannot downgrade deterministic blocks.
- **L3 Behavioral/Risk Productization** (`core/behavioral.py`, `core/risk.py`): Strict profile enables behavioral by default. Added Redis startup warnings. Added risk events for L0 and L1.5 findings, and repeated deterministic blocks. Multi-turn behavioral sequences tested.
- **Runtime Receipt Emission** (`core/receipts.py`): Added opt-in `receipt_v1` JSONL emission for `mcp-receipt`. Receipt events are disabled by default, separate from audit logs, and include canonical request/normalized-message hashes, profile context, policy decisions, and findings without embedding raw tool arguments.

### Added

- **Profile-aware CLI**: `--profile` flag on `vanguard start`, `vanguard sse`, and `vanguard benchmark-run`.
- **Benchmark profile support**: Benchmark runner evaluates cases with the selected profile, loading strict overlay rules when `VANGUARD_PROFILE=strict`.
- **Layered benchmark corpora**: Added `layered_strict_adversarial_cases.yaml`, `layered_balanced_benign_cases.yaml`, `layered_behavioral_sequences.yaml`, and `layered_profile_matrix.yaml`.
- **Packaged rules fallback**: `RulesEngine` loads rules from `importlib.resources` when `rules/` directory is not present on disk, enabling correct benchmark execution from installed wheels.
- **L0 telemetry**: Added `l0_findings` counter to telemetry metrics.
- **Safe-zone operator guide**: Added explicit documentation for tuning `rules/safe_zones.yaml` so filesystem perimeter blocks are intentional rather than surprising.
- **Benchmark interpretation guide**: Added public guidance explaining what the benchmark suites do and do not prove, including why curated pass rates are not universal security claims.

### Changed

- **Inspection pipeline order**: Formalized layer order: L0 Preflight → Auth Policy → L1 Rules → L1.5 Camouflage → L2 Semantic → L3 Behavioral → Final Policy Composer → Audit.
- **RulesEngine reload**: Now supports atomic reload from both filesystem and packaged resources.
- **Profile-specific rule isolation**: Proxy construction now reloads the singleton rules engine through the constructor path so strict-only overlays cannot leak into later balanced/monitor proxies in the same Python process.
- **Benchmark harness isolation**: Auth-policy benchmark cases now clear safe zones inside the auth harness so jail policy cannot mask WARN/BLOCK auth expectations.

### Packaging and Release Gates

- Release gate targets: wheel build, sdist build, `twine check`, clean-venv smoke install, and CLI entrypoint validation.
- Verified layered benchmark corpora load correctly outside repo cwd during local development.
- Strict layered benchmark suite: 35/35 cases pass locally when `VANGUARD_PROFILE=strict`.
- GPU hardening suite remains covered by the existing benchmark corpus.
- Full local verification before release cut: Linux/WSL `445 passed`; Windows `443 passed, 2 documented platform skips`.
- GitHub CI, CodeQL, dependency audit, SBOM, Railway deployment, and PyPI Trusted Publishing remain external release gates after push.

## [2.0.1] - 2026-05-29 (Post-Release Hardening Patch)

### Security and Correctness

- **Post-release audit fixes**: Patched the confirmed high-priority audit findings from the `2.0.0` follow-up pass, including SSE rate-limit fallthrough, shared DEGRADE-mode config mutation, unreachable entropy critical-risk recording, orphaned semantic task handling on L3 blocks, semantic event classification, management-tool guardrails, safe-zone path-key coverage, and ambiguous tool safety hints.
- **Semantic false-positive tuning**: Updated the Layer 2 semantic prompt to treat quoted strings, incident notes, documentation excerpts, log-analysis snippets, and educational examples as benign context unless the actual tool action is suspicious.
- **Risk and benchmark accounting**: Added semantic-specific risk event handling and benchmark quality metrics for adversarial block rate, benign allow rate, false-positive rate, and false-negative rate.

### Added

- **Local/offline semantic mode guidance**: Added `docs/LOCAL_SEMANTIC_MODE.md` plus deployment-doc updates for Ollama, LM Studio, llama.cpp, and OpenAI-compatible local endpoints.
- **GPU-derived benchmark hardening**: Added curated adversarial, benign false-positive, and semantic-threshold corpora while keeping raw R&D notes out of the public release promise.
- **Hardening benchmark corpora**: Added paired adversarial and benign false-positive benchmark corpora, plus a synthetic semantic-threshold corpus.
- **New benchmark commands**: Added `vanguard gpu-harden` and `vanguard gpu-thresholds` for repeatable hardening smoke tests and threshold-sensitivity checks.
- **Phase 7 measurement tooling**: Added local measurement, mock L2, Redis code-path, live-evidence, closeout, status, markdown-report, and results-log draft scripts, plus a scheduled/manual `phase7-measurement` GitHub Actions workflow.

### Changed

- **Release docs**: Updated README and deployment docs to point to the local semantic guide, use the canonical Railway template link, and clarify Redis, semantic-threshold, and operator-warning language.
- **Project metadata**: Updated package project URLs to the current ProvnAI website/documentation URLs.

### CI/CD and Code Quality

- **Lint hardening**: Resolved 52 ruff errors across `core/` — fixed E402 (import order), E701 (multi-statement lines), E722 (bare except), and F401 (unused imports) in `cli.py`, `proxy.py`, `vex_client.py`, `behavioral.py`, and related modules.
- **CI action version correction**: Fixed invalid GitHub Action versions across all 6 workflows (`test.yml`, `security-audit.yml`, `sbom.yml`, `publish.yml`, `codeql.yml`, `phase7-measurement.yml`): `actions/checkout@v6` → `v4`, `actions/setup-python@v6` → `v5`, `actions/upload-artifact@v7` → `v4`.

### Notes

- Redis overhead, real local L2 throughput, and GPU attestation remain live-evidence gates. They are intentionally documented as external proof items, not shipped GPU product claims.
- GPU acceleration and hardware attestation are still research-only and are not part of the `2.0.1` product promise.

## [2.0.0] - 2026-05-22 (The Integrity Gateway Release)

### Security and Platform

- **Transport and gateway hardening** (`core/sse_server.py`, `core/session.py`, `core/proxy.py`): Added a hardened Streamable HTTP `/mcp` path alongside the existing SSE bridge, tightened session validation and lifecycle handling, added safer bind and proxy-header trust behavior, and strengthened gateway-side request ownership checks.
- **Metadata trust-boundary inspection** (`core/metadata_inspection.py`, `core/proxy.py`): Added server-to-agent inspection for `initialize.result.instructions` and `tools/list` metadata, with `block`, `warn`, and selective tool-filtering behavior to stop poisoned metadata before it reaches downstream models.
- **Cross-server isolation** (`core/session_isolation.py`, `core/behavioral.py`, `core/session.py`, `core/models.py`): Added deterministic `server_id` tracking, partitioned behavioral state by `(session_id, server_id)`, and surfaced cross-server boundaries in audit and session state so one upstream can no longer pollute another's decisions.
- **Server integrity and capability drift controls** (`core/server_integrity.py`, `core/capability_fingerprint.py`, `core/proxy.py`, `core/cli.py`): Added upstream server manifests, runtime drift enforcement, passive capability fingerprinting, baseline bundle workflows, and warn/block handling for capability drift.
- **Supply-chain trust verification** (`core/provenance.py`, `core/supplier_signatures.py`, `core/sigstore_bundle.py`, `core/proxy.py`, `core/cli.py`): Added signed upstream manifests, provenance verification hooks, detached artifact-signature checks, Sigstore bundle verification, identity-aware Sigstore certificate checks using allowed certificate identities and OIDC issuers, provider-style Fulcio claim verification for build/source metadata, GitHub-compatible repository/ref/SHA/trigger/workflow-name verification, and offline transparency-evidence validation for tlog entries, trusted `logId.keyId` allowlisting, inclusion promises/proofs, hashedrekord consistency, and certificate-validity time insertion.
- **Authorization maturity** (`core/auth.py`, `core/sse_server.py`, `core/proxy.py`): Added a principal-aware auth model, verified JWT/JWKS support for configured bearer auth, issuer/audience/claim/scope checks, JWKS URL and OIDC discovery support, cache and refresh-on-`kid`-miss behavior, Bearer challenge handling at the HTTP boundary, and auth-aware destructive-tool enforcement.
- **Benchmark and taxonomy coverage** (`core/benchmarks.py`, `core/taxonomy.py`, `rules/mcp38_coverage.yaml`): Added MCP-38 coverage mapping, an executable benchmark corpus, CLI benchmark reporting, and runnable benchmark evaluation to make security coverage measurable instead of purely descriptive.
- **Risk, fleet, and assurance work** (`core/risk.py`, `core/fleet.py`): Added risk scoring and tiered degrade/block behavior, plus fleet-oriented signed-rule sync plumbing and expanded assurance coverage.

### Added

- **New core modules**:
  - `core/auth.py`
  - `core/benchmarks.py`
  - `core/capability_fingerprint.py`
  - `core/fleet.py`
  - `core/metadata_inspection.py`
  - `core/risk.py`
  - `core/server_integrity.py`
  - `core/session_isolation.py`
  - `core/taxonomy.py`
- **New rule and taxonomy assets**:
  - `rules/mcp38_coverage.yaml`

### Changed

- **Release verification posture**: The repository now has a cleaner release-hardening baseline across packaging, CI, and public documentation, with the shipped gateway and integrity scope separated more clearly from longer-horizon platform work.
- **Management and operator tooling**: Auth cache management, rule reload, and integrity workflows are now part of the verified management surface instead of being treated as informal helpers.
- **Release posture**: The project now has a clearer split between shipped platform/security work and longer-horizon research-track ideas, reducing ambiguity in public release claims.

### Operator Notes

- Management and integrity features should be described using **server integrity**, **baseline verification**, and **capability drift** language, not full SBOM language.
- JWT/JWKS support in this release covers the verified bearer-auth path described in the implementation and tests, including Ed25519 / EdDSA JWT verification.
- Regex safety in this release includes RE2-backed matching through the shared safe-regex backend, with explicit fallback behavior for environments without the wheel.
- Broader control-plane work and other longer-horizon platform ideas are intentionally outside the core `2.0.0` release promise.

### Verification

- **Release scope validation**: Transport, metadata, auth, integrity, benchmark, cross-server isolation, and management/integrity recovery paths all have dedicated test coverage in the current tree.
- **Release packaging validation**: CI now builds the distribution artifacts and smoke-installs the packaged CLI before publish.

---

## [1.9.0] - 2026-04-12 (The Isolation Gate Release)

### Security — Phase 6: Cross-Server Isolation

- **Cross-Server Behavioral Partitioning** (`core/behavioral.py`): The behavioral state registry (`_states`) is now keyed on `(session_id, server_id)` tuples instead of plain `session_id` strings. This guarantees that sliding-window counters (BEH-001 scraping, BEH-002 enumeration, BEH-005 flooding), sensitive read histories (BEH-003 privilege escalation), and Shannon entropy token buckets are fully isolated per upstream MCP server identity. One server's traffic can no longer pollute the security decisions made for another.
- **Deterministic Server Identity** (`core/session_isolation.py`): New module providing `derive_server_id(server_command)` — a stable 12-character SHA-256 fingerprint of the upstream command argv. Derives the same ID on every restart with no configuration required. Stable for single-upstream deployments (zero behavior change).
- **Session-Level Server Tracking** (`core/session.py`): `SessionState` now carries a `server_id` field. `SessionManager.create()` accepts and persists it. `session.summary()` exposes it for management tools and dashboards.
- **Audit Trail Traceability** (`core/models.py`): `AuditEvent` gains a `server_id` field. Text log format includes `[srv:xxx]` when set; JSON format includes the full field. Every blocked or warned event is now traceable to the specific upstream server that triggered it.
- **Cross-Server Boundary Detection** (`core/session_isolation.py`): `check_server_boundary()` emits `CrossServerTransitionEvent` and a `WARNING`-level log when an incoming server identity differs from the session's recorded identity. Prepares for future multi-upstream gateway enforcement.
- **Bonus: Metadata Inspection ReDoS Guard** (`core/metadata_inspection.py`): The four META-001–004 prompt-injection pattern searches are now executed inside a `ThreadPoolExecutor` with a 100ms timeout (matching `rules_engine.py`). On timeout, the inspection fails-closed with a `META-REDOS` block. Closes the last bare-regex execution path in the codebase.

### Added

- **`core/session_isolation.py`** (NEW): `derive_server_id()`, `CrossServerTransitionEvent`, `check_server_boundary()`.
- **`tests/test_cross_server_isolation.py`** (NEW): 15 tests proving partition guarantees, boundary detection, server ID derivation stability, audit event formatting, and positive-control intra-server detection.
- **Redis key partitioning**: All Redis keys for behavioral state (`vguard:beh:*`) now include `server_id` in their namespace (`vguard:beh:{session_id}:{server_id}:*`).

### Changed

- `VanguardProxy.__init__` gains an optional `server_id` parameter; defaults to `derive_server_id(server_command)`.
- `SessionManager.create()` gains `server_id` optional parameter.
- `behavioral.inspect_request()`, `inspect_response()`, `get_state()`, `clear_state()` all gain `server_id: str = "default"` parameter — fully backwards compatible.
- `VanguardStreamableSessionManager._run_session()` and `handle_sse()` in `sse_server.py` now derive and pass `server_id` to `VanguardProxy`.
- `test_management_tools.py` and `test_proxy_response_path.py` updated to use tuple key format and `derive_server_id` respectively.

### Test Results

- **204 passed, 1 skipped** (previously 125+ on core suite; 15 new isolation tests added).
- The 1 skipped is a pre-existing platform-conditional test. Zero regressions.

---

## [1.8.2] - 2026-04-06 (The Trust Anchor Release)

### Security
- **Detached Rule Signatures** (`core/signing.py`, `core/cli.py`): `vanguard update` now requires a detached Ed25519 signature over `rules/manifest.json` by default, closing the remaining unsigned-update supply-chain gap. Added built-in trusted signer pinning plus `--trust-key-file` support for private registries.
- **Management Surface Default-Off** (`core/proxy.py`, `core/cli.py`): Native `vanguard_*` tools are no longer exposed by default. They must be explicitly enabled with `VANGUARD_MANAGEMENT_TOOLS_ENABLED=true` or CLI flags, and disabled calls now fail closed with audit coverage.
- **Management Audit Coverage** (`core/proxy.py`): Native Vanguard tool calls now enter the audit trail instead of bypassing it.
- **Response-Path Integrity** (`core/proxy.py`): Response blocking now returns valid JSON-RPC errors and throttling preserves whole-frame JSON-RPC output instead of fragmenting messages.

### Changed
- **Self-Contained Dashboard** (`core/dashboard.py`): Removed third-party CDN dependencies for the dashboard frontend. The UI is now fully self-hosted and no longer depends on HTMX or Tailwind CDNs.
- **Packaging Cleanup** (`pyproject.toml`, `requirements.txt`): Added `cryptography` for detached signature verification and removed the unused `fastapi` dependency from the runtime package manifest.
- **Release Tooling** (`core/cli.py`): Added `vanguard keygen` and `vanguard sign-rules` commands for rule-signing workflows.

### Added
- **Signed Manifest Artifacts** (`rules/manifest.json`, `rules/manifest.sig.json`): The repo now ships a verified manifest plus detached signature for the current rule bundle.
- **Regression Coverage** (`tests/test_cli_update.py`, `tests/test_rules_manifest.py`, `tests/test_dashboard_assets.py`, `tests/test_proxy_enrichment.py`): Added tests for detached signatures, trusted signer verification, dashboard self-containment, and management-tool default-off behavior.

## [1.8.1] - 2026-03-22 (Titan-Grade Security Hardening)

### Security (Audit Remediation)
- **CRIT-1: Format-Independent Safe Zones** (`core/rules_engine.py`): Decoupled tool call detection from JSON-RPC method names. Validates tool arguments based on structure, defeating format-evasion bypasses.
- **CRIT-2: Default-Deny Policy** (`core/rules_engine.py`): Introduced `VANGUARD_DEFAULT_POLICY=DENY` support for ultra-secure "fail-closed" environments.
- **CRIT-3: Session TTL & Memory Management** (`core/behavioral.py`): Fixed a memory leak in the behavioral layer by implementing automatic LRU-style pruning of inactive session states.
- **MED-1: Proxy Error Transparency** (`core/proxy.py`): Replaced silent exception swallowing with structured error logging for improved auditability.
- **MED-2: Payload Size Enforcement** (`core/proxy.py`): The proxy now explicitly rejects oversized strings instead of truncating them, preventing "tail-end" regex bypasses.
- **MED-3: Semantic Context Hardening** (`core/semantic.py`): Protected the LLM intent classifier against context-injection attacks by strictly fencing tool parameters and enforcing instruction-ignoring system prompts.
- **Windows UNC Blocking** (`core/jail.py`): Explicitly blocks all path patterns starting with `\\` to forestall extended-length or network share bypasses.
- **Linux Compatibility** (`core/jail.py`): Added graceful `ENOSYS` fallback for `openat2` to ensure stability on older Linux kernels while maintaining security.

### Added
- **Adversarial Test Suite** (`tests/test_audit_remediation.py`): 4 new high-intensity security tests targeting the identified audit bypasses. 

---

## [1.8.0] - 2026-03-21 (The Guardian Bundle Release)

### Claude Desktop Directory Readiness (MCPB)
- **MIT License Migration**: Transitioned from Apache 2.0 to MIT to satisfy Anthropic's strict directory requirements.
- **MCPB Bundling**: Implemented the `.mcpb` (Model Context Protocol Bundle) specification for one-click installation.
- **Node.js Bridge**: Added a lightweight Node.js wrapper (`index.js`) to satisfy host-side architectural preferences while maintaining the Python security core.
- **Compliance Auditor**: New `vanguard audit-compliance` CLI command for instant verification against directory rules.
- **Testing Guide**: Added `TESTING_GUIDE.md` for directory reviewers, providing sample prompts to verify all security layers.

### Test Architecture & Reliability
- **In-Process E2E Testing**: Refactored major integration tests to use environment-aware threading, eliminating "Socket Connection Refused" flakes on Windows.
- **Titan-Grade Certification**: Achieved a certified 94/94 green test state across hybrid Windows/Linux environments.

### Cloud Deployment (Railway)
- **Polyglot Nixpacks**: Added a custom `nixpacks.toml` to provision both Node.js and Python 3.11 in a single container.
- **Bunkerized Build**: Implemented an isolated virtual environment (`/opt/venv`) and static versioning to eliminate `.git` dependencies during cloud deployment.

## [1.7.0] - 2026-03-20 (The Hermetic Gate Release)

### Fixed
- **CLI Precedence**: Fixed a bug where CLI boolean defaults would unintentionally override `.env` security settings.
- **Sticky Throttling**: The entropy-based behavioral governor now correctly clears the throttle state once the token bucket refills above 50%.
- **Safe Zone Depth**: Fixed schema enforcement for `max_entropy` and `recursive` flags in safe_zones.yaml.

### Changed
- **Testability Refactor**: Promoted SSE and health handlers to module-level functions with a unified `ServerContext`, enabling direct unit testing of security logic.
- **Diagnostic Logging**: Hardened security logs with `repr()` escaping to prevent Unicode console-injection or crash-loops.

---

## [1.6.0] - 2026-03-17 (Production Hardening Release)

### Added
- **Interactive Initializer**: New `vanguard init` command for rapid developer onboarding and `.env` generation.
- **Claude Desktop Integration**: New `vanguard configure-claude` command to automatically protect your local agents.
- **Security Dashboard**: Real-time, HTMX-powered visual monitor via `vanguard ui`.

### Security
- **Shadow Mode (Audit Only)**: Non-blocking policy assessment via `VANGUARD_MODE=audit`. Log security violations without disrupting workflows.
- **Universal Cloud Provider Support**: Native integration for DeepSeek, Groq, Mistral, and vLLM via `VANGUARD_SEMANTIC_CUSTOM_URL`.
- **Deep Health Probes**: `/health` now performs live connectivity checks against Redis and Semantic LLMs for cloud-native reliability.
- **SIEM-Ready JSON Logging**: Optional structured output via `VANGUARD_AUDIT_FORMAT=json` for enterprise SOC ingestion.

### Fixed
- **Partitioned Throttling**: Fixed proxy hangs on high-entropy data by implementing chunked streaming in `core/proxy.py`.

## [1.5.0] - 2026-03-15 (Forensic Hardening Update)

### Security (Spec Alignment)
- **Entropy-Aware Token Bucket Governor** (`core/behavioral.py`): Implemented formal governor for deterministic rate-limiting. High-entropy data now incurs a $10\times$ penalty relative to standard tool calls.
- **1 Byte/Second Hard Throttle** (`core/proxy.py`): Implemented physical stream clamping for compromised agent sessions.
- **Forensic Gate Sensors** (`core/models.py`): The `SecureToolManifest` now includes `gate_sensors` for OS-level path resolution and forensic audit finality.

### Changed
- **Modular Semantic Scorer**: Refactored Layer 2 to support multiple cloud providers (OpenAI, MiniMax) via a unified OpenAI-compatible handler.
- **JSON Extraction Robustness**: Implemented a resilient extraction engine to handle non-standard LLM conversational output.
- **Backend Priority**: Standardized L2 provider selection order (OpenAI > MiniMax > Ollama).
- **CLI & Log Formatting**: Updated terminal output and audit log signatures for improved industry alignment and enterprise ingest compatibility.
- **Project Identity**: Unified authorship and project metadata under the **Provnai Development Team**.
- **Documentation Standards**: Refined README and deployment guides for technical precision and authoritative tone.
- **Unified Forensic Schema**: Optimized all security violation outputs to map directly to VEX forensic traces.

## [1.2.0] - 2026-03-15 (Titan-Grade L1 Perimeter)

### Security (TitanGate Alignment)
- **Linux path-boundary hardening** (`core/jail.py`): Replaced fragile string matching with deterministic path resolution using `openat2` (`RESOLVE_BENEATH`) where available. This materially strengthens Safe Zone enforcement against symlink and `../` escape attempts, while still relying on normal OS/container isolation for complete sandboxing.
- **Handle-Based Canonicalization (Windows)** (`core/jail.py`): Defeated 8.3 shortname bypasses (`PROGRA~1`) and junction point tricks utilizing `GetFinalPathNameByHandleW`. Explicitly blocks extended paths (`\\?\`) and DOS device namespaces (`\\.\`).
- **Risk-Weighted Entropy Throttling** (`core/behavioral.py`): The rate-limiter now acts as a Shannon Entropy ($H(X)$) scouter. It samples payload data to instantly detect cryptographic keys, binary data, or encrypted exfiltration attempts.
  - Payloads with $H > 7.5$ trigger an immediate `BEH-006` block.
  - Payloads with $H > 6.0$ apply a massive virtual penalty multiplier, freezing the session before data siphoning can occur.

### Added
- **Secure Tool Manifests** (`core/models.py`, `core/vex_client.py`): Standardized the handoff payload for the VEX backend. Blocked calls now generate an OPA-compatible JSON manifest including the Principal, Action, Resource, Entropy Score, and an environment snapshot, ensuring unpolluted forensic audits.
- **Granular Safe Zones** (`rules/safe_zones.yaml`): Introduced a new deterministic configuration file that intercepts tool calls *before* legacy regex processing runs. Allows per-tool definitions (`allowed_prefixes`, `max_entropy`, `recursive`).
- **The Breakout Test Suite** (`tests/test_breakouts.py`): Integrated a dedicated stress-test suite specifically targeted at simulating path traversal, symlink spoofing, and DOS namespace attacks. (All 27 core tests passing).

## [1.1.4] - 2026-03-10 (Security Audit Hardening)


### Security
- **Fail-Closed ReDoS Guard** (`core/rules_engine.py`): We've re-engineered the regex timeout logic. If a complex pattern takes too long to match, the system now **blocks by default** (fail-closed) instead of letting it slip through.
- **Zero-Bypass Network Rules** (`rules/network.yaml`): Closed a blind spot in our network rules. We now inspect `params.command` and `params.arguments.command` for encoded IP bypasses, catching attacks that hide inside tool arguments.
- **Defensive Semantic Scoring** (`core/semantic.py`): The semantic layer now ships in "Fail-Closed" mode by default. If your LLM provider is down or reaching a timeout, Vanguard will protect your system by blocking suspicious-looking intents.
- **Windows Sensitive Path Monitoring** (`core/behavioral.py`): Expanded our behavioral layer to include native Windows sensitive paths (like `System32/config/SAM`). Your Windows deployments are now as safe as our Linux ones.
- **Parallel Rule Executions**: Increased the regex thread pool from 4 to 12 workers to handle high-concurrency security audits without breaking a sweat.

### Added
- **Finality Receipts** (`core/vex_client.py`): Vanguard now explicitly verifies and logs the receipt of CHORA EvidenceCapsules. You get cryptographic proof that every block was recorded.
- **Production Readiness Alert**: Added clear guidance in the deployment docs regarding the **critical requirement of Redis** for horizontal scaling and state persistence.

### Fixed
- **Glob False Positives** (`rules/commands.yaml`): Refined `CMD-010` to allow everyday terminal globs like `ls *.py` while keeping up the guard against dangerous traversal attempts.
- **Unicode Homograph Expansion**: Significantly broadened our detection of visual spoofing characters (Cyrillic, Greek, Math variations) in the filesystem rules.
- **Optimized Production Logs**: Switched the default audit log level to `INFO` to keep your production logs clean and free of unnecessary noise.

## [1.1.3] - 2026-03-10 (Stability & Concurrency Update)

### Added
- **Stable Concurrency** (`core/sse_server.py` & `core/session.py`): Implemented `asyncio.Lock` and `threading.Lock` for atomic registry management. Prevents race conditions during high-burst connection surges.
- **Strict Authentication Decoding**: Authentication headers now enforce strict UTF-8 decoding in the SSE transport layer.
- **Enhanced Behavioral Reporting**: `BEH-003` (Privilege Escalation) blocks now include the specific sensitive path(s) that triggered the violation.

### Changed
- **Session Entropy**: Upgraded to full UUID4 for session identifiers.
- **Input Hardening**: Added length-based safeguards to prevent resource exhaustion.
- **Atomic Sessions**: Guaranteed thread-safe session creation and restoration.
- **Clean Shutdown**: Added task cancellation to prevent proxy hangs.
- **Scale Test Suite**: Automated stress test simulating 5,000+ requests.

### Fixed
- Fixed a potential race condition in `SessionManager.create` that could lead to exceeding session capacity.
- Removed vestigial debug logging in behavioral analysis logic.
- Unified block reason formatting across all security layers.

## [1.1.2] - 2026-03-10

### Added
- **Deep Audit Hardening**: Implemented 10 security fixes from the Deep Audit Report.
- **SSE Rate Limiting**: Token-bucket algorithm for transport protection.
- **Fail-Closed Semantic Layer**: High-security mode for LLM-based inspection.
- **Redis Session Persistence**: Session metadata now survives server restarts.
- **IP Allowlisting**: Configurable access control for SSE connections.
- **Dynamic Versioning**: Integrated `setuptools-scm` for flawless releases.

### Fixed
- Fixed SSE version leakage in `/health` endpoint.
- Upgraded directory enumeration (BEH-002) to `BLOCK` mode.
- Expanded Unicode homograph detection (FS-009).
- Resolved PyPI Trusted Publishing OIDC configuration errors.

### Security
- **Constant-Time Authentication** (`core/sse_server.py`): Switched to `hmac.compare_digest` for API key verification to prevent character-level timing attacks.
- **20-Pass Stabilization Loop** (`core/proxy.py`): Upgraded message normalization from 5 to 20 passes. Defeats deep-nested encoding evasion (e.g., 6+ levels of URL/Hex nesting).
- **Fail-Closed Inspection Timeouts** (`core/proxy.py`): Implemented a hard 5-second timeout on the inspection pipeline. Security checks that hang or take too long now trigger an automatic `BLOCK` to prevent "timeout bypasses."
- **Strict State Consistency** (`core/behavioral.py`): Added `VANGUARD_STRICT_REDIS` environment flag. When enabled, the proxy enters a restricted failsafe mode (blocking all tool calls) if the Redis state backend becomes unreachable, preventing "Security Amnesia."
- **Regex Hardening** (`rules/commands.yaml`): Refined `CMD-004` (Command Substitution) and `CMD-010` (Brace/Glob Expansion) patterns to close bypasses involving shell backticks and quoted glob characters.

## [1.0.3] - 2026-03-04

### Changed
- **Railway Certification Suite** (`tests/benchmarks/railway_certification.py`): Added a comprehensive 5-phase certification benchmark suite to validate 100% Postgres finalize rates, SSE interception, and local scaling failsafes against VEX v0.3.0.
- **Forensic Metadata Strategy** (`core/vex_client.py`): VEX audit submissions now extract and transmit sanitized forensic risk indicators (attack class, pattern summary, risk tier) instead of raw malicious payloads. This ensures 100% audit finality by cleanly separating forensic evidence from exploit strings, resolving false-positive rejections from the VEX API safety layer.
- **Railway Deployment Guide** (`docs/railway-deployment-guide.md`): Updated with VEX v0.2.1/v0.3.0 compatibility notes including PostgreSQL backend auto-detection and OTEL tracing configuration.

### Fixed
- **Jailbreak Payload Gap** (`rules/jailbreak.yaml`): Added `params.arguments.message` to the match fields for all Jailbreak and Ignore-Instructions rules. This patches a blind spot where system prompts embedded natively in the `message` argument were bypassing the Layer 1 proxy.
- **Test Import Resolution** (`tests/test_rules.py`): Corrected `from tests.conftest import` to `from conftest import` — the absolute package path was resolving to a stale cached copy in site-packages, causing CI collection failures.

## [1.0.2] - 2026-03-03

### Security
- **Recursive URL Decoding**: `_normalize_message` now loops until the value stabilizes — defeats double and triple URL-encoding attacks (e.g., `..%252F`).
- **Zero-Width Character Stripping**: All Unicode format characters (zero-width space, RTL/LTR marks, zero-width joiners) are now silently removed from all incoming payloads before inspection.
- **Command Separator Blocking** (`CMD-012–015`): Added rules to block command chaining via `;`, `&&`, `||`, `\n`, and `\t` separators.
- **Extended IP Obfuscation Detection** (`NET-008–011`): Blocks IPv6 loopback (`::1`, `::ffff:`), integer-encoded IPs (e.g., `3232235777`), octal-encoded IPs, and leading-zero decimal IPs.
- **Cyrillic/Homograph Path Detection** (`FS-009`): Blocks Cyrillic and Greek lookalike characters in file paths, preventing homograph-based traversal bypasses.
- **SSE API Key Authentication**: `/sse` and `/messages` endpoints now check for an `X-Api-Key` header or `Authorization: Bearer` token when `VANGUARD_API_KEY` is set. The `/health` endpoint remains unauthenticated.
- **ReDoS Timeout Guard**: Every regex match now runs in a thread with a 100ms timeout. Catastrophically backtracking patterns abort cleanly instead of hanging the proxy.

## [1.0.1] - 2026-03-03

### Added
- **Security Normalization**: Implemented recursive URL-decoding and Unicode NFKC normalization for all incoming tool call messages. Mitigates encoding-based bypasses (e.g., `%2e%2e%2f` and fullwidth dot `U+FF0E`).
- **Hardened Rulesets**:
    - **Filesystem**: Added signatures for Null Byte (`\x00`) and redundant slash traversal.
    - **Network**: Added blocks for Cloud Metadata service IPs (AWS/GCP/Azure) and hex-encoded IP addresses to prevent SSRF.
    - **Commands**: Added protection against shell expansion bypasses (brace expansion, globbing, variable expansion).
    - **Privilege Protection**: Added detection for environment-based library injection (`LD_PRELOAD`) and procfs memory hijacks.
- **Core Proxy**: Sub-2ms JSON-RPC proxy for intercepting Agent-to-Server interactions.
- **Cloud Security Gateway (SSE Bridge)**: Implemented `vanguard sse` command for real-time bidirectional JSON-RPC over network streams.
- **Railway/Cloud Support**: One-click deployment configuration via `app.json` and `railway.json` with native Starlette handling.
- **Documentation**: Comprehensive guides for Railway, VEX/Bitcoin anchoring (CHORA), and vulnerability disclosure.
- **E2E Test Suite**: Verified 100% integrity across 50+ test cases in isolated WSL environment.
- **Rules Engine (Layer 1)**: Robust 60+ static signature YAML configuration preventing prompt injection and data exfiltration.
- **Semantic Intelligence (Layer 2)**: Quantized local Ollama API fallback and cloud OpenAI intent-scoring support.
- **Behavioral Analysis (Layer 3)**: Redis-backed sliding window memory analysis for clustered Vanguard deployments.
- **VEX Protocol Integration**: Fire-and-forget payload offloading to the VEX API and CHORA Gate for cryptographic Bitcoin anchoring.
- **CI/CD**: GitHub Actions pipeline configuring seamless PyPI Trusted Publisher releases.
- **Cloud Deployment**: Railway configuration (`railway.json` and `app.json`) for one-click proxy and Redis instantiation.
- **Documentation**: Comprehensive `DEPLOYMENT.md`, `ARCHITECTURE.md`, and `README.md` for full system transparency.

### Fixed
- **Railway/Docker Stability**: Automated `uvloop` detection and disabling; implemented threaded `stdin` reads to bypass container security restrictions.
- **Performance**: Optimized audit logger to prevent race conditions during concurrent rotating events.
- **Audit Scaling**: Restructured `audit.log` module to enforce 100MB bounds with 5-snapshot Native RotatingFileHandler retention.
- **SSE Serialization**: Resolved a critical Pydantic `AttributeError` by correctly validating `JSONRPCMessage` types within the `StreamWrapper` drain loop.
