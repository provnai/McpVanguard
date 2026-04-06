# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Kernel-Level Jailing (Linux )** (`core/jail.py`): Replaced fragile string-matching with deterministic path resolution using the `openat2` syscall (`RESOLVE_BENEATH`). It is now mathematically impossible for an agent to use symlinks or `../` to escape a designated Safe Zone.
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
