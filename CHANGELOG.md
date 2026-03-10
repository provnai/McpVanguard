# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
