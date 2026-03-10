# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2] - 2026-03-10

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
### Added
- **Core Proxy**: Sub-2ms JSON-RPC proxy for intercepting Agent-to-Server interactions.
- **Cloud Security Gateway (SSE Bridge)**: Implemented `vanguard sse` command to transform the proxy into an internet-reachable gateway.
- **Network Transport**: Integrated `Starlette` and `mcp.server.sse` for real-time bidirectional JSON-RPC over network streams. Refactored to native Starlette app for robust POST/GET route handling and connection stability.
- **Rules Engine (Layer 1)**: Robust 60+ static signature YAML configuration preventing prompt injection and data exfiltration.
- **Semantic Intelligence (Layer 2)**: Quantized local Ollama API fallback and cloud OpenAI intent-scoring support.
- **Behavioral Analysis (Layer 3)**: Redis-backed sliding window memory analysis for clustered Vanguard deployments.
- **VEX Protocol Integration**: Fire-and-forget payload offloading to the VEX API and CHORA Gate for cryptographic Bitcoin anchoring.
- **CI/CD**: GitHub Actions pipeline configuring seamless PyPI Trusted Publisher releases.
- **Cloud Deployment**: Railway configuration (`railway.json` and `app.json`) for one-click proxy and Redis instantiation.
- **E2E Test Suite**: Added `tests/test_sse_bridge.py` and `tests/test_e2e_vex.py` for verifying system integrity. Achieved **47/47 passing tests** in an isolated WSL verification environment.
- **Documentation**: Comprehensive `DEPLOYMENT.md`, `ARCHITECTURE.md`, and `README.md` for full system transparency.

### Fixed
- **Railway/Docker Stability**: Automated `uvloop` detection and disabling; implemented threaded `stdin` reads to bypass container security restrictions.
- **Performance**: Optimized audit logger to prevent race conditions during concurrent rotating events.
- **Audit Scaling**: Restructured `audit.log` module to enforce 10MB bounds with 5-snapshot Native RotatingFileHandler retention.
- **SSE Serialization**: Resolved a critical Pydantic `AttributeError` by correctly validating `JSONRPCMessage` types within the `StreamWrapper` drain loop.

