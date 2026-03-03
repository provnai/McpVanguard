# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

