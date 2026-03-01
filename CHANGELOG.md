# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-01
### Added
- **Core Proxy**: Sub-2ms JSON-RPC proxy for intercepting Agent-to-Server interactions.
- **Cloud Security Gateway (SSE Bridge)**: Implemented `vanguard sse` command to transform the proxy into an internet-reachable gateway.
- **Network Transport**: Integrated `Starlette` and `mcp.server.sse` for real-time bidirectional JSON-RPC over network streams.
- **Rules Engine (Layer 1)**: Robust 60+ static signature YAML configuration preventing prompt injection and data exfiltration.
- **Semantic Intelligence (Layer 2)**: Quantized local Ollama API fallback and cloud OpenAI intent-scoring support.
- **Behavioral Analysis (Layer 3)**: Redis-backed sliding window memory analysis for clustered Vanguard deployments.
- **VEX Protocol Integration**: Fire-and-forget payload offloading to the VEX API and CHORA Gate for cryptographic Bitcoin anchoring.
- **CI/CD**: GitHub Actions pipeline configuring seamless PyPI Trusted Publisher releases.
- **Cloud Deployment**: Railway configuration (`railway.json` and `app.json`) for one-click proxy and Redis instantiation.
- **E2E Test Suite**: Added `tests/test_sse_bridge.py` and `tests/test_e2e_vex.py` for verifying system integrity.
- **Documentation**: Comprehensive `DEPLOYMENT.md`, `ARCHITECTURE.md`, and `README.md` for full system transparency.

### Fixed
- **Railway/Docker Stability**: Automated `uvloop` detection and disabling; implemented threaded `stdin` reads to bypass container security restrictions.
- **Performance**: Optimized audit logger to prevent race conditions during concurrent rotating events.
- **Audit Scaling**: Restructured `audit.log` module to enforce 10MB bounds with 5-snapshot Native RotatingFileHandler retention.

