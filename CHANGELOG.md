# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-01
### Added
- **Core Proxy**: Sub-2ms JSON-RPC proxy for intercepting Agent-to-Server interactions.
- **Rules Engine (Layer 1)**: Robust 60+ static signature YAML configuration preventing prompt injection and data exfiltration.
- **Semantic Intelligence (Layer 2)**: Quantized local Ollama API fallback and cloud OpenAI intent-scoring support.
- **Behavioral Analysis (Layer 3)**: Redis-backed sliding window memory analysis for clustered Vanguard deployments.
- **VEX Protocol Integration**: Fire-and-forget payload offloading to the VEX API and CHORA Gate for cryptographic Bitcoin anchoring.
- **CI/CD**: GitHub Actions pipeline configuring seamless PyPI Trusted Publisher releases.
- **Cloud Deployment**: Railway configuration (`railway.json` and `app.json`) for one-click proxy and Redis instantiation.
- **Documentation**: Comprehensive `DEPLOYMENT.md` for Enterprise CISOs and clear architectural diagrams showcasing full capabilities.

### Changed
- Refactored legacy in-memory state matrices to horizontally scalable Redis infrastructure.
- Restructured `audit.log` module to enforce 10MB bounds with 5-snapshot Native RotatingFileHandler retention.

