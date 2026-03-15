# Deploy and Host McpVanguard with Railway

**McpVanguard** is an open-source security gateway and active firewall for the **Model Context Protocol (MCP)**. It sits in real-time between AI agents and your tools, intercepting malicious intent, prompt injection, and unauthorized data access before they reach your system.

## About Hosting McpVanguard

Hosting McpVanguard on Railway provides a cloud-native "Security Gateway" (SSE Bridge) for your AI agents. By wrapping your local or remote MCP servers with Vanguard, you gain a persistent, secure endpoint that inspects every JSON-RPC message. Our load-tested core ensures sub-20ms security latency even under high-concurrency bursts.

## Common Use Cases

- **Secure Remote Access**: Allow mobile or web-based AI agents to connect to your local tools securely over the internet.
- **Enterprise Governance**: Implement deterministic OS-Level Safe Zones to jail agent payloads, and deploy Shannon Entropy Scouters to catch data exfiltration thresholds.
- **Audit & Compliance**: Integrate with the VEX Protocol to generate immutable, anchored receipts of every blocked attack for compliance auditing.
- **Multi-Server Aggregation**: Use Vanguard as a central security hub for multiple MCP servers across different environments.

## Dependencies for McpVanguard Hosting

- **Python 3.11+**: The core engine is built on high-performance Starlette and Uvicorn.
- **MCP SDK**: Full compatibility with standard Model Context Protocol servers.
- **VEX Protocol (Optional)**: For immutable audit logging and block verification.
- **Redis (Optional)**: Enables L3 Stateful Behavioral analysis for anomaly detection.

### Deployment Dependencies

- [Official Documentation](https://github.com/provnai/McpVanguard)
- [Railway Partnership Program](https://railway.com/partners)
- [Provnai Open Research](https://provnai.com)

## Why Deploy McpVanguard on Railway?

Railway is the premier platform for deploying AI infrastructure stacks. By deploying McpVanguard on Railway, you get a singular, hardened gateway that simplifies your agentic security stack. Railway manages the networking, scaling, and health monitoring, allowing you to focus on building powerful AI agents without worrying about the underlying security vulnerabilities.
