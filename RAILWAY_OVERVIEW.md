# Deploy and Host McpVanguard with Railway

**McpVanguard** is an enterprise-grade security gateway and active firewall for the **Model Context Protocol (MCP)**. It acts as a real-time defense layer between AI agents and your tools, preventing malicious intent, prompt injection, and unauthorized data exfiltration before they reach your system.

## About Hosting McpVanguard

Hosting McpVanguard on Railway provides a cloud-native "Security Gateway" (SSE Bridge) for your AI agents. By wrapping your local or remote MCP servers with Vanguard, you gain a persistent, secure endpoint that inspects every JSON-RPC message. Railway's infrastructure ensures that your defense layer is always-on, high-performance, and easily scalable with minimal configuration.

## Common Use Cases

- **Secure Remote Access**: Allow mobile or web-based AI agents to connect to your local tools securely over the internet.
- **Enterprise Governance**: Implement 60+ static security rules to prevent agents from accessing sensitive files like SSH keys or environment secrets.
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
