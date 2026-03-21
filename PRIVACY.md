# Privacy Policy for McpVanguard

**Last Updated: March 20, 2026**

McpVanguard ("we", "our", or "the software") is a security proxy tool designed for the Model Context Protocol (MCP). We prioritize user privacy and local-first data processing.

## 1. Data Collection and Processing
McpVanguard operates primarily as a **local-only** tool. 
- **Tool Interception**: We process JSON-RPC messages between your AI agent and MCP servers. This processing happens entirely on your local machine.
- **Audit Logs**: Security audit logs are stored locally in `audit.log`. These logs are never transmitted to our servers unless you explicitly share them for support.
- **Semantic Scoring**: If Layer 2 (Semantic Scorer) is enabled, message fragments may be sent to your configured LLM provider (e.g., OpenAI, Ollama). This data is subject to your provider's privacy policy.

## 2. Telemetry and Analytics
McpVanguard does **not** include tracking, analytics, or home-calling telemetry. No usage data, IP addresses, or metadata are collected by ProvnAI.

## 3. Blockchain Logging (VEX Protocol)
If configured, McpVanguard can anchor signed security manifests to the VEX Protocol. 
- These manifests contain technical details of blocked calls (tool name, rule matched, payload entropy).
- **NO PII** (Personally Identifiable Information) or sensitive file content is included in blockchain anchors. The anchor only serves as a verifiable cryptographic proof that a security enforcement action occurred.

## 4. Third-Party Services
McpVanguard may interact with:
- **MCP Servers**: Local or remote servers you choose to proxy.
- **LLM Backends**: For semantic intent analysis.
- **VEX Protocol**: For decentralized audit logging.

## 5. Contact
For privacy-related inquiries, please contact:
**ProvnAI Security Team**  
Email: [contact@provnai.com](mailto:contact@provnai.com)  
Web: [provnai.com](https://provnai.com)
