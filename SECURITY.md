# Security Policy

## Supported Versions

Currently, only the latest major release of McpVanguard is supported with security updates.

| Version | Supported |
| ------- | --------- |
| 1.1.x   | ✅ Yes |
| 1.0.x   | ⚠️ Critical fixes only |
| < 1.0   | ❌ No |

## Reporting a Vulnerability

As an AI security proxy, taking vulnerabilities seriously is our highest priority. 

If you discover a security vulnerability within McpVanguard, please DO NOT open a public issue.

Instead, please send an encrypted email or a direct message to the core maintainers at **contact@provnai.com**.

We will acknowledge receipt of your report within 48 hours and keep you updated on progress. If your report reveals a significant bypass in the core inspection logic, you may be eligible for a recognition credit and bounty.

## Threat Model

McpVanguard is designed to protect against:
- Malicious AI intent and prompt injection bypassing tool constraints
- Path traversal and unauthorized filesystem access via tools
- Unauthorized command execution and reverse shells
- Unsanctioned data exfiltration to external networks
- Scraping and enumeration behaviors over an active session

It is **NOT** designed to protect against:
- Vulnerabilities within the underlying MCP server code itself (Vanguard acts as a firewall, not a patch for broken servers).
- System-level exploits that do not originate through the MCP JSON-RPC connection.
