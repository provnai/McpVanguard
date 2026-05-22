# Security Policy

## Supported Versions

McpVanguard security updates are provided for the active release line only. Older lines may receive critical guidance, but should not be assumed to receive normal fixes.

| Version | Supported |
| ------- | --------- |
| 2.0.x   | Yes |
| 1.1.x   | Critical fixes only |
| 1.0.x   | No |
| < 1.0   | No |

## Reporting a Vulnerability

If you discover a security vulnerability in McpVanguard, do not open a public issue first.

Please report it privately to **contact@provnai.com** with:

- a description of the issue
- affected version(s)
- reproduction steps or proof of concept, if available
- any suggested mitigation or operational impact you observed

Response expectations:

- we aim to acknowledge reports within 2 business days
- we aim to keep reporters informed during triage and remediation
- we prefer coordinated disclosure after a fix or mitigation is available

At this time, McpVanguard does not offer a formal bug bounty program or security SLA.

## Threat Model

McpVanguard is designed to help protect against:

- malicious AI intent and prompt injection that attempts to bypass tool constraints
- path traversal and unauthorized filesystem access through MCP tool calls
- unauthorized command execution and reverse-shell style behavior
- unsanctioned data exfiltration to external networks
- scraping and enumeration behavior across an active session

McpVanguard is not designed to provide:

- a patch for vulnerabilities inside the underlying MCP server implementation itself
- protection against system-level exploits that do not originate through the MCP request path
- a blanket guarantee that all prompt injection or model misuse is eliminated
- a production security warranty for every deployment shape or tool stack

McpVanguard should be treated as an enforcement layer and control boundary, not as a substitute for secure upstream server design, operational hardening, or infrastructure review.
