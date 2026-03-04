# Deploying McpVanguard on Railway 🛡️🚉

This guide explains how to deploy McpVanguard as a production-grade Security Gateway for your AI agents using Railway.

## 🚀 1-Click Deployment

1. Click the **Deploy on Railway** button in the [README](https://github.com/provnai/McpVanguard).
2. Configure your `MCP_SERVER_COMMAND`. This is the command Vanguard will use to spawn your "inner" server (e.g., `npx @modelcontextprotocol/server-filesystem /app/data`).
3. Deploy!

## 🧪 Verifying Your Deployment

Once deployed, Railway will assign you a public URL (e.g., `mcp-vanguard.up.railway.app`). You can verify it is running by visiting the health endpoint:

```bash
curl https://your-project.up.railway.app/health
# Expected: {"status": "ok", "version": "1.0.2"}
```

## 🌉 Connecting Your Agent

To connect an AI agent (like Claude Desktop) to your Railway deployment:

1. Add the following to your agent's configuration:
   ```json
   {
     "mcpServers": {
       "vanguard-remote": {
         "url": "https://your-project.up.railway.app/sse"
       }
     }
   }
   ```
2. The agent will connect over HTTP/SSE. Vanguard will intercept every tool call locally on Railway before passing it to your server.

## 🛡️ Scaling Security (Optional)

- **Behavioral Analysis**: Add an official Railway **Redis** service to your project. McpVanguard will automatically detect the `REDIS_URL` and enable Layer 3 stateful tracking.
- **Immutable Audits**: Set the `VANGUARD_VEX_URL` and `VANGUARD_VEX_KEY` to stream blocked attacks to a VEX Auditor for cryptographic proof-of-block.

## 🆘 Support

If you encounter issues with the template, please [open an issue](https://github.com/provnai/McpVanguard/issues) or reach out via the [Provnai Research Initiative](https://provnai.com/links).
