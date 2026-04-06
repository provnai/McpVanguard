"""
core/dashboard.py
A lightweight Starlette dashboard for the McpVanguard audit log.
"""

import json
import os
from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from starlette.applications import Starlette
from starlette.responses import HTMLResponse
from starlette.routing import Route

from core import __version__

LOG_FILE = os.getenv("VANGUARD_LOG_FILE", "audit.log")


class AuditLogItem(BaseModel):
    timestamp: str
    action: str
    session_id: str
    direction: str
    method: Optional[str]
    tool_name: Optional[str]
    reason: Optional[str]
    layer: Optional[int]


def parse_log_line(line: str) -> Optional[AuditLogItem]:
    """Parse a text line or JSON line from the audit log."""
    line = line.strip()
    if not line:
        return None

    if line.startswith("{"):
        try:
            data = json.loads(line)
            ts = datetime.fromtimestamp(data.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
            return AuditLogItem(
                timestamp=ts,
                action=data.get("action", "UNKNOWN"),
                session_id=data.get("session_id", "???")[:8],
                direction=data.get("direction", ""),
                method=data.get("method"),
                tool_name=data.get("tool_name"),
                reason=data.get("blocked_reason"),
                layer=data.get("layer_triggered"),
            )
        except Exception:
            return None

    try:
        ts_part = line[1:20]
        action_start = line.find("[", 21)
        action_end = line.find("]", action_start)
        action = line[action_start + 1 : action_end]

        return AuditLogItem(
            timestamp=ts_part,
            action=action,
            session_id="N/A",
            direction="N/A",
            method=None,
            tool_name=None,
            reason=None,
            layer=None,
        )
    except Exception:
        return None


async def get_dashboard(request):
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>McpVanguard Audit Dashboard</title>
        <style>
            :root {{
                --bg: #08111f;
                --panel: #0e1a2b;
                --panel-alt: #14233a;
                --border: #28405f;
                --text: #e2e8f0;
                --muted: #8aa0ba;
                --accent: #31c48d;
                --danger: #fb7185;
                --warn: #fbbf24;
                --info: #60a5fa;
                --shadow: #a78bfa;
            }}
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                background:
                    radial-gradient(circle at top, rgba(49, 196, 141, 0.12), transparent 32%),
                    linear-gradient(180deg, #050b14 0%, var(--bg) 100%);
                color: var(--text);
                font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            }}
            .shell {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px 48px; }}
            .header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 16px;
                padding-bottom: 18px;
                margin-bottom: 24px;
                border-bottom: 1px solid var(--border);
            }}
            .headline {{ margin: 0; font-size: 2.1rem; letter-spacing: 0.02em; color: var(--accent); }}
            .subhead {{ margin: 6px 0 0; color: var(--muted); }}
            .badge {{
                border: 1px solid rgba(49, 196, 141, 0.3);
                background: rgba(49, 196, 141, 0.12);
                color: #9df2cd;
                border-radius: 999px;
                padding: 8px 12px;
                font-size: 0.8rem;
                letter-spacing: 0.12em;
                text-transform: uppercase;
                white-space: nowrap;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 14px;
                margin-bottom: 24px;
            }}
            .card {{
                background: linear-gradient(180deg, rgba(20, 35, 58, 0.96), rgba(10, 19, 32, 0.98));
                border: 1px solid var(--border);
                border-radius: 14px;
                padding: 16px;
                box-shadow: 0 14px 40px rgba(0, 0, 0, 0.16);
            }}
            .card h3 {{
                margin: 0 0 8px;
                color: var(--muted);
                font-size: 0.74rem;
                letter-spacing: 0.14em;
                text-transform: uppercase;
            }}
            .card p {{ margin: 0; font-size: 1.85rem; font-weight: 700; }}
            .stat-danger {{ color: var(--danger); }}
            .stat-warn {{ color: var(--warn); }}
            .stat-info {{ color: var(--info); text-transform: uppercase; }}
            .table-wrap {{
                background: rgba(14, 26, 43, 0.94);
                border: 1px solid var(--border);
                border-radius: 16px;
                overflow: hidden;
                box-shadow: 0 18px 48px rgba(0, 0, 0, 0.18);
            }}
            table {{ width: 100%; border-collapse: collapse; }}
            thead {{ background: rgba(21, 36, 60, 0.96); }}
            th, td {{
                padding: 14px 16px;
                border-bottom: 1px solid rgba(40, 64, 95, 0.72);
                text-align: left;
                vertical-align: top;
            }}
            th {{
                color: #b8c7d9;
                font-size: 0.76rem;
                text-transform: uppercase;
                letter-spacing: 0.1em;
            }}
            td {{ font-size: 0.92rem; }}
            tbody tr:hover {{ background: rgba(20, 35, 58, 0.72); }}
            .timestamp, .session {{ color: var(--muted); font-family: "Consolas", "Courier New", monospace; }}
            .direction {{
                display: block;
                margin-bottom: 4px;
                color: #6f89a6;
                font-size: 0.72rem;
                letter-spacing: 0.08em;
                text-transform: uppercase;
            }}
            .reason {{
                max-width: 420px;
                color: #c0cede;
                word-break: break-word;
            }}
            .empty {{
                padding: 28px 18px;
                color: var(--muted);
                text-align: center;
                font-style: italic;
            }}
            .footer {{
                margin-top: 22px;
                color: #6f89a6;
                font-size: 0.75rem;
                letter-spacing: 0.12em;
                text-align: center;
                text-transform: uppercase;
            }}
            .action-ALLOW {{ color: var(--accent); }}
            .action-BLOCK {{ color: var(--danger); font-weight: 700; }}
            .action-WARN {{ color: var(--warn); font-weight: 700; }}
            .action-SHADOW-BLOCK {{ color: var(--shadow); font-style: italic; font-weight: 700; }}
            @media (max-width: 760px) {{
                .header {{ align-items: flex-start; flex-direction: column; }}
                th, td {{ padding: 12px; }}
            }}
        </style>
    </head>
    <body>
        <div class="shell">
            <header class="header">
                <div>
                    <h1 class="headline">McpVanguard Audit</h1>
                    <p class="subhead">Real-time security monitoring for MCP agents</p>
                </div>
                <span class="badge">Live Monitoring</span>
            </header>

            <div class="stats">
                <div class="card">
                    <h3>Total Requests</h3>
                    <p id="stat-total">--</p>
                </div>
                <div class="card">
                    <h3>Blocked</h3>
                    <p class="stat-danger" id="stat-blocked">--</p>
                </div>
                <div class="card">
                    <h3>Entropy Violations</h3>
                    <p class="stat-warn" id="stat-entropy">--</p>
                </div>
                <div class="card">
                    <h3>Mode</h3>
                    <p class="stat-info" id="stat-mode">Audit Only</p>
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Action</th>
                            <th>Session</th>
                            <th>Tool / Method</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody id="logs-container">
                        <tr>
                            <td colspan="5" class="empty">Connecting to audit log...</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <footer class="footer">
                Provnai Open Research Initiative - McpVanguard v{__version__}
            </footer>
        </div>
        <script>
            async function refreshLogs() {{
                const container = document.getElementById("logs-container");
                try {{
                    const response = await fetch("/logs", {{
                        headers: {{"x-requested-with": "mcpvanguard-dashboard"}}
                    }});
                    if (!response.ok) {{
                        throw new Error("HTTP " + response.status);
                    }}
                    container.innerHTML = await response.text();
                }} catch (error) {{
                    container.innerHTML = "<tr><td colspan='5' class='empty'>Dashboard refresh failed: " + error.message + "</td></tr>";
                }}
            }}

            window.addEventListener("load", function () {{
                refreshLogs();
                window.setInterval(refreshLogs, 3000);
            }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


async def get_logs_fragment(request):
    if not os.path.exists(LOG_FILE):
        return HTMLResponse("<tr><td colspan='5' class='px-4 py-4 text-center'>Log file not found</td></tr>")

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-20:]

        rows = []
        for line in reversed(lines):
            item = parse_log_line(line)
            if not item:
                continue

            row = f"""
            <tr>
                <td class="timestamp">{item.timestamp}</td>
                <td class="action-{item.action}">{item.action}</td>
                <td class="session">{item.session_id}</td>
                <td>
                    <span class="direction">{item.direction}</span>
                    {item.tool_name or item.method or '---'}
                </td>
                <td class="reason">
                    {item.reason or '---'}
                </td>
            </tr>
            """
            rows.append(row)

        return HTMLResponse(content="".join(rows))
    except Exception as e:
        return HTMLResponse(f"<tr><td colspan='5' class='px-4 py-4 text-center text-red-500'>Error reading logs: {e}</td></tr>")


app = Starlette(
    debug=False,
    routes=[
        Route("/", get_dashboard, methods=["GET"]),
        Route("/logs", get_logs_fragment, methods=["GET"]),
    ],
)


def start_dashboard(host: str = "127.0.0.1", port: int = 4040):
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="warning")
