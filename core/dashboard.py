"""
core/dashboard.py
A lightweight FastAPI/HTMX dashboard for the McpVanguard proxy.
"""

import json
import os
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="McpVanguard Audit Dashboard")

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
        
    # Check if it is JSON
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
                layer=data.get("layer_triggered")
            )
        except Exception:
            return None
            
    # Text format: [2026-03-17 06:10:56] [ALLOW]   (Layer 1)  | session | agent→server [tool] — reason
    try:
        # Very brittle parser for now, should ideally use JSON for the dashboard
        ts_part = line[1:20]
        action_start = line.find("[", 21)
        action_end = line.find("]", action_start)
        action = line[action_start+1:action_end]
        
        return AuditLogItem(
            timestamp=ts_part,
            action=action,
            session_id="N/A",
            direction="N/A",
            method=None,
            tool_name=None,
            reason=None,
            layer=None
        )
    except Exception:
        return None

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>McpVanguard Audit Dashboard</title>
        <script src="https://unpkg.com/htmx.org@1.9.10"></script>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            .action-ALLOW { color: #10b981; }
            .action-BLOCK { color: #ef4444; font-weight: bold; }
            .action-WARN { color: #f59e0b; }
            .action-SHADOW-BLOCK { color: #6366f1; font-style: italic; }
        </style>
    </head>
    <body class="bg-slate-900 text-slate-100 font-sans">
        <div class="max-w-6xl mx-auto p-8">
            <header class="flex justify-between items-center mb-8 border-b border-slate-700 pb-4">
                <div>
                    <h1 class="text-3xl font-bold text-emerald-500">McpVanguard Audit</h1>
                    <p class="text-slate-400">Real-time security monitoring for MCP agents</p>
                </div>
                <div class="text-right">
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-900 text-emerald-300">
                        LIVE MONITORING
                    </span>
                </div>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <div class="bg-slate-800 p-4 rounded-lg border border-slate-700">
                    <h3 class="text-slate-400 text-sm mb-1 uppercase tracking-wider">Total Requests</h3>
                    <p class="text-2xl font-bold" id="stat-total">--</p>
                </div>
                <div class="bg-slate-800 p-4 rounded-lg border border-slate-700">
                    <h3 class="text-slate-400 text-sm mb-1 uppercase tracking-wider">Blocked</h3>
                    <p class="text-2xl font-bold text-red-500" id="stat-blocked">--</p>
                </div>
                <div class="bg-slate-800 p-4 rounded-lg border border-slate-700">
                    <h3 class="text-slate-400 text-sm mb-1 uppercase tracking-wider">Entropy Violations</h3>
                    <p class="text-2xl font-bold text-orange-500" id="stat-entropy">--</p>
                </div>
                <div class="bg-slate-800 p-4 rounded-lg border border-slate-700">
                    <h3 class="text-slate-400 text-sm mb-1 uppercase tracking-wider">Mode</h3>
                    <p class="text-2xl font-bold text-blue-500 uppercase">Audit Only</p>
                </div>
            </div>

            <div class="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
                <table class="w-full text-left">
                    <thead class="bg-slate-700 text-slate-300 border-b border-slate-600">
                        <tr>
                            <th class="px-4 py-3 text-sm font-semibold uppercase tracking-wider">Timestamp</th>
                            <th class="px-4 py-3 text-sm font-semibold uppercase tracking-wider">Action</th>
                            <th class="px-4 py-3 text-sm font-semibold uppercase tracking-wider">Session</th>
                            <th class="px-4 py-3 text-sm font-semibold uppercase tracking-wider">Tool / Method</th>
                            <th class="px-4 py-3 text-sm font-semibold uppercase tracking-wider">Reason</th>
                        </tr>
                    </thead>
                    <tbody id="logs-container" hx-get="/logs" hx-trigger="load, every 3s" hx-swap="innerHTML">
                        <tr>
                            <td colspan="5" class="px-4 py-8 text-center text-slate-500 italic">Connecting to audit log...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <footer class="mt-8 text-center text-slate-500 text-xs uppercase tracking-widest">
                Provnai Open Research Initiative — McpVanguard v1.6.0
            </footer>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/logs")
async def get_logs_fragment():
    if not os.path.exists(LOG_FILE):
        return HTMLResponse("<tr><td colspan='5' class='px-4 py-4 text-center'>Log file not found</td></tr>")
        
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-20:] # Last 20 lines
            
        rows = []
        for line in reversed(lines):
            item = parse_log_line(line)
            if not item:
                continue
                
            row = f"""
            <tr class="border-b border-slate-700 hover:bg-slate-700/50 transition-colors">
                <td class="px-4 py-3 text-sm text-slate-400 font-mono">{item.timestamp}</td>
                <td class="px-4 py-3 text-sm font-bold action-{item.action}">{item.action}</td>
                <td class="px-4 py-3 text-sm text-slate-400 font-mono">{item.session_id}</td>
                <td class="px-4 py-3 text-sm font-medium text-slate-200">
                    <span class="text-slate-500 text-xs block uppercase tracking-tighter">{item.direction}</span>
                    {item.tool_name or item.method or '---'}
                </td>
                <td class="px-4 py-3 text-xs text-slate-400 max-w-xs truncate">
                    {item.reason or '---'}
                </td>
            </tr>
            """
            rows.append(row)
            
        return HTMLResponse(content="".join(rows))
    except Exception as e:
        return HTMLResponse(f"<tr><td colspan='5' class='px-4 py-4 text-center text-red-500'>Error reading logs: {e}</td></tr>")

def start_dashboard(host: str = "127.0.0.1", port: int = 4040):
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="warning")
