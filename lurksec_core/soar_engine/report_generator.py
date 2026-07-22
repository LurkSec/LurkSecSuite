import json
import time
from typing import Dict, List, Any

class SOARReportGenerator:
    """
    Generates SOAR Automation & Incident Case Reports.
    Matches the Minimalist Charcoal Console Theme.
    """

    def __init__(self, playbooks: List[Dict[str, Any]], cases: List[Dict[str, Any]], history: List[Dict[str, Any]]):
        self.playbooks = playbooks
        self.cases = cases
        self.history = history

    def generate_json(self) -> str:
        return json.dumps({
            "generated_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "playbooks": self.playbooks,
            "cases": self.cases,
            "history": self.history
        }, indent=2)

    def generate_markdown(self) -> str:
        md = ["# LURKSOAR AUTOMATION & INCIDENT CASE REPORT", f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n"]
        md.append("## Active SOAR Cases")
        md.append("| Case ID | Title | Severity | Status | Assigned To |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for c in self.cases:
            md.append(f"| `{c['case_id']}` | {c['title']} | **{c['severity']}** | `{c['status']}` | {c['assigned_to']} |")
        md.append("\n---\n*LurkSOAR Security Orchestration Report*")
        return "\n".join(md)

    def generate_html(self) -> str:
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8"><title>LurkSOAR Executive Report</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'JetBrains Mono', monospace; background: #0d1117; color: #c9d1d9; padding: 30px; font-size: 12px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #161b22; padding: 24px; border: 1px solid #30363d; }}
        h1 {{ color: #58a6ff; font-size: 18px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; background: #0d1117; border: 1px solid #30363d; }}
        th, td {{ padding: 8px 12px; border-bottom: 1px solid #30363d; text-align: left; }}
        th {{ background: #161b22; color: #8b949e; }}
        code {{ background: #21262d; color: #58a6ff; padding: 2px 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ LurkSOAR Executive Incident Report</h1>
        <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <h2>Active Security Cases ({len(self.cases)})</h2>
        <table>
            <thead><tr><th>Case ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Assigned</th></tr></thead>
            <tbody>
                {''.join([f"<tr><td><code>{c['case_id']}</code></td><td>{c['title']}</td><td><strong>{c['severity']}</strong></td><td><code>{c['status']}</code></td><td>{c['assigned_to']}</td></tr>" for c in self.cases])}
            </tbody>
        </table>
    </div>
</body>
</html>"""
        return html
