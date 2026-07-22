import json
import time
from typing import Dict, List, Any

class EDRReportGenerator:
    """
    Generates LurkEDR Threat Containment & Response Audit Reports.
    Matches the Minimalist Charcoal Console Theme.
    """

    def __init__(self, action_logs: List[Dict[str, Any]], quarantined_files: List[Dict[str, Any]]):
        self.action_logs = action_logs
        self.quarantined_files = quarantined_files

    def generate_json(self) -> str:
        return json.dumps({
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_actions": len(self.action_logs),
            "total_quarantined": len(self.quarantined_files),
            "action_logs": self.action_logs,
            "quarantined_vault": self.quarantined_files
        }, indent=2)

    def generate_markdown(self) -> str:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        md = f"# LurkEDR Threat Containment & Response Report\n"
        md += f"Generated: {now_str} | Agent: LurkEDR v1.0\n\n"
        md += f"## Containment Summary\n"
        md += f"- Total EDR Actions Executed: {len(self.action_logs)}\n"
        md += f"- Quarantined Files in Vault: {len(self.quarantined_files)}\n\n"

        md += f"## EDR Action Log Stream\n\n"
        if not self.action_logs:
            md += f"*No EDR containment actions executed yet.*\n"
        else:
            for log in self.action_logs:
                status = "SUCCESS" if log.get("success") else "FAILED"
                md += f"### [{status}] {log.get('action_type', 'Action')} (Time: {log.get('timestamp')})\n"
                md += f"- Target: {log.get('target')}\n"
                md += f"- Message: {log.get('message')}\n\n"

        md += f"## Quarantine Vault Inventory\n\n"
        if not self.quarantined_files:
            md += f"*Quarantine vault is empty.*\n"
        else:
            for q in self.quarantined_files:
                md += f"- **{q.get('filename')}** ({q.get('size_bytes')} bytes) | Vault: `{q.get('vault_path')}`\n"

        return md

    def generate_html(self) -> str:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        logs_html = ""
        for log in self.action_logs:
            badge_class = "status-pass" if log.get("success") else "status-fail"
            logs_html += f"""
            <div class="card">
                <div class="card-header">
                    <strong>{log.get('action_type', 'EDR Action')}</strong> - Target: <code>{log.get('target')}</code>
                    <span class="{badge_class}">[{'SUCCESS' if log.get('success') else 'FAILED'}]</span>
                </div>
                <div class="card-body">
                    <div>Timestamp: {log.get('timestamp')}</div>
                    <div>Details: {log.get('message')}</div>
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LurkEDR Containment Report</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }}
        h1, h2 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 12px; margin-bottom: 12px; }}
        .card-header {{ display: flex; justify-content: space-between; font-weight: bold; font-size: 14px; margin-bottom: 6px; }}
        .status-pass {{ color: #3fb950; }}
        .status-fail {{ color: #f85149; }}
        code {{ background: #21262d; padding: 2px 6px; border-radius: 3px; color: #58a6ff; }}
    </style>
</head>
<body>
    <h1>LurkEDR Endpoint Containment Audit</h1>
    <div>Report Generated: {now_str}</div>
    <h2>Action Log History ({len(self.action_logs)} Actions)</h2>
    {logs_html if logs_html else '<div>No containment actions logged.</div>'}
</body>
</html>"""
