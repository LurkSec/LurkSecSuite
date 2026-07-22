import json
import time
from typing import Dict, List, Any

class EDRReportGenerator:
    

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
            logs_html += f

        return f
