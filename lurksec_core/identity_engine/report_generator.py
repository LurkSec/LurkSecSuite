import json
import time
from typing import List, Dict, Any

class IdentityReportGenerator:
    def __init__(self, findings: List[Dict], policy_audits: List[Dict]):
        self.findings = findings
        self.policy_audits = policy_audits

    def generate_json(self) -> str:
        return json.dumps({
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(self.findings),
            "high_severity_findings": len([f for f in self.findings if f.get("severity") == "HIGH"]),
            "secret_findings": self.findings,
            "policy_audits": self.policy_audits
        }, indent=2)

    def generate_csv(self) -> str:
        csv = "Timestamp,FindingID,SecretType,Severity,FilePath,FileName,Evidence\n"
        for f in self.findings:
            csv += f'"{f.get("timestamp")}","{f.get("finding_id")}","{f.get("secret_type")}","{f.get("severity")}","{f.get("file_path")}","{f.get("file_name")}","{f.get("evidence")}"\n'
        return csv

    def generate_markdown(self) -> str:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        md = f"# LurkIdentity Secret & Credential Scan Report\nGenerated: {now_str}\n\n"
        md += f"## Summary\n- Total Findings: {len(self.findings)}\n- High Severity: {len([f for f in self.findings if f.get('severity') == 'HIGH'])}\n\n"
        md += f"## Secret Findings\n\n"
        for f in self.findings:
            md += f"- [{f.get('severity')}] `{f.get('secret_type')}` in `{f.get('file_path')}` — {f.get('evidence')}\n"
        md += f"\n## Password Policy Audit\n\n"
        for a in self.policy_audits:
            md += f"- [{a.get('status')}] {a.get('component')}: {a.get('value')} — {a.get('recommendation', '')}\n"
        return md
