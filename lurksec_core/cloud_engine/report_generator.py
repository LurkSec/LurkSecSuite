import json
import time
from typing import List, Dict, Any

class CloudReportGenerator:
    def __init__(self, aws_findings: List[Dict], azure_findings: List[Dict], baseline: List[Dict]):
        self.aws_findings = aws_findings
        self.azure_findings = azure_findings
        self.baseline = baseline
        self.all_findings = aws_findings + azure_findings

    def generate_json(self) -> str:
        return json.dumps({
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(self.all_findings),
            "aws_findings": self.aws_findings,
            "azure_findings": self.azure_findings,
            "baseline_audit": self.baseline
        }, indent=2)

    def generate_csv(self) -> str:
        csv = "Timestamp,ResourceType,ResourceID,Severity,Status,Finding,Recommendation\n"
        for f in self.all_findings:
            csv += f'"{f.get("timestamp")}","{f.get("resource_type")}","{f.get("resource_id")}","{f.get("severity")}","{f.get("status")}","{f.get("finding")}","{f.get("recommendation")}"\n'
        return csv

    def generate_markdown(self) -> str:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        md = f"# LurkCloud Infrastructure Compliance Report\nGenerated: {now_str}\n\n"
        md += f"## Summary\n- AWS Findings: {len(self.aws_findings)}\n- Azure Findings: {len(self.azure_findings)}\n\n"
        md += f"## AWS Security Findings\n\n"
        for f in self.aws_findings:
            md += f"- [{f.get('severity')}] `{f.get('resource_type')}` `{f.get('resource_id')}` — {f.get('finding')}\n"
        md += f"\n## Azure Security Findings\n\n"
        for f in self.azure_findings:
            md += f"- [{f.get('severity')}] `{f.get('resource_type')}` `{f.get('resource_id')}` — {f.get('finding')}\n"
        return md
