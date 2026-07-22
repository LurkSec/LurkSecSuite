import json
import time
from typing import Dict, List, Any

class SOARReportGenerator:
    

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
        html = f
        return html
