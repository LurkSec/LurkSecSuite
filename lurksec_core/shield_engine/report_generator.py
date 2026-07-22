import json
import time
from typing import List, Dict, Any

class ShieldReportGenerator:
    def __init__(self, block_log: List[Dict[str, Any]], rule_summary: List[Dict[str, Any]]):
        self.block_log = block_log
        self.rule_summary = rule_summary

    def generate_json(self) -> str:
        return json.dumps({
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_blocked": len([r for r in self.block_log if r.get("blocked")]),
            "total_allowed": len([r for r in self.block_log if not r.get("blocked")]),
            "block_log": self.block_log,
            "active_rules": self.rule_summary
        }, indent=2)

    def generate_csv(self) -> str:
        csv = "Timestamp,Method,URI,Action,Severity,RulesMatched\n"
        for r in self.block_log:
            rules = "|".join([m["rule_id"] for m in r.get("rules_matched", [])])
            csv += f'"{r.get("timestamp")}","{r.get("method")}","{r.get("uri")}","{r.get("action")}","{r.get("severity")}","{rules}"\n'
        return csv

    def generate_markdown(self) -> str:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        blocked = [r for r in self.block_log if r.get("blocked")]
        md = f"# LurkShield WAF Block Report\n"
        md += f"Generated: {now_str}\n\n"
        md += f"## Summary\n"
        md += f"- Total Requests Inspected: {len(self.block_log)}\n"
        md += f"- Blocked: {len(blocked)}\n"
        md += f"- Allowed: {len(self.block_log) - len(blocked)}\n\n"
        md += f"## Blocked Requests\n\n"
        for r in blocked[:50]:
            rules = ", ".join([m["name"] for m in r.get("rules_matched", [])])
            md += f"- [{r.get('severity')}] `{r.get('method')} {r.get('uri')}` — Rules: {rules}\n"
        return md

    def generate_html(self) -> str:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        blocked = [r for r in self.block_log if r.get("blocked")]
        rows = ""
        for r in self.block_log[:100]:
            color = "#f85149" if r.get("blocked") else "#3fb950"
            rules = ", ".join([m["rule_id"] for m in r.get("rules_matched", [])])
            rows += f"<tr><td>{r.get('timestamp')}</td><td>{r.get('method')}</td><td>{r.get('uri')[:60]}</td><td style='color:{color}'>{r.get('action')}</td><td>{rules}</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LurkShield WAF Block Report</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }}
        h1 {{ color: #58a6ff; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
        th, td {{ padding: 8px 12px; border-bottom: 1px solid #30363d; text-align: left; }}
        th {{ background: #161b22; color: #8b949e; }}
    </style>
</head>
<body>
    <h1>LurkShield WAF Block Report</h1>
    <p>Generated: {now_str} | Total Blocked: {len(blocked)} / {len(self.block_log)}</p>
    <table>
        <thead><tr><th>Timestamp</th><th>Method</th><th>URI</th><th>Action</th><th>Rules</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</body>
</html>"""
