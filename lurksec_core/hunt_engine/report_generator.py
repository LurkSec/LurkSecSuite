import json
import time
from typing import Dict, List, Any

class HuntReportGenerator:
    """
    Generates LurkHunt Threat Hunting Reports.
    Matches the Minimalist Charcoal Console Theme.
    """

    def __init__(self, sigma_rules: List[Dict[str, Any]], yara_sigs: List[Dict[str, Any]], scan_hits: List[Dict[str, Any]]):
        self.sigma_rules = sigma_rules
        self.yara_sigs = yara_sigs
        self.scan_hits = scan_hits

    def generate_json(self) -> str:
        return json.dumps({
            "generated_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "sigma_rules_count": len(self.sigma_rules),
            "yara_sigs_count": len(self.yara_sigs),
            "hits_count": len(self.scan_hits),
            "hits": self.scan_hits
        }, indent=2)

    def generate_markdown(self) -> str:
        md = ["# LURKHUNT THREAT HUNTING REPORT", f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n"]
        md.append(f"- **Loaded SIGMA Rules:** `{len(self.sigma_rules)}`")
        md.append(f"- **Loaded YARA Signatures:** `{len(self.yara_sigs)}`")
        md.append(f"- **Threat Hunting Hits:** `{len(self.scan_hits)}`\n")
        md.append("## Identified Threat Matches")
        md.append("| Rule / Sig ID | Name / Title | Severity | Source / Match |")
        md.append("| :--- | :--- | :--- | :--- |")
        for h in self.scan_hits:
            id_val = h.get("rule_id") or h.get("sig_id")
            title = h.get("title") or h.get("sig_name")
            md.append(f"| `{id_val}` | {title} | **{h['severity']}** | `{h.get('source', 'System Scan')}` |")
        md.append("\n---\n*LurkHunt Threat Hunting & Detection Report*")
        return "\n".join(md)

    def generate_html(self) -> str:
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8"><title>LurkHunt Threat Hunting Report</title>
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
        <h1>🔍 LurkHunt Threat Hunting Report</h1>
        <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <h2>Threat Detections & Signature Matches ({len(self.scan_hits)})</h2>
        <table>
            <thead><tr><th>Rule / Sig ID</th><th>Name / Title</th><th>Severity</th><th>Source</th></tr></thead>
            <tbody>
                {''.join([f"<tr><td><code>{h.get('rule_id') or h.get('sig_id')}</code></td><td>{h.get('title') or h.get('sig_name')}</td><td><strong>{h['severity']}</strong></td><td><code>{h.get('source', 'System Scan')}</code></td></tr>" for h in self.scan_hits])}
            </tbody>
        </table>
    </div>
</body>
</html>"""
        return html
