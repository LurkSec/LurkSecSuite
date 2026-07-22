import json
import time
from typing import Dict, List, Any

class HuntReportGenerator:
    

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
        html = f
        return html
