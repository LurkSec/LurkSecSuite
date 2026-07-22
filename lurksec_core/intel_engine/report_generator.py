import json
import time
from typing import List, Dict, Any

class IntelReportGenerator:
    def __init__(self, ioc_matches: List[Dict], heatmap: List[Dict], kev_list: List[Dict]):
        self.ioc_matches = ioc_matches
        self.heatmap = heatmap
        self.kev_list = kev_list

    def generate_json(self) -> str:
        return json.dumps({
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_ioc_matches": len(self.ioc_matches),
            "ioc_matches": self.ioc_matches,
            "mitre_heatmap": self.heatmap,
            "cisa_kev_sample": self.kev_list[:20]
        }, indent=2)

    def generate_markdown(self) -> str:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        md = f"# LurkIntel Threat Intelligence Report\nGenerated: {now_str}\n\n"
        md += f"## IOC Match Summary\n- Total IOC Matches: {len(self.ioc_matches)}\n\n"
        md += f"## IOC Matches Against CTI Feed\n\n"
        if not self.ioc_matches:
            md += "*No active system connections matched threat intelligence feeds.*\n\n"
        else:
            for m in self.ioc_matches:
                md += f"- [{m['severity']}] `{m['indicator']}` ({m['foreign_address']}) — MITRE: {m['mitre_technique']} ({m['mitre_name']})\n"
        md += f"\n## MITRE ATT&CK Technique Heatmap\n\n"
        for t in self.heatmap:
            md += f"- `{t['technique_id']}` {t['name']} ({t['tactic']}) — Hits: {t['hit_count']}\n"
        return md
