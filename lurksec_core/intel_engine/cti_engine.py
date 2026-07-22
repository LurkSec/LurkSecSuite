import json
import socket
import subprocess
import time
import urllib.request
from typing import List, Dict, Any

KNOWN_THREAT_IPS = [
    "185.220.101.5", "185.220.101.34", "185.220.101.45", "185.107.47.215",
    "45.142.212.100", "45.142.212.200", "194.165.16.11", "194.165.16.17",
    "193.32.162.157", "193.32.162.170", "2.56.57.50", "2.56.57.57",
    "64.227.35.85", "64.227.35.90", "104.244.74.115", "104.244.74.116",
    "23.129.64.200", "23.129.64.213", "199.249.230.68", "199.249.230.87"
]

# MITRE ATT&CK Techniques map
MITRE_TECHNIQUES = {
    "T1059": {"name": "Command & Scripting Interpreter", "tactic": "Execution"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1071": {"name": "Application Layer Protocol (C2)", "tactic": "Command & Control"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command & Control"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"}
}

class CTIFeedManager:
    

    _cached_ips: List[str] = []
    _cached_kev: List[Dict] = []
    _last_fetch: float = 0
    CACHE_TTL = 300

    @classmethod
    def get_threat_ips(cls) -> List[str]:
        now = time.time()
        if cls._cached_ips and (now - cls._last_fetch) < cls.CACHE_TTL:
            return cls._cached_ips

        ips = set(KNOWN_THREAT_IPS)

        try:
            url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
            req = urllib.request.Request(url, headers={"User-Agent": "LurkIntel/1.0"})
            with urllib.request.urlopen(req, timeout=4) as r:
                data = json.loads(r.read().decode("utf-8"))
                if isinstance(data, list):
                    for entry in data[:200]:
                        ip = entry.get("ip_address", "")
                        if ip: ips.add(ip)
        except Exception:
            pass

        cls._cached_ips = list(ips)
        cls._last_fetch = now
        return cls._cached_ips

    @classmethod
    def get_cisa_kev(cls) -> List[Dict[str, Any]]:
        now = time.time()
        if cls._cached_kev and (now - cls._last_fetch) < cls.CACHE_TTL:
            return cls._cached_kev

        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            req = urllib.request.Request(url, headers={"User-Agent": "LurkIntel/1.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read().decode("utf-8"))
                vulns = data.get("vulnerabilities", [])[:50]
                cls._cached_kev = vulns
                return vulns
        except Exception:
            return []


class IOCMatcher:
    """
    Cross-references live system network sockets against CTI threat IP feeds.
    """

    @staticmethod
    def get_active_remote_ips() -> List[Dict[str, str]]:
        ips = []
        try:
            out = subprocess.check_output("netstat -ano", shell=True, text=True, errors="ignore")
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0].upper() in ["TCP", "UDP"]:
                    foreign = parts[2]
                    if ":" in foreign:
                        ip = foreign.rsplit(":", 1)[0]
                        if ip not in ["0.0.0.0", "127.0.0.1", "*", "[::]", "0:0:0:0:0:0:0:0"]:
                            ips.append({"ip": ip, "foreign_address": foreign, "protocol": parts[0]})
        except Exception:
            pass
        return ips

    @staticmethod
    def match_iocs(active_ips: List[Dict], threat_ips: List[str]) -> List[Dict[str, Any]]:
        threat_set = set(threat_ips)
        matches = []
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        for conn in active_ips:
            ip = conn["ip"]
            if ip in threat_set:
                matches.append({
                    "timestamp": now,
                    "ioc_type": "Malicious IP",
                    "indicator": ip,
                    "foreign_address": conn["foreign_address"],
                    "protocol": conn["protocol"],
                    "severity": "HIGH",
                    "source": "CTI Feed",
                    "mitre_technique": "T1071",
                    "mitre_name": MITRE_TECHNIQUES["T1071"]["name"]
                })
        return matches


class MITREMapper:
    """
    Maps detected threat indicators to MITRE ATT&CK framework techniques.
    """

    @staticmethod
    def get_technique_heatmap(ioc_matches: List[Dict], process_alerts: List[Dict]) -> List[Dict[str, Any]]:
        hit_counts = {tid: 0 for tid in MITRE_TECHNIQUES}

        for match in ioc_matches:
            tid = match.get("mitre_technique")
            if tid in hit_counts:
                hit_counts[tid] += 1

        # Map process anomalies to MITRE
        for alert in process_alerts:
            category = alert.get("category", "").lower()
            if "obfuscat" in category or "encoded" in category:
                hit_counts["T1027"] += 1
                hit_counts["T1059"] += 1
            if "temp" in category or "appdata" in category:
                hit_counts["T1105"] += 1

        heatmap = []
        for tid, count in hit_counts.items():
            tech = MITRE_TECHNIQUES[tid]
            heatmap.append({
                "technique_id": tid,
                "name": tech["name"],
                "tactic": tech["tactic"],
                "hit_count": count,
                "severity": "HIGH" if count > 0 else "LOW"
            })
        return sorted(heatmap, key=lambda x: x["hit_count"], reverse=True)
