import socket
import time
from typing import Dict, List, Any

class DNSSinkhole:
    

    KNOWN_MALICIOUS_DOMAINS = [
        "c2-beacon-sinkhole.internal",
        "feodo-tracker-c2.xyz",
        "lockbit-ransomware.pay",
        "mimikatz-exfil.top",
        "phishing-login.online",
        "evil-download-server.cc",
        "trickbot-botnet.net",
        "asyncrat-beacon.info"
    ]

    def __init__(self):
        self.sinkhole_log: List[Dict[str, Any]] = []

    def inspect_query(self, domain: str, client_ip: str = "127.0.0.1", query_type: str = "A") -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        clean_domain = domain.strip().lower()

        is_malicious = any(bad in clean_domain for bad in ["badactor", "c2", "ransomware", "exfil", "phishing", "evil", "botnet", "asyncrat"]) or clean_domain in self.KNOWN_MALICIOUS_DOMAINS

        resolved_ip = "127.0.0.1"
        if not is_malicious:
            try:
                resolved_ip = socket.gethostbyname(clean_domain)
            except Exception:
                resolved_ip = "NXDOMAIN / Unresolved"

        if is_malicious:
            res = {
                "timestamp": now,
                "client_ip": client_ip,
                "domain": clean_domain,
                "query_type": query_type,
                "status": "SINKHOLED",
                "response_ip": "127.0.0.1",
                "severity": "HIGH",
                "category": "Malicious C2 Blocked",
                "message": f"DNS Query '{clean_domain}' sinkholed to 127.0.0.1 (High-Risk C2 Threat)."
            }
        else:
            res = {
                "timestamp": now,
                "client_ip": client_ip,
                "domain": clean_domain,
                "query_type": query_type,
                "status": "ALLOWED",
                "response_ip": resolved_ip,
                "severity": "PASS",
                "category": "Legitimate DNS Query",
                "message": f"DNS Query '{clean_domain}' resolved to {resolved_ip}."
            }

        self.sinkhole_log.insert(0, res)
        return res

    def get_summary(self) -> Dict[str, Any]:
        sinkholed_count = sum(1 for q in self.sinkhole_log if q["status"] == "SINKHOLED")
        allowed_count = sum(1 for q in self.sinkhole_log if q["status"] == "ALLOWED")

        return {
            "total_queries": len(self.sinkhole_log),
            "sinkholed_queries": sinkholed_count,
            "allowed_queries": allowed_count,
            "blocked_domains_count": len(self.KNOWN_MALICIOUS_DOMAINS),
            "recent_queries": self.sinkhole_log[:20],
            "known_bad_domains": self.KNOWN_MALICIOUS_DOMAINS
        }

