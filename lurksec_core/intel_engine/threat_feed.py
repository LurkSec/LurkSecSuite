import json
import ssl
import time
import urllib.request
from typing import Dict, List, Any, Set

class ThreatFeedManager:
    FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    def __init__(self):
        self.cached_iocs: List[Dict[str, Any]] = []
        self.ip_set: Set[str] = set()
        self.domain_set: Set[str] = set()
        self.last_sync: str = "Never"
        self.sync_status: str = "Idle"

    def fetch_live_feed(self) -> Dict[str, Any]:
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(
            self.FEODO_URL,
            headers={"User-Agent": "LurkSecSuite-CTI/1.0", "Accept": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                if resp.status == 200:
                    raw_data = resp.read().decode("utf-8")
                    data = json.loads(raw_data)

                    self.cached_iocs = []
                    self.ip_set.clear()
                    self.domain_set.clear()

                    for item in data[:250]:
                        ip = item.get("ip_address", "")
                        port = item.get("port", "")
                        malware = item.get("malware", "Botnet C2")
                        country = item.get("country", "Global")
                        first_seen = item.get("first_seen", "")

                        if ip:
                            self.ip_set.add(ip)
                            self.cached_iocs.append({
                                "id": f"FEODO-{len(self.cached_iocs)+1}",
                                "ioc": f"{ip}:{port}" if port else ip,
                                "type": "ip:port",
                                "threat": f"{malware} C2 Server ({country})",
                                "confidence": 100,
                                "first_seen": first_seen
                            })

                    self.last_sync = time.strftime("%Y-%m-%d %H:%M:%S")
                    self.sync_status = f"Synced {len(self.cached_iocs)} live C2 IOCs"
                    return {
                        "success": True,
                        "count": len(self.cached_iocs),
                        "last_sync": self.last_sync,
                        "message": f"Successfully pulled {len(self.cached_iocs)} live C2 server IOCs from Abuse.ch Feodo Tracker."
                    }
        except Exception as e:
            self.sync_status = f"Sync failed: {str(e)}"

        return {
            "success": False,
            "count": len(self.cached_iocs),
            "last_sync": self.last_sync,
            "message": f"Live CTI sync unavailable ({self.sync_status}). Using local Threat Intel baseline."
        }

    def match_sockets(self, sockets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        matches = []
        for s in sockets:
            remote_ip = s.get("remote_ip", "")
            if remote_ip in self.ip_set:
                matches.append({
                    "remote_ip": remote_ip,
                    "local_port": s.get("local_port"),
                    "pid": s.get("pid"),
                    "process_name": s.get("process_name"),
                    "severity": "CRITICAL",
                    "threat": "Known Malicious C2 IP (Abuse.ch Feodo Tracker Feed)"
                })
        return matches

    def get_summary(self) -> Dict[str, Any]:
        return {
            "last_sync": self.last_sync,
            "sync_status": self.sync_status,
            "total_iocs": len(self.cached_iocs),
            "tracked_ips": len(self.ip_set),
            "tracked_domains": len(self.domain_set),
            "recent_iocs": self.cached_iocs[:15]
        }
