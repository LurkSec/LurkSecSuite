import json
import time
import urllib.request
from typing import Dict, List, Any, Set

class ThreatFeedManager:
    THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self):
        self.cached_iocs: List[Dict[str, Any]] = []
        self.ip_set: Set[str] = set()
        self.domain_set: Set[str] = set()
        self.last_sync: str = "Never"
        self.sync_status: str = "Idle"

    def fetch_live_feed(self) -> Dict[str, Any]:
        req_data = json.dumps({"query": "get_iocs", "days": 1}).encode("utf-8")
        req = urllib.request.Request(
            self.THREATFOX_URL,
            data=req_data,
            headers={"User-Agent": "LurkSecSuite-CTI/1.0", "Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("query_status") == "ok":
                        raw_iocs = data.get("data", [])
                        self.cached_iocs = []
                        self.ip_set.clear()
                        self.domain_set.clear()

                        for item in raw_iocs[:200]:
                            ioc_val = item.get("ioc", "")
                            ioc_type = item.get("ioc_type", "")
                            threat = item.get("malware_printable", "Unknown Threat")

                            if ioc_type in ["ip:port", "ip"]:
                                ip = ioc_val.split(":")[0]
                                self.ip_set.add(ip)
                            elif ioc_type in ["domain", "url"]:
                                domain = ioc_val.replace("http://", "").replace("https://", "").split("/")[0]
                                self.domain_set.add(domain)

                            self.cached_iocs.append({
                                "id": item.get("id"),
                                "ioc": ioc_val,
                                "type": ioc_type,
                                "threat": threat,
                                "confidence": item.get("confidence_level", 50),
                                "first_seen": item.get("first_seen", "")
                            })

                        self.last_sync = time.strftime("%Y-%m-%d %H:%M:%S")
                        self.sync_status = f"Synced {len(self.cached_iocs)} IOCs"
                        return {
                            "success": True,
                            "count": len(self.cached_iocs),
                            "last_sync": self.last_sync,
                            "message": f"Successfully pulled {len(self.cached_iocs)} live IOCs from ThreatFox."
                        }
        except Exception as e:
            self.sync_status = f"Sync failed: {str(e)}"

        return {
            "success": False,
            "count": len(self.cached_iocs),
            "last_sync": self.last_sync,
            "message": f"Feed sync unavailable ({self.sync_status}). Using local Threat Intel baseline."
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
                    "threat": "Known Malicious C2 IP (ThreatFox Live Feed)"
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
