import json
import subprocess
import time
from typing import Dict, List, Any

class SIEMLogParser:
    @staticmethod
    def get_real_events(max_events: int = 100) -> List[Dict[str, Any]]:
        events = []
        limit = max_events // 2
        ps_script =  + str(limit) + 

        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                text=True, errors="ignore", timeout=8
            )
            raw = out.strip()
            if raw:
                data = json.loads(raw)
                if isinstance(data, dict): data = [data]
                idx = 1000
                for item in data:
                    event_id = item.get("Id", 0)
                    provider = item.get("ProviderName", "Windows")
                    log_name = item.get("LogName", "System")
                    time_created = item.get("TimeCreated", time.strftime("%Y-%m-%d %H:%M:%S"))
                    level = item.get("LevelDisplayName", "Information")
                    user = item.get("User", "SYSTEM")
                    msg = item.get("Message", "Event logged")

                    severity = "LOW"
                    if level and level.lower() in ["error", "critical"]: severity = "HIGH"
                    elif level and level.lower() in ["warning"]: severity = "MEDIUM"

                    if event_id == 4624: msg = "Successful User Authentication / Logon"; severity = "LOW"
                    elif event_id == 4625: msg = "FAILED User Authentication Attempt"; severity = "HIGH"
                    elif event_id in [7045, 7040]: msg = f"System Service Modification: {msg}"; severity = "MEDIUM"

                    events.append({
                        "event_key": f"EVT-{idx}",
                        "event_id": event_id,
                        "log_name": log_name,
                        "provider": provider,
                        "timestamp": time_created,
                        "user": user,
                        "source_ip": "127.0.0.1",
                        "severity": severity,
                        "message": msg
                    })
                    idx += 1
        except Exception:
            pass

        events.sort(key=lambda x: x["timestamp"], reverse=True)
        return events
