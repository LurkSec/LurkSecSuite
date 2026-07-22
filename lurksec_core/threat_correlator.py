from typing import Dict, List, Any

class SIEMCorrelator:
    def __init__(self, events: List[Dict[str, Any]]):
        self.events = events

    def evaluate_rules(self) -> Dict[str, Any]:
        alerts = []
        failed_logons = [e for e in self.events if e.get("event_id") == 4625 or "FAILED" in (e.get("message") or "").upper()]
        service_events = [e for e in self.events if e.get("event_id") in [7040, 7045] or "SERVICE" in (e.get("provider") or "").upper()]

        if len(failed_logons) >= 1:
            alerts.append({
                "rule_id": "RULE-BRUTE-FORCE",
                "title": "Failed Authentication Audit Detection",
                "category": "Identity & Access",
                "severity": "HIGH" if len(failed_logons) > 3 else "MEDIUM",
                "count": len(failed_logons),
                "description": f"Detected {len(failed_logons)} failed user authentication attempt(s).",
                "evidence": f"Target User: {failed_logons[0].get('user', 'Unknown')}"
            })

        if len(service_events) >= 1:
            alerts.append({
                "rule_id": "RULE-SERVICE-STATE",
                "title": "System Service Configuration Change",
                "category": "Host Persistence",
                "severity": "MEDIUM",
                "count": len(service_events),
                "description": f"Identified {len(service_events)} system service creation or state modification event(s).",
                "evidence": f"Provider: {service_events[0].get('provider')}"
            })

        if not alerts:
            alerts.append({
                "rule_id": "RULE-PASS",
                "title": "System Audit Baseline Clean",
                "category": "Baseline Audit",
                "severity": "LOW",
                "count": 0,
                "description": "Windows Event Log audit stream shows clean operating state.",
                "evidence": "Log Source: Windows Security & System Logs"
            })

        severity_counts = {
            "HIGH": sum(1 for a in alerts if a["severity"] == "HIGH"),
            "MEDIUM": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
            "LOW": sum(1 for a in alerts if a["severity"] == "LOW")
        }

        return {
            "total_alerts": len(alerts),
            "severity_counts": severity_counts,
            "alerts": alerts
        }
