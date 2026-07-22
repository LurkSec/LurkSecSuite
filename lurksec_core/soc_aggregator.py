import time
from typing import Dict, List, Any

class SOCAggregator:
    """
    LurkSOC: Master Incident Command Feed correlating alerts across all sub-engines.
    """

    @staticmethod
    def aggregate_incidents(
        network_sockets: List[Dict[str, Any]],
        siem_alerts: Dict[str, Any],
        decoy_summary: Dict[str, Any],
        packet_alerts: Dict[str, Any],
        process_alerts: Dict[str, Any],
        audit_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        incidents = []
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        # 1. Collect Honeypot Intrusions (LurkDecoy)
        probes = decoy_summary.get("intrusions", [])
        for p in probes:
            incidents.append({
                "incident_id": f"INC-DECOY-{p['probe_id']}",
                "timestamp": p["timestamp"],
                "engine": "LurkDecoy",
                "category": "Deception Probe",
                "title": f"Unauthorized Probe on {p['service']} (Port {p['target_port']})",
                "severity": p["severity"],
                "origin": p["origin"],
                "evidence": f"Attacker IP: {p['source_ip']} | Payload: {p['payload']}"
            })

        # 2. Collect SIEM Correlation Alerts (LurkSIEM)
        for s in siem_alerts.get("alerts", []):
            if s["rule_id"] != "RULE-PASS":
                incidents.append({
                    "incident_id": f"INC-SIEM-{s['rule_id']}",
                    "timestamp": now_str,
                    "engine": "LurkSIEM",
                    "category": s["category"],
                    "title": s["title"],
                    "severity": s["severity"],
                    "origin": "System Event Log",
                    "evidence": s["evidence"]
                })

        # 3. Collect Process Anomalies (LurkTrace)
        for pr in process_alerts.get("alerts", []):
            if pr["rule_id"] != "RULE-PASS":
                incidents.append({
                    "incident_id": f"INC-TRACE-{pr['rule_id']}",
                    "timestamp": now_str,
                    "engine": "LurkTrace",
                    "category": pr["category"],
                    "title": pr["title"],
                    "severity": pr["severity"],
                    "origin": "Win32_Process",
                    "evidence": pr["evidence"]
                })

        # 4. Collect Packet Security Alerts (LurkPacket)
        for pa in packet_alerts.get("alerts", []):
            if pa["rule_id"] != "ALERT-PASS":
                incidents.append({
                    "incident_id": f"INC-PKT-{pa['rule_id']}",
                    "timestamp": now_str,
                    "engine": "LurkPacket",
                    "category": pa["category"],
                    "title": pa["title"],
                    "severity": pa["severity"],
                    "origin": "Network Frame",
                    "evidence": pa["evidence"]
                })

        # 5. Collect OS Hardening Warnings (LurkAudit)
        for au in audit_summary.get("audits", []):
            if au["status"] in ["WARN", "FAIL"]:
                incidents.append({
                    "incident_id": f"INC-AUD-{au['audit_id']}",
                    "timestamp": now_str,
                    "engine": "LurkAudit",
                    "category": "OS Hardening",
                    "title": f"Hardening Warning: {au['component']}",
                    "severity": au["severity"],
                    "origin": "OS Baseline",
                    "evidence": au["details"]
                })

        # Default PASS card if zero high/medium incidents
        if not incidents:
            incidents.append({
                "incident_id": "INC-PASS-001",
                "timestamp": now_str,
                "engine": "LurkSOC Command",
                "category": "Master Security Baseline",
                "title": "Master Incident Feed Baseline Clean",
                "severity": "LOW",
                "origin": "LurkSec Command Suite",
                "evidence": "Zero high-risk security threats detected across all 6 engines."
            })

        high_count = sum(1 for i in incidents if i["severity"] == "HIGH")
        med_count = sum(1 for i in incidents if i["severity"] == "MEDIUM")
        low_count = sum(1 for i in incidents if i["severity"] == "LOW")

        return {
            "total_incidents": len(incidents),
            "severity_counts": {"HIGH": high_count, "MEDIUM": med_count, "LOW": low_count},
            "incidents": incidents
        }
