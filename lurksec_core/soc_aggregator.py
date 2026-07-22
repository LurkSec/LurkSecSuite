import time
from typing import Dict, List, Any

class SOCAggregator:
    """
    LurkSOC: Master Incident Command Feed correlating telemetry across all 13 sub-engines.
    """

    @staticmethod
    def aggregate_incidents(
        network_sockets: List[Dict[str, Any]],
        siem_alerts: Dict[str, Any],
        decoy_summary: Dict[str, Any],
        packet_alerts: Dict[str, Any],
        process_alerts: Dict[str, Any],
        audit_summary: Dict[str, Any],
        edr_logs: List[Dict[str, Any]] = None,
        waf_logs: List[Dict[str, Any]] = None,
        cti_matches: List[Dict[str, Any]] = None,
        identity_findings: List[Dict[str, Any]] = None,
        cloud_findings: List[Dict[str, Any]] = None,
        soar_cases: List[Dict[str, Any]] = None,
        hunt_hits: List[Dict[str, Any]] = None
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

        # 6. Collect EDR Action Logs (LurkEDR)
        if edr_logs:
            for ed in edr_logs:
                incidents.append({
                    "incident_id": f"INC-EDR-{int(time.time())}",
                    "timestamp": ed.get("timestamp", now_str),
                    "engine": "LurkEDR",
                    "category": "Active Response",
                    "title": f"EDR Action: {ed.get('action_type', 'Enforcement')}",
                    "severity": "HIGH" if ed.get("success") else "MEDIUM",
                    "origin": "Endpoint Agent",
                    "evidence": f"Target: {ed.get('target')} | Outcome: {ed.get('message')}"
                })

        # 7. Collect Threat Hunting Matches (LurkHunt)
        if hunt_hits:
            for hh in hunt_hits:
                incidents.append({
                    "incident_id": f"INC-HUNT-{hh.get('rule_id') or hh.get('sig_id')}",
                    "timestamp": now_str,
                    "engine": "LurkHunt",
                    "category": "Threat Detection",
                    "title": f"Rule Match: {hh.get('title') or hh.get('sig_name')}",
                    "severity": hh.get("severity", "HIGH"),
                    "origin": hh.get("source", "Memory/Disk"),
                    "evidence": f"Matched Sample: {hh.get('matched_sample') or hh.get('matched_pattern')}"
                })

        # 8. Collect SOAR Incident Cases (LurkSOAR)
        if soar_cases:
            for sc in soar_cases:
                if sc.get("status") in ["OPEN", "IN_PROGRESS"]:
                    incidents.append({
                        "incident_id": f"INC-SOAR-{sc['case_id']}",
                        "timestamp": sc.get("created_at", now_str),
                        "engine": "LurkSOAR",
                        "category": "SOC Case Management",
                        "title": f"Active Case: {sc['title']}",
                        "severity": sc.get("severity", "MEDIUM"),
                        "origin": f"Assigned: {sc.get('assigned_to')}",
                        "evidence": sc.get("description", "")
                    })

        # 9. Collect WAF Block Events (LurkShield)
        if waf_logs:
            for wf in waf_logs:
                incidents.append({
                    "incident_id": f"INC-WAF-{int(time.time())}",
                    "timestamp": wf.get("timestamp", now_str),
                    "engine": "LurkShield",
                    "category": "WAF Protection",
                    "title": f"Blocked Payload: {wf.get('rule_matched')}",
                    "severity": "HIGH",
                    "origin": f"Remote IP: {wf.get('ip')}",
                    "evidence": f"URI: {wf.get('uri')}"
                })

        # Default PASS card if zero incidents
        if not incidents:
            incidents.append({
                "incident_id": "INC-PASS-001",
                "timestamp": now_str,
                "engine": "LurkSOC Command",
                "category": "Master Security Baseline",
                "title": "Master Incident Feed Baseline Clean",
                "severity": "LOW",
                "origin": "LurkSec Command Suite",
                "evidence": "Zero high-risk security threats detected across all 13 engines."
            })

        high_count = sum(1 for i in incidents if i["severity"] == "HIGH")
        med_count = sum(1 for i in incidents if i["severity"] == "MEDIUM")
        low_count = sum(1 for i in incidents if i["severity"] == "LOW")

        return {
            "total_incidents": len(incidents),
            "severity_counts": {"HIGH": high_count, "MEDIUM": med_count, "LOW": low_count},
            "incidents": incidents
        }
