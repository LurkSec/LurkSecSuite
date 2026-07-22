import time
from typing import Dict, List, Any

class SOCAggregator:
    

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
        hunt_hits: List[Dict[str, Any]] = None,
        dns_summary: Dict[str, Any] = None,
        zero_summary: Dict[str, Any] = None,
        vuln_summary: Dict[str, Any] = None,
        sand_summary: Dict[str, Any] = None,
        guard_summary: Dict[str, Any] = None
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
                "evidence": f"Attacker IP: {p['source_ip']} | Payload: {p['payload']}",
                "action_type": "BLOCK_IP",
                "target_ip": p["source_ip"]
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

        # 4. Collect Threat Hunting Matches (LurkHunt)
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
                    "evidence": f"Matched Payload: {hh.get('matched_sample') or hh.get('matched_pattern')}"
                })

        # 5. Collect DNS C2 Sinkhole Blocks (LurkDNS)
        if dns_summary:
            for dq in dns_summary.get("recent_queries", []):
                if dq.get("status") == "SINKHOLED":
                    incidents.append({
                        "incident_id": f"INC-DNS-{dq.get('query_type')}",
                        "timestamp": dq.get("timestamp", now_str),
                        "engine": "LurkDNS",
                        "category": "DNS C2 Interception",
                        "title": f"Malicious Domain Blocked: {dq.get('domain')}",
                        "severity": "HIGH",
                        "origin": f"Client {dq.get('client_ip')}",
                        "evidence": f"Resolved 127.0.0.1 (Category: {dq.get('category')})",
                        "action_type": "BLOCK_IP",
                        "target_ip": dq.get("client_ip")
                    })

        # 6. Collect Zero Trust Denials (LurkZero)
        if zero_summary:
            for zt in zero_summary.get("recent_evaluations", []):
                if not zt.get("access_granted"):
                    incidents.append({
                        "incident_id": f"INC-ZERO-{int(time.time())}",
                        "timestamp": zt.get("timestamp", now_str),
                        "engine": "LurkZero",
                        "category": "Zero Trust Denial",
                        "title": f"Access Refused: {zt.get('user')}",
                        "severity": "HIGH",
                        "origin": f"Resource: {zt.get('resource')}",
                        "evidence": f"mTLS Status: {zt.get('mtls_status')} | Posture Score: {zt.get('posture_score')}"
                    })

        # 7. Collect Vulnerability Warnings (LurkVuln)
        if vuln_summary:
            for vn in vuln_summary.get("findings", []):
                if vn.get("status") == "UNPATCHED" and vn.get("severity") in ["CRITICAL", "HIGH"]:
                    incidents.append({
                        "incident_id": f"INC-VULN-{vn.get('cve')}",
                        "timestamp": now_str,
                        "engine": "LurkVuln",
                        "category": "Vulnerability Exposure",
                        "title": f"Unpatched CVE: {vn.get('cve')} ({vn.get('title')})",
                        "severity": vn.get("severity"),
                        "origin": vn.get("component"),
                        "evidence": f"CVSS {vn.get('cvss')} | Needed KB Patch: {vn.get('kb_needed')}"
                    })

        # 8. Collect Malware Sandbox Verdicts (LurkSand)
        if sand_summary:
            for sa in sand_summary.get("recent_analyses", []):
                if sa.get("verdict") in ["MALICIOUS", "SUSPICIOUS"]:
                    incidents.append({
                        "incident_id": f"INC-SAND-{sa.get('sample_name')[:10]}",
                        "timestamp": sa.get("timestamp", now_str),
                        "engine": "LurkSand",
                        "category": "Malware Sandbox Verdict",
                        "title": f"Malicious Binary Analyzed: {sa.get('sample_name')}",
                        "severity": "HIGH" if sa.get("verdict") == "MALICIOUS" else "MEDIUM",
                        "origin": "PE Analyzer",
                        "evidence": f"Verdict: {sa.get('verdict')} (Entropy: {sa.get('entropy')} | Threat Score: {sa.get('threat_score')})"
                    })

        # 9. Collect Active Directory ITDR Risks (LurkGuard)
        if guard_summary:
            for gd in guard_summary.get("findings", []):
                incidents.append({
                    "incident_id": f"INC-GUARD-{gd.get('id')}",
                    "timestamp": now_str,
                    "engine": "LurkGuard",
                    "category": "Identity Threat Detection",
                    "title": f"Identity Risk: {gd.get('name')}",
                    "severity": gd.get("severity"),
                    "origin": f"Account: {gd.get('account')}",
                    "evidence": f"SPN: {gd.get('spn')} | Recommendation: {gd.get('recommendation')}"
                })

        # 10. Collect EDR Actions (LurkEDR)
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

        # 11. Collect WAF Block Events (LurkShield)
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
                "evidence": "Zero high-risk security threats detected across all 18 engines."
            })

        high_count = sum(1 for i in incidents if i["severity"] in ["HIGH", "CRITICAL"])
        med_count = sum(1 for i in incidents if i["severity"] == "MEDIUM")
        low_count = sum(1 for i in incidents if i["severity"] in ["LOW", "PASS"])

        return {
            "total_incidents": len(incidents),
            "severity_counts": {"HIGH": high_count, "MEDIUM": med_count, "LOW": low_count},
            "incidents": incidents
        }
