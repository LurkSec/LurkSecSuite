import time
from typing import Dict, List, Any

class CaseManager:
    """
    LurkSOAR SOC Incident Case Manager.
    Tracks security incidents, evidence, timeline milestones, and analyst resolution states.
    """

    def __init__(self):
        self.cases: List[Dict[str, Any]] = [
            {
                "case_id": "CASE-2026-001",
                "title": "Unusual PowerShell Execution in %TEMP%",
                "severity": "HIGH",
                "status": "IN_PROGRESS",
                "assigned_to": "Analyst Lurk",
                "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                "description": "LurkTrace detected obfuscated PowerShell command executing from C:\\Users\\...\\AppData\\Local\\Temp.",
                "evidence": ["Process PID: 4876", "Parent PID: 1204 (explorer.exe)", "Encoded Base64 Payload"],
                "timeline": [
                    {"time": time.strftime('%Y-%m-%d %H:%M:%S'), "event": "Case automatically opened by LurkSOC aggregator."},
                    {"time": time.strftime('%Y-%m-%d %H:%M:%S'), "event": "Playbook PB-002 executed. Process terminated & binary quarantined."}
                ]
            },
            {
                "case_id": "CASE-2026-002",
                "title": "Multiple Failed Authentication Spikes",
                "severity": "MEDIUM",
                "status": "RESOLVED",
                "assigned_to": "SOC Auto-Bot",
                "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                "description": "LurkSIEM logged 14 failed logon attempts (Event 4625) targeting Administrator.",
                "evidence": ["Target IP: 192.168.1.105", "Event ID: 4625", "Failure Code: 0xc000006d"],
                "timeline": [
                    {"time": time.strftime('%Y-%m-%d %H:%M:%S'), "event": "Case created via SIEM correlation trigger."},
                    {"time": time.strftime('%Y-%m-%d %H:%M:%S'), "event": "Playbook PB-001 executed. IP blocked in Firewall."}
                ]
            }
        ]

    def get_cases(self) -> List[Dict[str, Any]]:
        return self.cases

    def create_case(self, title: str, severity: str, description: str, evidence: List[str] = None) -> Dict[str, Any]:
        case_id = f"CASE-2026-{len(self.cases) + 1:03d}"
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        new_case = {
            "case_id": case_id,
            "title": title,
            "severity": severity.upper(),
            "status": "OPEN",
            "assigned_to": "Unassigned",
            "created_at": now,
            "description": description,
            "evidence": evidence or [],
            "timeline": [{"time": now, "event": "Case initialized."}]
        }
        self.cases.insert(0, new_case)
        return new_case

    def update_case(self, case_id: str, status: str = None, note: str = None, assigned_to: str = None) -> Dict[str, Any]:
        case = next((c for c in self.cases if c["case_id"] == case_id), None)
        if not case:
            return {"success": False, "message": f"Case {case_id} not found."}

        now = time.strftime('%Y-%m-%d %H:%M:%S')
        if status:
            case["status"] = status.upper()
            case["timeline"].append({"time": now, "event": f"Status updated to {status.upper()}"})
        if assigned_to:
            case["assigned_to"] = assigned_to
            case["timeline"].append({"time": now, "event": f"Assigned to {assigned_to}"})
        if note:
            case["timeline"].append({"time": now, "event": f"Analyst Note: {note}"})

        return {"success": True, "case": case}
