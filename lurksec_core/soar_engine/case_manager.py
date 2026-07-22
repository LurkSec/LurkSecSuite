import time
from typing import Dict, List, Any

class CaseManager:
    

    def __init__(self):
        self.cases: List[Dict[str, Any]] = []

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
