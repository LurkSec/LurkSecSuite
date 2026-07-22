import json
import os
import time
from typing import List, Dict, Any

class EDRPolicyEngine:
    def __init__(self, rules_file: str = "edr_rules.json"):
        self.rules_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), rules_file)
        self.rules: List[Dict[str, Any]] = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return self._default_rules()

    def _default_rules(self) -> List[Dict[str, Any]]:
        default_rules = [
            {
                "id": "POL-001",
                "name": "Block Encoded PowerShell Execution",
                "enabled": True,
                "process_name": "powershell.exe",
                "cmd_contains": "-enc",
                "action": "KILL_PROCESS",
                "severity": "HIGH",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            {
                "id": "POL-002",
                "name": "Quarantine Unsigned Temp Executables",
                "enabled": False,
                "process_name": "cmd.exe",
                "cmd_contains": "AppData\\Local\\Temp",
                "action": "QUARANTINE_FILE",
                "severity": "MEDIUM",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        ]
        self._save_rules(default_rules)
        return default_rules

    def _save_rules(self, rules: List[Dict[str, Any]] = None):
        if rules is not None:
            self.rules = rules
        try:
            with open(self.rules_file, "w", encoding="utf-8") as f:
                json.dump(self.rules, f, indent=2)
        except Exception:
            pass

    def get_rules(self) -> List[Dict[str, Any]]:
        return self.rules

    def add_rule(self, name: str, process_name: str, cmd_contains: str, action: str, severity: str = "HIGH") -> Dict[str, Any]:
        rule_id = f"POL-{len(self.rules) + 1:03d}"
        new_rule = {
            "id": rule_id,
            "name": name,
            "enabled": True,
            "process_name": process_name.lower().strip(),
            "cmd_contains": cmd_contains.lower().strip(),
            "action": action.upper().strip(),
            "severity": severity.upper().strip(),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.rules.append(new_rule)
        self._save_rules()
        return new_rule

    def toggle_rule(self, rule_id: str) -> Dict[str, Any]:
        for r in self.rules:
            if r["id"] == rule_id:
                r["enabled"] = not r.get("enabled", True)
                self._save_rules()
                return {"success": True, "rule": r}
        return {"success": False, "message": "Rule not found"}

    def delete_rule(self, rule_id: str) -> Dict[str, Any]:
        orig_len = len(self.rules)
        self.rules = [r for r in self.rules if r["id"] != rule_id]
        if len(self.rules) < orig_len:
            self._save_rules()
            return {"success": True}
        return {"success": False, "message": "Rule not found"}

    def evaluate_process(self, proc: Dict[str, Any]) -> List[Dict[str, Any]]:
        matches = []
        p_name = (proc.get("name") or "").lower()
        p_cmd = (proc.get("command_line") or "").lower()

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            name_match = not rule.get("process_name") or rule["process_name"] in p_name
            cmd_match = not rule.get("cmd_contains") or rule["cmd_contains"] in p_cmd

            if name_match and cmd_match:
                matches.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "action": rule["action"],
                    "severity": rule["severity"],
                    "pid": proc.get("pid"),
                    "process_name": proc.get("name"),
                    "command_line": proc.get("command_line")
                })

        return matches
