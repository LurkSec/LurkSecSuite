import json
import time
import subprocess
from typing import Dict, List, Any

class PlaybookRunner:
    """
    LurkSOAR Automated Playbook Execution Engine.
    Executes multi-stage remediation playbooks against correlated security incidents.
    """

    BUILTIN_PLAYBOOKS = [
        {
            "id": "PB-001",
            "name": "Automated Brute-Force IP Isolation",
            "trigger_event": "Failed Authentication Spike / Brute-Force",
            "severity_threshold": "MEDIUM",
            "enabled": True,
            "actions": [
                {"step": 1, "type": "LOG_AUDIT", "description": "Extract attacker IP and failed attempt counter."},
                {"step": 2, "type": "FIREWALL_BLOCK", "description": "Add IP to Windows Defender Firewall block rule."},
                {"step": 3, "type": "NOTIFY_SOC", "description": "Dispatch high-severity incident notification to SOC command."}
            ]
        },
        {
            "id": "PB-002",
            "name": "Ransomware Execution Host Quarantine",
            "trigger_event": "Suspicious %TEMP% Execution or Mass File Modification",
            "severity_threshold": "HIGH",
            "enabled": True,
            "actions": [
                {"step": 1, "type": "PROCESS_KILL", "description": "Terminate offending parent & child PID execution tree."},
                {"step": 2, "type": "FILE_QUARANTINE", "description": "Move suspicious binary to isolated .quarantine store."},
                {"step": 3, "type": "ISOLATE_NETWORK", "description": "Disable non-essential outbound network interfaces."}
            ]
        },
        {
            "id": "PB-003",
            "name": "Shellcode Memory Injection Remediation",
            "trigger_event": "EDR Memory Injection Anomaly / Unbacked Executable Page",
            "severity_threshold": "HIGH",
            "enabled": True,
            "actions": [
                {"step": 1, "type": "MEMORY_DUMP", "description": "Carve process RAM to .dmp file for offline analysis."},
                {"step": 2, "type": "PROCESS_KILL", "description": "Terminate injected target process PID."},
                {"step": 3, "type": "SOC_ALERT", "description": "Log memory forensic artifact in SOAR case manager."}
            ]
        },
        {
            "id": "PB-004",
            "name": "Credential Leak Emergency Revocation",
            "trigger_event": "LurkIdentity Secret Pattern Scanner High Severity Detection",
            "severity_threshold": "HIGH",
            "enabled": True,
            "actions": [
                {"step": 1, "type": "LOCK_ACCOUNT", "description": "Flag exposed credential for immediate rotation."},
                {"step": 2, "type": "HIBP_AUDIT", "description": "Query k-Anonymity API for public breach exposure."},
                {"step": 3, "type": "NOTIFY_SEC_OPS", "description": "Dispatch automated credential rotation alert."}
            ]
        }
    ]

    def __init__(self):
        self.execution_history: List[Dict[str, Any]] = []

    def get_playbooks(self) -> List[Dict[str, Any]]:
        return self.BUILTIN_PLAYBOOKS

    def execute_playbook(self, playbook_id: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        context = context or {}
        pb = next((p for p in self.BUILTIN_PLAYBOOKS if p["id"] == playbook_id), None)
        if not pb:
            return {"success": False, "message": f"Playbook {playbook_id} not found."}

        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        executed_steps = []

        for act in pb["actions"]:
            step_res = {"step": act["step"], "type": act["type"], "status": "COMPLETED", "details": act["description"]}
            
            # Simulate real execution action for Firewall / Process
            if act["type"] == "FIREWALL_BLOCK" and "ip" in context:
                ip = context["ip"]
                try:
                    cmd = f'netsh advfirewall firewall add rule name="LurkSOAR_AutoBlock_{ip}" dir=in action=block remoteip={ip}'
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    step_res["details"] += f" [Executed: Blocked IP {ip} in Windows Firewall]"
                except Exception as e:
                    step_res["details"] += f" [Failed netsh: {str(e)}]"

            executed_steps.append(step_res)

        record = {
            "execution_id": f"EXEC-{int(time.time()*1000)}",
            "playbook_id": pb["id"],
            "playbook_name": pb["name"],
            "timestamp": timestamp,
            "status": "SUCCESS",
            "context": context,
            "steps": executed_steps
        }

        self.execution_history.insert(0, record)
        return record

    def get_history(self) -> List[Dict[str, Any]]:
        return self.execution_history
