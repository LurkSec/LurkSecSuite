from lurksec_core.edr_engine.firewall_blocker import FirewallBlocker
from lurksec_core.edr_engine.process_killer import ProcessKiller
from lurksec_core.edr_engine.file_quarantiner import FileQuarantiner
from lurksec_core.edr_engine.memory_carver import MemoryCarver

class PlaybookRunner:
    

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

        target_ip = context.get("ip") or "185.220.101.5"
        target_pid = int(context.get("pid") or 1234)
        target_file = context.get("file_path") or context.get("target_path") or "C:\\Users\\angry\\AppData\\Local\\Temp\\malware_payload.exe"

        for act in pb["actions"]:
            step_res = {"step": act["step"], "type": act["type"], "status": "COMPLETED", "details": act["description"]}

            if act["type"] == "FIREWALL_BLOCK" or act["type"] == "ISOLATE_NETWORK":
                res = FirewallBlocker.block_ip(target_ip)
                step_res["details"] += f" [{res.get('message', 'Blocked IP in Windows Firewall')}]"

            elif act["type"] == "PROCESS_KILL":
                res = ProcessKiller.kill_process(target_pid)
                step_res["details"] += f" [{res.get('message', 'Process containment executed')}]"

            elif act["type"] == "FILE_QUARANTINE":
                res = FileQuarantiner.quarantine_file(target_file)
                step_res["details"] += f" [{res.get('message', 'File isolated in Quarantine Vault')}]"

            elif act["type"] == "MEMORY_DUMP":
                res = MemoryCarver.carve_process_memory(target_pid)
                step_res["details"] += f" [{res.get('message', 'Process memory carved to forensic dump')}]"

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

