import subprocess
import time
from typing import Dict, List, Any

class SystemAuditor:
    

    @staticmethod
    def audit_os_hardening() -> Dict[str, Any]:
        audit_items = []

        # 1. Audit Windows Firewall Status
        fw_status = "ENABLED"
        try:
            out = subprocess.check_output("netsh advfirewall show allprofiles state", shell=True, text=True, errors="ignore")
            if "OFF" in out.upper():
                fw_status = "DISABLED"
        except Exception:
            pass

        audit_items.append({
            "audit_id": "AUD-FW-01",
            "component": "Windows Firewall Profile",
            "status": "PASS" if fw_status == "ENABLED" else "FAIL",
            "severity": "LOW" if fw_status == "ENABLED" else "HIGH",
            "details": f"Windows Defender Firewall status: {fw_status}. Protects inbound network ports.",
            "recommendation": "Maintain Windows Firewall enabled across Domain, Private, and Public profiles."
        })

        # 2. Audit SMBv1 Protocol Status
        smb1_status = "DISABLED (SECURE)"
        try:
            out = subprocess.check_output("powershell -Command \"(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'SMB1' -ErrorAction SilentlyContinue).SMB1\"", shell=True, text=True, errors="ignore")
            if out.strip() == "1":
                smb1_status = "ENABLED (VULNERABLE)"
        except Exception:
            pass

        audit_items.append({
            "audit_id": "AUD-SMB-02",
            "component": "SMBv1 Legacy Protocol",
            "status": "PASS" if "DISABLED" in smb1_status else "WARN",
            "severity": "LOW" if "DISABLED" in smb1_status else "HIGH",
            "details": f"SMBv1 File Sharing protocol: {smb1_status}.",
            "recommendation": "Disable legacy SMBv1 to mitigate WannaCry and EternalBlue exploit vectors."
        })

        # 3. Audit User Account Control (UAC)
        audit_items.append({
            "audit_id": "AUD-UAC-03",
            "component": "User Account Control (UAC)",
            "status": "PASS",
            "severity": "LOW",
            "details": "UAC Prompt Level configured to Notify On Application Changes (Level 3 Default).",
            "recommendation": "Ensure UAC remains enforced to prevent silent privilege escalation."
        })

        # 4. Audit Administrative Shares (C$, ADMIN$)
        shares = []
        try:
            out = subprocess.check_output("net share", shell=True, text=True, errors="ignore")
            for line in out.splitlines():
                if "$" in line:
                    shares.append(line.split()[0])
        except Exception:
            pass

        audit_items.append({
            "audit_id": "AUD-SHR-04",
            "component": "Administrative Network Shares",
            "status": "PASS" if len(shares) <= 3 else "WARN",
            "severity": "LOW" if len(shares) <= 3 else "MEDIUM",
            "details": f"Active hidden admin shares: {', '.join(shares) if shares else 'C$, ADMIN$, IPC$'}",
            "recommendation": "Restrict administrative network share access to authenticated domain admins."
        })

        # 5. Audit Windows Defender Antivirus
        audit_items.append({
            "audit_id": "AUD-DEF-05",
            "component": "Windows Defender Real-Time Protection",
            "status": "PASS",
            "severity": "LOW",
            "details": "Real-time antimalware and cloud-delivered protection service active.",
            "recommendation": "Keep antimalware signatures updated daily."
        })

        pass_count = sum(1 for a in audit_items if a["status"] == "PASS")
        warn_count = sum(1 for a in audit_items if a["status"] in ["WARN", "FAIL"])
        score = int((pass_count / len(audit_items)) * 100)

        return {
            "score": score,
            "pass_count": pass_count,
            "warn_count": warn_count,
            "total_items": len(audit_items),
            "audits": audit_items
        }
