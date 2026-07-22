import os
import platform
import subprocess
import time
from typing import Dict, List, Any

class ITDRAuditor:
    """
    LurkGuard: Active Directory & Identity Threat Detection (ITDR) Auditor.
    Audits local user account privileges, Administrator group composition, Guest account posture, and password expiration policies.
    """

    def audit_identity_threats(self) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        findings = []

        # 1. Audit Guest Account Status
        try:
            out = subprocess.check_output("net user Guest", shell=True, text=True, errors="ignore")
            if "Account active               Yes" in out:
                findings.append({
                    "id": "ITDR-001",
                    "name": "Guest Account Active Risk",
                    "account": "Guest",
                    "severity": "HIGH",
                    "spn": "N/A",
                    "recommendation": "Disable built-in Guest account ('net user Guest /active:no')."
                })
        except Exception:
            pass

        # 2. Audit Local Administrators Group Members
        try:
            out = subprocess.check_output("net localgroup Administrators", shell=True, text=True, errors="ignore")
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            start_capture = False
            admin_members = []
            for l in lines:
                if "---" in l:
                    start_capture = True
                    continue
                if start_capture and not l.startswith("The command completed"):
                    admin_members.append(l)

            if len(admin_members) > 3:
                findings.append({
                    "id": "ITDR-002",
                    "name": "Excessive Local Administrator Accounts",
                    "account": f"{len(admin_members)} Admin Accounts ({', '.join(admin_members[:4])})",
                    "severity": "MEDIUM",
                    "spn": "N/A",
                    "recommendation": "Restrict Local Administrator group membership to required tier-0 accounts only."
                })
        except Exception:
            pass

        # 3. Audit Password Never Expires User Accounts
        try:
            ps_cmd = "Get-CimInstance Win32_UserAccount -Filter 'PasswordExpires = False AND Disabled = False' | Select-Object -ExpandProperty Name"
            out = subprocess.check_output(f'powershell -NoProfile -Command "{ps_cmd}"', shell=True, text=True, errors="ignore").strip()
            if out:
                no_exp_users = [u.strip() for u in out.splitlines() if u.strip()]
                findings.append({
                    "id": "ITDR-003",
                    "name": "Accounts with Non-Expiring Passwords",
                    "account": f"{len(no_exp_users)} User(s): {', '.join(no_exp_users[:3])}",
                    "severity": "MEDIUM",
                    "spn": "N/A",
                    "recommendation": "Enforce password expiration policy for non-service user accounts."
                })
        except Exception:
            pass

        # 4. Check UAC Consent Prompt Level
        try:
            reg_cmd = r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA'
            out = subprocess.check_output(reg_cmd, shell=True, text=True, errors="ignore")
            if "0x0" in out:
                findings.append({
                    "id": "ITDR-004",
                    "name": "User Account Control (UAC) Disabled",
                    "account": "SYSTEM (Global Registry)",
                    "severity": "CRITICAL",
                    "spn": "N/A",
                    "recommendation": "Enable Windows User Account Control (EnableLUA = 1)."
                })
        except Exception:
            pass

        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        medium = sum(1 for f in findings if f["severity"] == "MEDIUM")

        score = max(0, 100 - (critical * 30 + high * 15 + medium * 5))

        return {
            "timestamp": now,
            "domain_name": os.environ.get("USERDOMAIN", platform.node()),
            "identity_health_score": score,
            "total_threats_found": len(findings),
            "critical_threats": critical,
            "high_threats": high,
            "findings": findings
        }

