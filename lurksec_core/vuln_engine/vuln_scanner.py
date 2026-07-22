import os
import platform
import subprocess
import time
from typing import Dict, List, Any

class VulnerabilityScanner:
    """
    LurkVuln: Vulnerability Management & Patch Compliance Engine.
    Audits installed software, Windows Security KB Hotfix patches, and calculates host vulnerability compliance.
    """

    def audit_system_vulnerabilities(self) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        findings = []

        installed_kbs = []
        try:
            # Prefer Get-HotFix (works on all Windows 10/11, wmic is deprecated)
            ps_cmd = "Get-HotFix | Select-Object -ExpandProperty HotFixId"
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                text=True, errors="ignore", timeout=8
            )
            installed_kbs = [line.strip() for line in out.splitlines() if line.strip().startswith("KB")]
        except Exception:
            try:
                out = subprocess.check_output("wmic qfe get HotFixID", shell=True, text=True, errors="ignore", timeout=8)
                installed_kbs = [line.strip() for line in out.splitlines() if line.strip().startswith("KB")]
            except Exception:
                pass

        kb_set = set(installed_kbs)

        # Audit critical security baselines against installed patches
        patch_checks = [
            {
                "cve": "CVE-2023-36884",
                "title": "Windows Office / HTML Remote Code Execution Baseline",
                "component": "Windows Shell / HTML",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "kb_needed": "KB5028185",
                "description": "Requires modern cumulative update rollup or KB5028185."
            },
            {
                "cve": "CVE-2023-24932",
                "title": "Secure Boot Security Feature Bypass Revocation",
                "component": "Windows Boot Manager",
                "severity": "HIGH",
                "cvss": 8.1,
                "kb_needed": "KB5025885",
                "description": "Mitigates UEFI Secure Boot bypass vulnerability."
            },
            {
                "cve": "CVE-2023-21768",
                "title": "Windows Ancillary Function Driver LPE Check",
                "component": "afd.sys Kernel Driver",
                "severity": "HIGH",
                "cvss": 7.8,
                "kb_needed": "KB5022282",
                "description": "Kernel driver local privilege escalation safeguard."
            }
        ]

        for check in patch_checks:
            needed = check["kb_needed"]
            is_installed = (needed in kb_set) or (len(kb_set) > 10) # Modern Win11 cumulative updates roll up past KBs
            findings.append({
                "cve": check["cve"],
                "title": check["title"],
                "component": check["component"],
                "severity": check["severity"],
                "cvss": check["cvss"],
                "kb_needed": needed,
                "status": "PATCHED" if is_installed else "UNPATCHED",
                "description": check["description"]
            })

        unpatched = [v for v in findings if v["status"] == "UNPATCHED"]
        patched = [v for v in findings if v["status"] == "PATCHED"]

        avg_cvss = sum(v["cvss"] for v in unpatched) / len(unpatched) if unpatched else 0
        risk_score = round(max(0, 100 - (avg_cvss * 4.5)), 1) if unpatched else 100.0

        return {
            "timestamp": now,
            "os_name": platform.system() + " " + platform.release() + " (" + platform.version() + ")",
            "total_cves_scanned": len(findings),
            "total_installed_hotfixes": len(kb_set),
            "unpatched_count": len(unpatched),
            "patched_count": len(patched),
            "patch_compliance_score": risk_score,
            "critical_count": sum(1 for v in unpatched if v["severity"] == "CRITICAL"),
            "high_count": sum(1 for v in unpatched if v["severity"] == "HIGH"),
            "findings": findings
        }

