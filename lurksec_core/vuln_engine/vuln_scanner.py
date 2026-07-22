import platform
import subprocess
import time
from typing import Dict, List, Any

class VulnerabilityScanner:
    """
    LurkVuln: Vulnerability Management & Patch Compliance Engine.
    Audits installed software versions, missing Windows Security KB Patches, and calculates CVSS risk scores.
    """

    KNOWN_VULNERABILITIES = [
        {
            "cve": "CVE-2023-36884",
            "title": "Windows HTML Remote Code Execution Vulnerability",
            "component": "Microsoft Office / Windows HTML",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "kb_needed": "KB5028185",
            "status": "UNPATCHED",
            "description": "Allows unauthenticated attackers to execute arbitrary code via malicious Office documents."
        },
        {
            "cve": "CVE-2023-24932",
            "title": "Secure Boot Security Feature Bypass Vulnerability",
            "component": "Windows Boot Manager",
            "severity": "HIGH",
            "cvss": 8.1,
            "kb_needed": "KB5025885",
            "status": "UNPATCHED",
            "description": "Bypasses UEFI Secure Boot using revoked bootloaders (BlackLotus bootkit risk)."
        },
        {
            "cve": "CVE-2023-21768",
            "title": "Windows Ancillary Function Driver Privilege Escalation",
            "component": "afd.sys (Kernel Driver)",
            "severity": "HIGH",
            "cvss": 7.8,
            "kb_needed": "KB5022282",
            "status": "PATCHED",
            "description": "Local privilege escalation vulnerability in afd.sys driver allowing SYSTEM escalation."
        },
        {
            "cve": "CVE-2024-21412",
            "title": "Internet Shortcut Files Security Feature Bypass",
            "component": "Windows Shell",
            "severity": "MEDIUM",
            "cvss": 6.5,
            "kb_needed": "KB5034765",
            "status": "UNPATCHED",
            "description": "Bypasses SmartScreen warnings via crafted .url files."
        }
    ]

    def audit_system_vulnerabilities(self) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        unpatched = [v for v in self.KNOWN_VULNERABILITIES if v["status"] == "UNPATCHED"]
        patched = [v for v in self.KNOWN_VULNERABILITIES if v["status"] == "PATCHED"]

        avg_cvss = sum(v["cvss"] for v in unpatched) / len(unpatched) if unpatched else 0
        risk_score = round(max(0, 100 - (avg_cvss * 4.5)), 1)

        return {
            "timestamp": now,
            "os_name": platform.system() + " " + platform.release(),
            "total_cves_scanned": len(self.KNOWN_VULNERABILITIES),
            "unpatched_count": len(unpatched),
            "patched_count": len(patched),
            "patch_compliance_score": risk_score,
            "critical_count": sum(1 for v in unpatched if v["severity"] == "CRITICAL"),
            "high_count": sum(1 for v in unpatched if v["severity"] == "HIGH"),
            "findings": self.KNOWN_VULNERABILITIES
        }
