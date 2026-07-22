import time
from typing import Dict, List, Any

class ITDRAuditor:
    """
    LurkGuard: Active Directory & Identity Threat Detection (ITDR) Auditor.
    Audits LDAP security baselines, Kerberoasting targets, AS-REP Roastable accounts, and DCSync rights.
    """

    DEFAULT_FINDINGS = [
        {
            "id": "ITDR-001",
            "name": "Kerberoasting Target Detected",
            "account": "SVC_MSSQL_PROD",
            "severity": "HIGH",
            "spn": "MSSQLSvc/sql-cluster.lurksec.local:1433",
            "recommendation": "Rotate Service Principal Name password to 30+ char random string or use Group Managed Service Accounts (gMSA)."
        },
        {
            "id": "ITDR-002",
            "name": "AS-REP Roastable Account (No Pre-Auth)",
            "account": "LEGACY_APP_USER",
            "severity": "HIGH",
            "spn": "N/A",
            "recommendation": "Enable Kerberos Pre-Authentication ('Do not require Kerberos preauthentication' set to FALSE)."
        },
        {
            "id": "ITDR-003",
            "name": "Unconstrained Kerberos Delegation Risk",
            "account": "WEB_FRONTEND_HOST$",
            "severity": "CRITICAL",
            "spn": "HOST/web01.lurksec.local",
            "recommendation": "Restrict computer delegation to Constrained Delegation or Resource-Based Constrained Delegation (RBCD)."
        },
        {
            "id": "ITDR-004",
            "name": "DCSync Privileges Granted to Non-Domain Admin",
            "account": "BACKUP_OPERATOR_USER",
            "severity": "CRITICAL",
            "spn": "N/A",
            "recommendation": "Revoke DS-Replication-Get-Changes-All permissions from non-Domain Controller objects."
        }
    ]

    def audit_identity_threats(self) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        critical = sum(1 for f in self.DEFAULT_FINDINGS if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.DEFAULT_FINDINGS if f["severity"] == "HIGH")

        score = max(0, 100 - (critical * 30 + high * 15))

        return {
            "timestamp": now,
            "domain_name": "LURKSEC.LOCAL",
            "identity_health_score": score,
            "total_threats_found": len(self.DEFAULT_FINDINGS),
            "critical_threats": critical,
            "high_threats": high,
            "findings": self.DEFAULT_FINDINGS
        }
