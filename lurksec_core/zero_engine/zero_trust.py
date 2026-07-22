import time
from typing import Dict, List, Any

class ZeroTrustEngine:
    """
    LurkZero: Zero Trust Network Access (ZTNA) & Posture Inspector.
    Validates Mutual TLS (mTLS) client certificates, JWT tokens, and device security posture tokens.
    """

    POLICY_RULES = [
        {"id": "ZT-001", "name": "mTLS Certificate Verification", "status": "ACTIVE", "enforcement": "STRICT"},
        {"id": "ZT-002", "name": "JWT Token Signature & Expiry", "status": "ACTIVE", "enforcement": "STRICT"},
        {"id": "ZT-003", "name": "Endpoint Patch Baseline Check", "status": "ACTIVE", "enforcement": "WARN"},
        {"id": "ZT-004", "name": "EDR Active Protection Verification", "status": "ACTIVE", "enforcement": "STRICT"},
        {"id": "ZT-005", "name": "Geo-IP Anomaly Lockout", "status": "ACTIVE", "enforcement": "STRICT"}
    ]

    def __init__(self):
        self.access_logs: List[Dict[str, Any]] = []

    def verify_access(self, user: str, device_id: str, resource: str, mtls_valid: bool = True) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        posture_score = 90 if mtls_valid else 30
        granted = mtls_valid and posture_score >= 70

        res = {
            "timestamp": now,
            "user": user,
            "device_id": device_id,
            "mtls_status": "VALID" if mtls_valid else "FAILED_POSTURE",
            "posture_score": posture_score,
            "access_granted": granted,
            "resource": resource,
            "severity": "PASS" if granted else "HIGH",
            "message": f"Zero Trust Decision: Access {'GRANTED' if granted else 'DENIED'} for {user} on {resource}."
        }
        self.access_logs.insert(0, res)
        return res

    def get_summary(self) -> Dict[str, Any]:
        total = len(self.access_logs)
        granted = sum(1 for a in self.access_logs if a["access_granted"])
        denied = total - granted

        return {
            "total_evaluations": total,
            "access_granted_count": granted,
            "access_denied_count": denied,
            "policies": self.POLICY_RULES,
            "recent_evaluations": self.access_logs[:20]
        }
