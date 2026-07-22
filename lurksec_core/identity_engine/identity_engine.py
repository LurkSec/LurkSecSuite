import os
import re
import time
from typing import List, Dict, Any

# Secret detection patterns
SECRET_PATTERNS = [
    {"id": "SEC-001", "name": "AWS Access Key",       "severity": "HIGH",   "pattern": r'AKIA[0-9A-Z]{16}'},
    {"id": "SEC-002", "name": "AWS Secret Key",       "severity": "HIGH",   "pattern": r'(?i)aws.{0,20}["\']?([a-z0-9\/+]{40})["\']?'},
    {"id": "SEC-003", "name": "Private RSA/SSH Key",  "severity": "HIGH",   "pattern": r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----'},
    {"id": "SEC-004", "name": "Generic API Key",      "severity": "HIGH",   "pattern": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'},
    {"id": "SEC-005", "name": "GitHub Token",         "severity": "HIGH",   "pattern": r'gh[pousr]_[A-Za-z0-9_]{36}'},
    {"id": "SEC-006", "name": "Slack Token",          "severity": "HIGH",   "pattern": r'xox[baprs]-([0-9a-zA-Z]{10,48})'},
    {"id": "SEC-007", "name": "Generic Password",     "severity": "MEDIUM", "pattern": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?'},
    {"id": "SEC-008", "name": "Database URL",         "severity": "HIGH",   "pattern": r'(?i)(mongodb|postgres|mysql|redis|mssql):\/\/[^\s"\']+'},
    {"id": "SEC-009", "name": "JWT Token",            "severity": "MEDIUM", "pattern": r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'},
    {"id": "SEC-010", "name": "Generic Secret",       "severity": "MEDIUM", "pattern": r'(?i)(secret[_-]?key|secret)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'}
]

SCAN_DIRS = [
    os.path.expanduser("~\\Desktop"),
    os.path.expanduser("~\\Documents"),
    os.path.expanduser("~\\Downloads"),
    os.path.expanduser("~\\AppData\\Local"),
    os.path.expanduser("~\\AppData\\Roaming"),
]

SCAN_EXTENSIONS = [".env", ".cfg", ".config", ".ini", ".json", ".yml", ".yaml", ".txt", ".xml", ".properties"]
SCAN_FILENAMES = [".env", "config", "credentials", "secrets", "settings", ".env.local", ".env.production", "id_rsa", "id_ed25519"]


class SecretScanner:
    

    @staticmethod
    def scan_filesystem(max_files: int = 200) -> List[Dict[str, Any]]:
        findings = []
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        files_scanned = 0

        for scan_dir in SCAN_DIRS:
            if not os.path.isdir(scan_dir):
                continue
            for root, dirs, files in os.walk(scan_dir):
                # Skip hidden/system directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', '.git']]

                for fname in files:
                    if files_scanned >= max_files:
                        break
                    fpath = os.path.join(root, fname)
                    fname_lower = fname.lower()
                    ext = os.path.splitext(fname_lower)[1]

                    if ext not in SCAN_EXTENSIONS and fname_lower not in SCAN_FILENAMES:
                        continue

                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read(32768)  # Read up to 32KB per file
                        files_scanned += 1

                        for pattern_def in SECRET_PATTERNS:
                            matches = re.findall(pattern_def["pattern"], content)
                            if matches:
                                findings.append({
                                    "timestamp": now,
                                    "finding_id": f"FIND-{len(findings) + 1001}",
                                    "pattern_id": pattern_def["id"],
                                    "secret_type": pattern_def["name"],
                                    "severity": pattern_def["severity"],
                                    "file_path": fpath,
                                    "file_name": fname,
                                    "match_count": len(matches),
                                    "evidence": f"Pattern {pattern_def['id']} matched {len(matches)} occurrence(s) in file"
                                })
                    except Exception:
                        continue

        return findings


class PolicyAuditor:
    """
    Audits Windows local user account security policy baseline.
    """

    @staticmethod
    def audit_password_policy() -> List[Dict[str, Any]]:
        import subprocess
        audits = []
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        try:
            out = subprocess.check_output("net accounts", shell=True, text=True, errors="ignore")
            lines = out.splitlines()

            for line in lines:
                linesafe = line.strip()

                if "Minimum password length" in linesafe:
                    parts = linesafe.split(":")
                    val = parts[-1].strip() if len(parts) > 1 else "0"
                    num = int(val) if val.isdigit() else 0
                    status = "PASS" if num >= 8 else "FAIL"
                    audits.append({
                        "audit_id": "POLICY-001",
                        "component": "Minimum Password Length",
                        "value": val,
                        "status": status,
                        "severity": "LOW" if status == "PASS" else "HIGH",
                        "recommendation": "Set minimum password length to 12+ characters."
                    })

                elif "Lockout threshold" in linesafe:
                    parts = linesafe.split(":")
                    val = parts[-1].strip() if len(parts) > 1 else "Never"
                    status = "PASS" if val.isdigit() and int(val) <= 10 else "WARN"
                    audits.append({
                        "audit_id": "POLICY-002",
                        "component": "Account Lockout Threshold",
                        "value": val,
                        "status": status,
                        "severity": "LOW" if status == "PASS" else "MEDIUM",
                        "recommendation": "Set lockout threshold to 5 or fewer failed attempts."
                    })

                elif "Password expires" in linesafe:
                    parts = linesafe.split(":")
                    val = parts[-1].strip() if len(parts) > 1 else "Never"
                    status = "WARN" if "never" in val.lower() else "PASS"
                    audits.append({
                        "audit_id": "POLICY-003",
                        "component": "Password Expiration",
                        "value": val,
                        "status": status,
                        "severity": "MEDIUM" if status == "WARN" else "LOW",
                        "recommendation": "Set password expiration to 90 days or less."
                    })

        except Exception:
            pass

        if not audits:
            audits.append({
                "audit_id": "POLICY-000",
                "component": "Windows Account Policy",
                "value": "Unavailable",
                "status": "WARN",
                "severity": "LOW",
                "recommendation": "Run as Administrator to retrieve full password policy details."
            })

        return audits
