import re
import time
from typing import Dict, List, Any

class WAFInspector:
    

    RULES = [
        {
            "rule_id": "WAF-001",
            "name": "SQL Injection",
            "category": "Injection",
            "severity": "HIGH",
            "patterns": [
                r"(?i)(union\s+select|select\s+.+from|insert\s+into|drop\s+table|delete\s+from|update\s+.+set)",
                r"(?i)(\bor\b\s+\d+=\d+|\band\b\s+\d+=\d+)",
                r"(?i)(--\s*$|;\s*drop|;\s*delete|;\s*insert|;\s*update)",
                r"'[^']*'|\"[^\"]*\""
            ]
        },
        {
            "rule_id": "WAF-002",
            "name": "Cross-Site Scripting (XSS)",
            "category": "Injection",
            "severity": "HIGH",
            "patterns": [
                r"(?i)<script[^>]*>",
                r"(?i)javascript\s*:",
                r"(?i)on(load|click|mouseover|error|focus|blur)\s*=",
                r"(?i)<iframe|<object|<embed|<svg\s+on"
            ]
        },
        {
            "rule_id": "WAF-003",
            "name": "Path Traversal / LFI",
            "category": "Broken Access Control",
            "severity": "HIGH",
            "patterns": [
                r"(\.\./|\.\.\\){2,}",
                r"(?i)(etc/passwd|etc/shadow|win/system32|windows/system32)",
                r"(?i)(%2e%2e%2f|%2e%2e/|\.\.%2f)"
            ]
        },
        {
            "rule_id": "WAF-004",
            "name": "Command Injection",
            "category": "Injection",
            "severity": "HIGH",
            "patterns": [
                r"(?i)(\||;|&|`|\$\()\s*(ls|dir|cat|whoami|id|wget|curl|bash|sh|cmd|powershell)",
                r"(?i)(system\(|exec\(|shell_exec\(|passthru\(|popen\()",
                r"(?i)(eval\s*\(|assert\s*\()"
            ]
        },
        {
            "rule_id": "WAF-005",
            "name": "Server-Side Request Forgery (SSRF)",
            "category": "SSRF",
            "severity": "MEDIUM",
            "patterns": [
                r"(?i)(http://169\.254\.169\.254|http://metadata\.google)",
                r"(?i)(http://localhost|http://127\.|http://0\.0\.0\.0)",
                r"(?i)(file://|dict://|gopher://|ftp://)"
            ]
        },
        {
            "rule_id": "WAF-006",
            "name": "Sensitive File Access",
            "category": "Information Disclosure",
            "severity": "MEDIUM",
            "patterns": [
                r"(?i)\.(env|git|svn|htpasswd|htaccess|config|bak|sql|log)($|\?)",
                r"(?i)/(admin|phpmyadmin|wp-admin|config|backup|\.well-known)"
            ]
        }
    ]

    @classmethod
    def inspect_request(cls, method: str, uri: str, headers: Dict[str, str], body: str = "") -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        full_payload = f"{method} {uri} {body}"

        matched_rules = []
        for rule in cls.RULES:
            for pattern in rule["patterns"]:
                if re.search(pattern, full_payload):
                    matched_rules.append({
                        "rule_id": rule["rule_id"],
                        "name": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "matched_payload": full_payload[:200]
                    })
                    break

        blocked = len(matched_rules) > 0
        return {
            "timestamp": now,
            "method": method,
            "uri": uri[:200],
            "blocked": blocked,
            "rules_matched": matched_rules,
            "severity": matched_rules[0]["severity"] if matched_rules else "PASS",
            "action": "BLOCK" if blocked else "ALLOW"
        }

    @classmethod
    def get_rule_summary(cls) -> List[Dict[str, Any]]:
        return [{"rule_id": r["rule_id"], "name": r["name"], "category": r["category"], "severity": r["severity"]} for r in cls.RULES]
