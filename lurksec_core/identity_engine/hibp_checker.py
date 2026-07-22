import hashlib
import time
import urllib.request
from typing import Dict, Any

class HIBPChecker:
    """
    HIBP k-Anonymity SHA-1 prefix API breach checker.
    Checks if a password hash prefix is in the HIBP database without exposing the full hash.
    """

    @staticmethod
    def check_password(password: str) -> Dict[str, Any]:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        found = False
        breach_count = 0
        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            req = urllib.request.Request(url, headers={"User-Agent": "LurkIdentity/1.0"})
            with urllib.request.urlopen(req, timeout=4) as r:
                body = r.read().decode("utf-8")
                for line in body.splitlines():
                    if ":" in line:
                        line_suffix, count = line.split(":", 1)
                        if line_suffix.strip().upper() == suffix:
                            found = True
                            breach_count = int(count.strip())
                            break
        except Exception as e:
            return {
                "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "sha1_prefix": prefix,
                "found_in_breach": None,
                "breach_count": 0,
                "error": str(e)
            }

        return {
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sha1_prefix": prefix,
            "found_in_breach": found,
            "breach_count": breach_count,
            "severity": "HIGH" if found else "PASS",
            "message": f"Password found in {breach_count:,} data breach records." if found else "Password not found in known breach databases."
        }
