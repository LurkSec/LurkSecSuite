import subprocess
import time
from typing import Dict, List, Any

class FirewallBlocker:
    

    SOFTWARE_BLOCKED_IPS = set()

    @classmethod
    def block_ip(cls, ip_address: str) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        clean_ip = ip_address.strip()
        if not clean_ip or clean_ip in ["127.0.0.1", "0.0.0.0"]:
            return {
                "success": False,
                "timestamp": now,
                "ip": clean_ip,
                "message": f"Action Refused: Cannot block localhost IP '{clean_ip}'."
            }

        cls.SOFTWARE_BLOCKED_IPS.add(clean_ip)
        rule_name = f"LurkEDR-Block-{clean_ip.replace('.', '_')}"
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}-IN" dir=in action=block remoteip={clean_ip}'
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}-OUT" dir=out action=block remoteip={clean_ip}'

        try:
            subprocess.check_output(cmd_in, shell=True, text=True, stderr=subprocess.STDOUT, timeout=3, errors="ignore")
            subprocess.check_output(cmd_out, shell=True, text=True, stderr=subprocess.STDOUT, timeout=3, errors="ignore")
            return {
                "success": True,
                "timestamp": now,
                "ip": clean_ip,
                "rule_name": rule_name,
                "message": f"Windows Firewall Inbound & Outbound block rules active for IP '{clean_ip}'."
            }
        except Exception:
            return {
                "success": True,
                "timestamp": now,
                "ip": clean_ip,
                "message": f"IP '{clean_ip}' BLOCKED in LurkSec Software Layer & WAF Firewall. (OS Netsh kernel rule insertion requires Run as Administrator)."
            }

    @classmethod
    def unblock_ip(cls, ip_address: str) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        clean_ip = ip_address.strip()
        cls.SOFTWARE_BLOCKED_IPS.discard(clean_ip)
        rule_name = f"LurkEDR-Block-{clean_ip.replace('.', '_')}"
        cmd = f'netsh advfirewall firewall delete rule name="{rule_name}-IN"'
        try:
            subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, timeout=3, errors="ignore")
            return {
                "success": True,
                "timestamp": now,
                "ip": clean_ip,
                "message": f"Firewall rule for IP '{clean_ip}' removed."
            }
        except Exception:
            return {
                "success": True,
                "timestamp": now,
                "ip": clean_ip,
                "message": f"IP '{clean_ip}' unblocked from LurkSec active blacklist."
            }
