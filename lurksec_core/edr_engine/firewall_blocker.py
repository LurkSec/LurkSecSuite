import subprocess
import time
from typing import Dict, List, Any

class FirewallBlocker:
    """
    Manages Windows Firewall rules to dynamically block & unblock malicious remote IPs.
    """

    @staticmethod
    def block_ip(ip_address: str) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        clean_ip = ip_address.strip()
        if not clean_ip or clean_ip in ["127.0.0.1", "0.0.0.0"]:
            return {
                "success": False,
                "timestamp": now,
                "ip": clean_ip,
                "message": f"Action Refused: Cannot block localhost IP '{clean_ip}'."
            }

        rule_name = f"LurkEDR-Block-{clean_ip.replace('.', '_')}"
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}-IN" dir=in action=block remoteip={clean_ip}'
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}-OUT" dir=out action=block remoteip={clean_ip}'

        try:
            subprocess.check_output(cmd_in, shell=True, text=True, stderr=subprocess.STDOUT, errors="ignore")
            subprocess.check_output(cmd_out, shell=True, text=True, stderr=subprocess.STDOUT, errors="ignore")
            return {
                "success": True,
                "timestamp": now,
                "ip": clean_ip,
                "rule_name": rule_name,
                "message": f"Windows Firewall Inbound & Outbound block rules active for IP '{clean_ip}'."
            }
        except subprocess.CalledProcessError as e:
            return {
                "success": False,
                "timestamp": now,
                "ip": clean_ip,
                "message": f"Firewall command execution notice: {e.output.strip() if e.output else str(e)}"
            }
        except Exception as ex:
            return {
                "success": False,
                "timestamp": now,
                "ip": clean_ip,
                "message": f"Firewall rule creation error: {str(ex)}"
            }

    @staticmethod
    def unblock_ip(ip_address: str) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        clean_ip = ip_address.strip()
        rule_name = f"LurkEDR-Block-{clean_ip.replace('.', '_')}"
        cmd_in = f'netsh advfirewall firewall delete rule name="{rule_name}-IN"'
        cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name}-OUT"'

        try:
            subprocess.check_output(cmd_in, shell=True, text=True, stderr=subprocess.STDOUT, errors="ignore")
            subprocess.check_output(cmd_out, shell=True, text=True, stderr=subprocess.STDOUT, errors="ignore")
            return {
                "success": True,
                "timestamp": now,
                "ip": clean_ip,
                "message": f"Firewall block rules deleted for IP '{clean_ip}'."
            }
        except Exception as ex:
            return {
                "success": False,
                "timestamp": now,
                "ip": clean_ip,
                "message": f"Rule removal notice: {str(ex)}"
            }
