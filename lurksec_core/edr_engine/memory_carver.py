import re
import subprocess
import time
from typing import Dict, List, Any

class MemoryCarver:
    """
    Extracts process artifacts, ASCII strings, IP addresses, URLs, and IOCs from target PIDs.
    """

    @staticmethod
    def carve_process(pid: int) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        if pid <= 4:
            return {
                "success": False,
                "timestamp": now,
                "pid": pid,
                "strings_found": 0,
                "iocs": [],
                "message": f"Action Refused: System process PID {pid} cannot be memory carved."
            }

        try:
            # Query executable path of target PID via PowerShell
            ps_cmd = f"Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object -ExpandProperty ExecutablePath"
            path = subprocess.check_output(f'powershell -NoProfile -Command "{ps_cmd}"', shell=True, text=True, errors="ignore").strip()

            if not path:
                return {
                    "success": False,
                    "timestamp": now,
                    "pid": pid,
                    "strings_found": 0,
                    "iocs": [],
                    "message": f"Could not resolve Executable Path for PID {pid}."
                }

            # Read printable strings from process executable binary
            printable_strings = []
            with open(path, "rb") as f:
                content = f.read(1024 * 1024)  # Read up to 1MB sample
                ascii_matches = re.findall(rb'[ -~]{4,}', content)
                for m in ascii_matches[:300]:
                    printable_strings.append(m.decode('ascii', errors='ignore'))

            # Extract IP addresses & URLs
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*')

            extracted_ips = set()
            extracted_urls = set()

            for s in printable_strings:
                for ip in ip_pattern.findall(s):
                    if not ip.startswith("127.") and not ip.startswith("0."):
                        extracted_ips.add(ip)
                for url in url_pattern.findall(s):
                    extracted_urls.add(url[:100])

            iocs = []
            for ip in extracted_ips:
                iocs.append({"type": "IP Address", "value": ip, "risk": "MEDIUM"})
            for url in extracted_urls:
                iocs.append({"type": "URL Endpoint", "value": url, "risk": "HIGH" if "http://" in url else "MEDIUM"})

            return {
                "success": True,
                "timestamp": now,
                "pid": pid,
                "executable_path": path,
                "strings_found": len(printable_strings),
                "iocs": iocs,
                "sample_strings": printable_strings[:20],
                "message": f"Carved {len(printable_strings)} strings and {len(iocs)} IOC indicators from PID {pid} ({path})."
            }
        except Exception as ex:
            return {
                "success": False,
                "timestamp": now,
                "pid": pid,
                "strings_found": 0,
                "iocs": [],
                "message": f"Memory carving notice for PID {pid}: {str(ex)}"
            }
