import re
import subprocess
import time
from typing import Dict, List, Any

class MemoryCarver:
    """
    Extracts process artifacts, ASCII strings, IP addresses, URLs, and IOCs from target PIDs.
    Uses fast process path discovery with timeout safeguards.
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

        path = ""
        try:
            # Query executable path of target PID via WMIC or PowerShell with timeout
            cmd_wmic = f"wmic process where processid={pid} get ExecutablePath /format:csv"
            out = subprocess.check_output(cmd_wmic, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=2, errors="ignore")
            lines = [line.strip() for line in out.splitlines() if line.strip() and not line.startswith("Node")]
            if lines and "," in lines[0]:
                parts = lines[0].split(",")
                if len(parts) >= 2 and parts[1]:
                    path = parts[1]
        except Exception:
            pass

        if not path:
            try:
                ps_cmd = f"Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object -ExpandProperty ExecutablePath"
                path = subprocess.check_output(f'powershell -NoProfile -Command "{ps_cmd}"', shell=True, text=True, timeout=2, errors="ignore").strip()
            except Exception:
                pass

        if not path:
            return {
                "success": False,
                "timestamp": now,
                "pid": pid,
                "strings_found": 0,
                "iocs": [],
                "message": f"Process PID {pid} is not active or ExecutablePath cannot be accessed."
            }

        try:
            printable_strings = []
            with open(path, "rb") as f:
                content = f.read(1024 * 1024)  # Read 1MB sample
                ascii_matches = re.findall(rb'[ -~]{4,}', content)
                for m in ascii_matches[:300]:
                    printable_strings.append(m.decode('ascii', errors='ignore'))

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

            iocs = [{"type": "IP Address", "value": ip} for ip in sorted(extracted_ips)]
            for url in sorted(extracted_urls):
                iocs.append({"type": "URL / Endpoint", "value": url})

            return {
                "success": True,
                "timestamp": now,
                "pid": pid,
                "executable_path": path,
                "strings_found": len(printable_strings),
                "iocs": iocs[:30],
                "sample_strings": printable_strings[:20],
                "message": f"Successfully carved {len(printable_strings)} strings & {len(iocs)} IOC indicators from PID {pid} ({path})."
            }
        except Exception as ex:
            return {
                "success": False,
                "timestamp": now,
                "pid": pid,
                "strings_found": 0,
                "iocs": [],
                "message": f"Memory carving error reading binary: {str(ex)}"
            }
