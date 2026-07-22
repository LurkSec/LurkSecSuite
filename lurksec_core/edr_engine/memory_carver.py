import re
import subprocess
import time
from typing import Dict, List, Any

class MemoryCarver:
    

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
                "message": f"Action Refused: Critical system process PID {pid} protected."
            }

        path = ""
        try:
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
                "message": f"Process PID {pid} executable path could not be resolved from OS API."
            }

        try:
            printable_strings = []
            with open(path, "rb") as f:
                content = f.read(1024 * 1024)
                ascii_matches = re.findall(rb'[ -~]{4,}', content)
                for m in ascii_matches[:300]:
                    try:
                        s = m.decode("ascii", errors="ignore")
                        printable_strings.append(s)
                    except Exception:
                        pass

            combined = "\n".join(printable_strings)
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', combined)
            urls = re.findall(r'https?://[^\s/$.?#].[^\s]*', combined)

            iocs = list(set(ips + urls))

            return {
                "success": True,
                "timestamp": now,
                "pid": pid,
                "executable_path": path,
                "strings_found": len(printable_strings),
                "iocs": iocs[:20],
                "sample_strings": printable_strings[:15],
                "message": f"Successfully carved {len(printable_strings)} memory/executable strings and {len(iocs)} IOCs from PID {pid}."
            }
        except Exception as ex:
            return {
                "success": False,
                "timestamp": now,
                "pid": pid,
                "strings_found": 0,
                "iocs": [],
                "message": f"Unable to carve memory/executable file for PID {pid}: {str(ex)}"
            }
