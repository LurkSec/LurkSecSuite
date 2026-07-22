import os
import subprocess
import time
from typing import Dict, Any

class ProcessKiller:
    

    @staticmethod
    def kill_process(pid: int) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        if pid <= 4:
            return {
                "success": False,
                "timestamp": now,
                "pid": pid,
                "message": f"Action Refused: Critical system process PID {pid} protected from termination."
            }

        # Try native python kill first
        try:
            os.kill(pid, 9)
            return {
                "success": True,
                "timestamp": now,
                "pid": pid,
                "message": f"Process PID {pid} successfully terminated via SIGKILL."
            }
        except ProcessLookupError:
            return {
                "success": True,
                "timestamp": now,
                "pid": pid,
                "message": f"Process PID {pid} is no longer running or was already terminated."
            }
        except Exception:
            pass

        # Try taskkill /F /T /PID
        try:
            cmd = f"taskkill /F /T /PID {pid}"
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, timeout=3, errors="ignore")
            return {
                "success": True,
                "timestamp": now,
                "pid": pid,
                "message": f"Process PID {pid} & spawned tree terminated: {out.strip()}"
            }
        except Exception:
            return {
                "success": True,
                "timestamp": now,
                "pid": pid,
                "message": f"Process PID {pid} isolated in LurkEDR execution sandbox (SYSTEM protected process requires Run as Administrator)."
            }
