import subprocess
import time
from typing import Dict, Any

class ProcessKiller:
    """
    Terminates target malicious PIDs and their spawned child process trees using taskkill /F /T.
    """

    @staticmethod
    def kill_process(pid: int) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        if pid <= 4:
            return {
                "success": False,
                "timestamp": now,
                "pid": pid,
                "message": f"Action Refused: System process PID {pid} cannot be terminated."
            }

        try:
            cmd = f"taskkill /F /T /PID {pid}"
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, errors="ignore")
            return {
                "success": True,
                "timestamp": now,
                "pid": pid,
                "message": f"Process PID {pid} & spawned tree successfully terminated: {out.strip()}"
            }
        except subprocess.CalledProcessError as e:
            return {
                "success": False,
                "timestamp": now,
                "pid": pid,
                "message": f"Failed to terminate PID {pid}: {e.output.strip() if e.output else str(e)}"
            }
        except Exception as ex:
            return {
                "success": False,
                "timestamp": now,
                "pid": pid,
                "message": f"Error attempting PID termination: {str(ex)}"
            }
