import socket
import subprocess
import time
import concurrent.futures
from typing import Dict, List, Any

class SystemNetworkInfo:
    @staticmethod
    def get_host_details() -> Dict[str, Any]:
        import platform
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = "127.0.0.1"

        ver = platform.version()
        build = ver.split(".")[-1] if ver else "22631"

        ram_gb = 16.0
        uptime_hrs = 12.4
        import os
        cores = os.cpu_count() or 8

        try:
            import psutil
            mem = psutil.virtual_memory()
            ram_gb = round(mem.total / (1024**3), 1)
            uptime_hrs = round((time.time() - psutil.boot_time()) / 3600, 1)
            cores = psutil.cpu_count(logical=True) or cores
        except Exception:
            pass


        os_name = f"{platform.system()} {platform.release()}" if platform.system() == "Windows" else platform.system()

        return {
            "hostname": hostname,
            "local_ip": local_ip,
            "os": os_name,
            "build": f"Build {build}",
            "full_os": f"{os_name} (Build {build})",
            "arch": platform.machine() or "AMD64",
            "cpu_cores": cores,
            "ram_total_gb": ram_gb,
            "uptime_hrs": uptime_hrs,
            "python_ver": platform.python_version()
        }


    @staticmethod
    def get_process_map() -> Dict[int, str]:
        proc_map = {}
        try:
            out = subprocess.check_output("tasklist /FO CSV /NH", shell=True, text=True, errors="ignore")
            for line in out.splitlines():
                parts = line.split('","')
                if len(parts) >= 2:
                    name = parts[0].replace('"', '').strip()
                    pid_str = parts[1].replace('"', '').strip()
                    if pid_str.isdigit():
                        proc_map[int(pid_str)] = name
        except Exception:
            pass
        return proc_map

    @staticmethod
    def classify_ip(ip_str: str) -> str:
        if not ip_str or ip_str in ["0.0.0.0", "127.0.0.1", "*"]:
            return "Local Host"
        parts = ip_str.split(".")
        if len(parts) == 4 and parts[0].isdigit():
            p0, p1 = int(parts[0]), int(parts[1])
            if p0 == 10 or (p0 == 192 and p1 == 168) or (p0 == 172 and 16 <= p1 <= 31):
                return "Private LAN"
        
        if ip_str.startswith(("172.64.", "162.159.", "104.16.")):
            return "Cloudflare Host"
        elif ip_str.startswith(("142.250.", "172.217.")):
            return "Google Cloud"
        elif ip_str.startswith(("13.", "20.", "52.")):
            return "Microsoft Azure"
        elif ip_str.startswith(("44.", "54.", "3.")):
            return "Amazon AWS"
        return "Public Internet"

    @staticmethod
    def get_network_sockets() -> List[Dict[str, Any]]:
        proc_map = SystemNetworkInfo.get_process_map()
        sockets = []
        try:
            out = subprocess.check_output("netstat -ano", shell=True, text=True, errors="ignore")
            idx = 1
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0].upper() in ["TCP", "UDP"]:
                    proto = parts[0].upper()
                    local_addr = parts[1]
                    foreign_addr = parts[2]
                    state = parts[3] if proto == "TCP" and len(parts) >= 5 else "N/A"
                    pid_str = parts[-1] if parts[-1].isdigit() else "0"
                    pid = int(pid_str)
                    proc_name = proc_map.get(pid, "System Process")

                    foreign_ip = foreign_addr.split(":")[0] if ":" in foreign_addr else foreign_addr
                    origin = SystemNetworkInfo.classify_ip(foreign_ip)

                    sockets.append({
                        "id": f"SOCK-{idx:04d}",
                        "protocol": proto,
                        "local_address": local_addr,
                        "foreign_address": foreign_addr,
                        "origin": origin,
                        "state": state,
                        "pid": pid,
                        "process_name": proc_name,
                        "severity": "HIGH" if state == "ESTABLISHED" and origin == "Public Internet" else "LOW"
                    })
                    idx += 1
        except Exception:
            pass
        return sockets[:100]

    @staticmethod
    def run_port_scan(target_host: str = "127.0.0.1", start_port: int = 1, end_port: int = 1024) -> List[Dict[str, Any]]:
        results = []
        common_ports = {
            21: ("FTP", "File Transfer Protocol"),
            22: ("SSH", "Secure Shell Remote Service"),
            80: ("HTTP", "Web Server"),
            135: ("RPC", "Microsoft RPC Endpoint Mapper"),
            443: ("HTTPS", "Encrypted Web Transport"),
            445: ("SMB", "Microsoft SMB Sharing"),
            3389: ("RDP", "Remote Desktop Protocol")
        }

        def check_port(p):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                res = s.connect_ex((target_host, p))
                s.close()
                if res == 0:
                    svc = common_ports.get(p, ("Unknown", "Active Listening Port"))
                    return {
                        "port": p,
                        "service": svc[0],
                        "description": svc[1],
                        "risk": "HIGH" if p in [135, 445, 3389] else "MEDIUM",
                        "banner": "Active Connection Established"
                    }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_port, p) for p in range(start_port, min(end_port + 1, start_port + 200))]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    results.append(res)

        results.sort(key=lambda x: x["port"])
        return results
