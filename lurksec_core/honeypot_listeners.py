import socket
import threading
import time
from typing import Dict, List, Any

class HoneypotManager:
    def __init__(self):
        self.intrusions = []
        self.running = False
        self.threads = []
        self.ports = {
            2222:  {"name": "SSH Decoy Listener",       "service": "SSH-2.0-OpenSSH_8.9p1",         "protocol": "SSH",    "banner": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"},
            2121:  {"name": "FTP Decoy Listener",       "service": "ProFTPD 1.3.5 Server",           "protocol": "FTP",    "banner": b"220 LurkDecoy FTP Service Ready\r\n"},
            2323:  {"name": "Telnet Router Decoy",      "service": "Cisco IOS Terminal",             "protocol": "TELNET", "banner": b"User Access Verification\r\nUsername: "},
            8080:  {"name": "HTTP Web Admin Decoy",     "service": "Apache/2.4.52 (Ubuntu)",         "protocol": "HTTP",   "banner": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\nContent-Type: text/html\r\n\r\n<html><body><h1>LurkDecoy Admin Portal</h1></body></html>"},
            8443:  {"name": "HTTPS SSL Portal Decoy",   "service": "nginx/1.18.0 (SSL)",             "protocol": "HTTPS",  "banner": b"HTTP/1.1 403 Forbidden\r\nServer: nginx/1.18.0\r\n\r\nForbidden"},
            4450:  {"name": "SMB File Share Decoy",     "service": "Windows SMB v2 IPC$",            "protocol": "SMB",    "banner": b"\xfeSMB\x00\x00\x00\x00\x00\x00\x00\x00"},
            14330: {"name": "MSSQL Server Decoy",       "service": "Microsoft SQL Server 2019",      "protocol": "TDS",    "banner": b"\x04\x01\x00\x25\x00\x00\x01\x00"},
            33060: {"name": "MySQL Server Decoy",       "service": "5.7.33-MySQL Community Server",  "protocol": "MYSQL",  "banner": b"J\x00\x00\x00\x0a5.7.33-log\x00"},
            33890: {"name": "RDP Remote Desktop Decoy", "service": "Microsoft RDP Terminal",         "protocol": "RDP",    "banner": b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x00\x00\x00\x00"},
            54320: {"name": "PostgreSQL DB Decoy",      "service": "PostgreSQL 14.2 Server",         "protocol": "POSTGRES", "banner": b"E\x00\x00\x00\x5bSFATAL\x00C28000\x00Mno pg_hba.conf entry\x00"},
            16379: {"name": "Redis In-Memory Decoy",    "service": "Redis server v=6.2.6",           "protocol": "REDIS",  "banner": b"-ERR unauthenticated redis connection\r\n"},
            27017: {"name": "MongoDB NoSQL Decoy",      "service": "MongoDB v5.0.6 Engine",          "protocol": "MONGO",  "banner": b"\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00"}
        }

    def start_all(self):
        if self.running:
            return
        self.running = True
        for port, info in self.ports.items():
            t = threading.Thread(target=self._run_listener, args=(port, info), daemon=True)
            t.start()
            self.threads.append(t)

    def _run_listener(self, port: int, info: Dict[str, Any]):
        s = None
        service_name = info["service"]
        banner = info["banner"]

        for p in [port, port + 100, port + 1000]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", p))
                sock.listen(5)
                sock.settimeout(2.0)
                s = sock
                port = p
                break
            except Exception:
                try: sock.close()
                except Exception: pass

        if not s:
            return

        while self.running:
            try:
                conn, addr = s.accept()
                src_ip = addr[0]
                payload = "TCP Decoy Connection Probe"

                try:
                    conn.sendall(banner)
                except Exception:
                    pass

                conn.settimeout(0.5)
                try:
                    data = conn.recv(512)
                    if data:
                        payload = data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass

                self._record_probe(port, service_name, src_ip, payload[:150])
                try: conn.close()
                except Exception: pass
            except socket.timeout:
                continue
            except Exception:
                pass
        try: s.close()
        except Exception: pass

    def _record_probe(self, port: int, service: str, src_ip: str, payload: str):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        origin = "Local Loopback" if src_ip in ["127.0.0.1", "0.0.0.0"] else ("Private LAN" if src_ip.startswith("192.168.") or src_ip.startswith("10.") else "Public Internet")
        severity = "HIGH" if port in [2222, 33890, 4450, 14330] else "MEDIUM"

        record = {
            "probe_id": f"PROBE-{len(self.intrusions) + 1001}",
            "timestamp": now,
            "target_port": port,
            "service": service,
            "source_ip": src_ip,
            "origin": origin,
            "severity": severity,
            "payload": payload or "TCP Probe"
        }
        self.intrusions.insert(0, record)

    def get_summary(self) -> Dict[str, Any]:
        high_count = sum(1 for i in self.intrusions if i["severity"] == "HIGH")
        med_count = sum(1 for i in self.intrusions if i["severity"] == "MEDIUM")
        
        active_listeners = []
        for port, info in self.ports.items():
            active_listeners.append({
                "port": port,
                "name": info["name"],
                "service": info["service"],
                "protocol": info["protocol"],
                "status": "LISTENING"
            })

        return {
            "total_probes": len(self.intrusions),
            "severity_counts": {"HIGH": high_count, "MEDIUM": med_count, "LOW": 0},
            "intrusions": self.intrusions,
            "active_listeners": active_listeners
        }
