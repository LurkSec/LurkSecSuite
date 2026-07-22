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
            2222: "SSH Decoy Listener",
            2121: "FTP Decoy Listener",
            8888: "HTTP Web Decoy",
            33890: "RDP Decoy Listener"
        }

    def start_all(self):
        if self.running:
            return
        self.running = True
        for port, service in self.ports.items():
            t = threading.Thread(target=self._run_listener, args=(port, service), daemon=True)
            t.start()
            self.threads.append(t)

    def _run_listener(self, port: int, service: str):
        s = None
        for p in [port, port + 1000, port + 10000]:
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
                payload = "TCP Connection Probe"

                try:
                    if port in [2222, 3222]: conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
                    elif port in [2121, 3121]: conn.sendall(b"220 LurkDecoy FTP Service Ready\r\n")
                    elif port in [8888, 9888, 8080]: conn.sendall(b"HTTP/1.1 200 OK\r\nServer: LurkDecoy-HTTP\r\nContent-Length: 13\r\n\r\nAccess Denied")
                except Exception:
                    pass

                conn.settimeout(0.5)
                try:
                    data = conn.recv(512)
                    if data: payload = data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass

                self._record_probe(port, service, src_ip, payload[:120])
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
        severity = "HIGH" if port in [2222, 33890] else "MEDIUM"

        record = {
            "probe_id": f"PROBE-{len(self.intrusions) + 1001}",
            "timestamp": now,
            "target_port": port,
            "service": service,
            "source_ip": src_ip,
            "origin": origin,
            "severity": severity,
            "payload": payload
        }
        self.intrusions.insert(0, record)

    def get_summary(self) -> Dict[str, Any]:
        high_count = sum(1 for i in self.intrusions if i["severity"] == "HIGH")
        med_count = sum(1 for i in self.intrusions if i["severity"] == "MEDIUM")
        return {
            "total_probes": len(self.intrusions),
            "severity_counts": {"HIGH": high_count, "MEDIUM": med_count, "LOW": 0},
            "intrusions": self.intrusions
        }
