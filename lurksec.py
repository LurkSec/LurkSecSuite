import argparse
import json
import os
import sys
import traceback
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lurksec_core.sys_info import SystemNetworkInfo
from lurksec_core.log_parser import SIEMLogParser
from lurksec_core.threat_correlator import SIEMCorrelator
from lurksec_core.honeypot_listeners import HoneypotManager
from lurksec_core.packet_inspector import PacketInspector
from lurksec_core.process_auditor import ProcessAuditor
from lurksec_core.system_auditor import SystemAuditor
from lurksec_core.soc_aggregator import SOCAggregator
from lurksec_core.report_generator import MasterReportGenerator

from lurksec_core.edr_engine.process_killer import ProcessKiller
from lurksec_core.edr_engine.firewall_blocker import FirewallBlocker
from lurksec_core.edr_engine.file_quarantiner import FileQuarantiner
from lurksec_core.edr_engine.memory_carver import MemoryCarver

# Global Managers
DECOY_MANAGER = HoneypotManager()
DECOY_MANAGER.start_all()

EDR_ACTION_LOGS = []

class LurkSecHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_console")
        super().__init__(*args, directory=web_dir, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        try:
            if path == "/api/summary":
                self.send_json(self.get_master_summary())

            elif path == "/api/portscan":
                res = SystemNetworkInfo.run_port_scan()
                self.send_json({"total_open": len(res), "results": res})

            elif path == "/api/pcap":
                packets = PacketInspector.capture_live_packets(20)
                pcap_bytes = PacketInspector.generate_pcap_bytes(packets)
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
                self.send_header("Content-Disposition", 'attachment; filename="LurkSec_Capture.pcap"')
                self.send_header("Content-Length", str(len(pcap_bytes)))
                self.end_headers()
                self.wfile.write(pcap_bytes)

            elif path == "/api/edr/kill":
                pid_str = params.get("pid", ["0"])[0]
                pid = int(pid_str) if pid_str.isdigit() else 0
                res = ProcessKiller.kill_process(pid)
                EDR_ACTION_LOGS.insert(0, {
                    "timestamp": res["timestamp"],
                    "action_type": "Process Termination",
                    "target": f"PID {pid}",
                    "success": res["success"],
                    "message": res["message"]
                })
                self.send_json(res)

            elif path == "/api/edr/block":
                ip = params.get("ip", [""])[0]
                res = FirewallBlocker.block_ip(ip)
                EDR_ACTION_LOGS.insert(0, {
                    "timestamp": res["timestamp"],
                    "action_type": "Firewall IP Block",
                    "target": f"IP {ip}",
                    "success": res["success"],
                    "message": res["message"]
                })
                self.send_json(res)

            elif path == "/api/edr/quarantine":
                filepath = params.get("path", [""])[0]
                res = FileQuarantiner.quarantine_file(filepath)
                EDR_ACTION_LOGS.insert(0, {
                    "timestamp": res["timestamp"],
                    "action_type": "Binary Quarantine",
                    "target": filepath,
                    "success": res["success"],
                    "message": res["message"]
                })
                self.send_json(res)

            elif path == "/api/edr/carve":
                pid_str = params.get("pid", ["0"])[0]
                pid = int(pid_str) if pid_str.isdigit() else 0
                res = MemoryCarver.carve_process(pid)
                EDR_ACTION_LOGS.insert(0, {
                    "timestamp": res["timestamp"],
                    "action_type": "Memory String Carver",
                    "target": f"PID {pid}",
                    "success": res["success"],
                    "message": res["message"]
                })
                self.send_json(res)

            elif path == "/api/report/json":
                summary = self.get_master_summary()
                rep = MasterReportGenerator(summary)
                self.send_text(rep.generate_json(), "application/json")

            elif path == "/api/report/md":
                summary = self.get_master_summary()
                rep = MasterReportGenerator(summary)
                self.send_text(rep.generate_markdown(), "text/markdown")

            elif path == "/api/report/html":
                summary = self.get_master_summary()
                rep = MasterReportGenerator(summary)
                self.send_text(rep.generate_html(), "text/html")

            else:
                super().do_GET()

        except Exception as e:
            traceback.print_exc()
            self.send_error(500, f"Server Error: {str(e)}")

    def get_master_summary(self):
        host_info = SystemNetworkInfo.get_host_details()
        sockets = SystemNetworkInfo.get_network_sockets()
        siem_events = SIEMLogParser.get_real_events(max_events=40)
        siem_alerts = SIEMCorrelator(siem_events).evaluate_rules()
        decoy_summary = DECOY_MANAGER.get_summary()

        packets = PacketInspector.capture_live_packets(20)
        packet_alerts = PacketInspector.evaluate_threats(packets)

        processes = ProcessAuditor.get_live_processes()
        process_alerts = ProcessAuditor.evaluate_anomalies(processes)

        audit_summary = SystemAuditor.audit_os_hardening()

        soc_incidents = SOCAggregator.aggregate_incidents(
            sockets, siem_alerts, decoy_summary, packet_alerts, process_alerts, audit_summary
        )

        return {
            "host_info": host_info,
            "sockets": sockets,
            "siem_events": siem_events,
            "siem_alerts": siem_alerts,
            "decoy_summary": decoy_summary,
            "packets": packets,
            "packet_alerts": packet_alerts,
            "processes": processes,
            "process_alerts": process_alerts,
            "audit": audit_summary,
            "soc_incidents": soc_incidents,
            "edr": {
                "action_logs": EDR_ACTION_LOGS,
                "quarantined_files": FileQuarantiner.list_quarantined_files()
            }
        }

    def send_json(self, data):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text, mime_type):
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def main():
    parser = argparse.ArgumentParser(description="LurkSec Unified Security Operations Suite Server")
    parser.add_argument("action", nargs="?", default="serve", choices=["serve", "audit"])
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    if args.action == "audit":
        print("[*] Running Master LurkSec Security Audit across all engines...")
        host = SystemNetworkInfo.get_host_details()
        sockets = SystemNetworkInfo.get_network_sockets()
        events = SIEMLogParser.get_real_events(30)
        siem_alerts = SIEMCorrelator(events).evaluate_rules()
        decoy = DECOY_MANAGER.get_summary()
        pkts = PacketInspector.capture_live_packets(10)
        pkt_alerts = PacketInspector.evaluate_threats(pkts)
        procs = ProcessAuditor.get_live_processes()
        proc_alerts = ProcessAuditor.evaluate_anomalies(procs)
        audit = SystemAuditor.audit_os_hardening()

        soc = SOCAggregator.aggregate_incidents(sockets, siem_alerts, decoy, pkt_alerts, proc_alerts, audit)
        print(f"[+] Master Audit Complete. Correlated Incidents: {soc['total_incidents']} (High Risk: {soc['severity_counts']['HIGH']}).")
        print(f"[+] OS Hardening Compliance Score: {audit['score']}%")
        for inc in soc["incidents"]:
            if inc["severity"] in ["HIGH", "MEDIUM"]:
                print(f"  [{inc['engine']}] ({inc['severity']}) {inc['title']} | Evidence: {inc['evidence']}")
    else:
        server_address = ("", args.port)
        httpd = HTTPServer(server_address, LurkSecHandler)
        url = f"http://localhost:{args.port}"
        print(f"[+] LurkSec Master Console listening on {url}")
        webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down LurkSec Server.")

if __name__ == "__main__":
    main()
