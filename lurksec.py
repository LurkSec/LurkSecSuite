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

# Initialize global honeypot background manager
honeypot_mgr = HoneypotManager()
honeypot_mgr.start_all()

class MasterLurkSecHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_console")
        super().__init__(*args, directory=web_dir, **kwargs)

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/api/summary":
                self.send_json(self.get_master_summary())
            elif path == "/api/portscan":
                results = SystemNetworkInfo.run_port_scan()
                self.send_json({"total_open": len(results), "results": results})
            elif path == "/api/pcap":
                summary = self.get_master_summary()
                pcap_bytes = PacketInspector.generate_pcap_bytes(summary["packets"])
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
                self.send_header("Content-Disposition", 'attachment; filename="Master_LurkSec_Capture.pcap"')
                self.send_header("Content-Length", str(len(pcap_bytes)))
                self.end_headers()
                self.wfile.write(pcap_bytes)
            elif path == "/api/report/html":
                summary = self.get_master_summary()
                report = MasterReportGenerator(summary)
                self.send_text(report.to_html(), "text/html")
            elif path == "/api/report/json":
                summary = self.get_master_summary()
                report = MasterReportGenerator(summary)
                self.send_json(json.loads(report.to_json()))
            elif path == "/api/report/md":
                summary = self.get_master_summary()
                report = MasterReportGenerator(summary)
                self.send_text(report.to_markdown(), "text/markdown")
            else:
                super().do_GET()
        except Exception as e:
            print("[ERROR] Master LurkSec GET Error:", e)
            traceback.print_exc()

    def send_json(self, data):
        json_bytes = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(json_bytes)))
        self.end_headers()
        self.wfile.write(json_bytes)

    def send_text(self, text, content_type):
        text_bytes = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(text_bytes)))
        self.end_headers()
        self.wfile.write(text_bytes)

    def get_master_summary(self):
        host_info = SystemNetworkInfo.get_host_details()
        sockets = SystemNetworkInfo.get_network_sockets()
        siem_events = SIEMLogParser.get_real_events(50)
        siem_alerts = SIEMCorrelator(siem_events).evaluate_rules()
        decoy_summary = honeypot_mgr.get_summary()
        packets = PacketInspector.capture_live_packets(40)
        packet_alerts = PacketInspector.evaluate_threats(packets)
        processes = ProcessAuditor.get_live_processes()
        process_alerts = ProcessAuditor.evaluate_anomalies(processes)
        audit_summary = SystemAuditor.audit_os_hardening()

        soc_incidents = SOCAggregator.aggregate_incidents(
            sockets, siem_alerts, decoy_summary, packet_alerts, process_alerts, audit_summary
        )

        return {
            "host_info": host_info,
            "soc_incidents": soc_incidents,
            "sockets": sockets,
            "siem_events": siem_events,
            "siem_alerts": siem_alerts,
            "decoy_summary": decoy_summary,
            "packets": packets,
            "packet_alerts": packet_alerts,
            "processes": processes,
            "process_alerts": process_alerts,
            "audit": audit_summary
        }


def main():
    parser = argparse.ArgumentParser(description="Master LurkSec Defensive Security Suite")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("audit", help="Run master security audit across all 6 engines")

    serve_p = subparsers.add_parser("serve", help="Launch Master LurkSec Web Console")
    serve_p.add_argument("--port", type=int, default=8000)

    report_p = subparsers.add_parser("report", help="Generate master security report")
    report_p.add_argument("--format", choices=["html", "markdown", "json"], default="html")
    report_p.add_argument("--output", default="master_security_report.html")

    args = parser.parse_args()

    if args.command == "audit":
        print("[*] Running Master LurkSec Security Audit across all engines...")
        handler = MasterLurkSecHandler.__new__(MasterLurkSecHandler)
        summary = handler.get_master_summary()
        soc = summary["soc_incidents"]
        print(f"[+] Master Audit Complete. Correlated Incidents: {soc['total_incidents']} (High Risk: {soc['severity_counts']['HIGH']}).")
        print(f"[+] OS Hardening Compliance Score: {summary['audit']['score']}%")
        for inc in soc["incidents"][:8]:
            try:
                print(f"  [{inc['engine']}] ({inc['severity']}) {inc['title']} | {inc['evidence']}")
            except Exception:
                safe_eng = inc['engine'].encode('ascii', 'ignore').decode('ascii')
                print(f"  [{safe_eng}] ({inc['severity']}) {inc['title']} | {inc['evidence']}")

    elif args.command == "serve":
        server = HTTPServer(("", args.port), MasterLurkSecHandler)
        url = f"http://localhost:{args.port}"
        print(f"Master LurkSec Command Suite running on {url}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Master LurkSec server.")

    elif args.command == "report":
        handler = MasterLurkSecHandler.__new__(MasterLurkSecHandler)
        summary = handler.get_master_summary()
        gen = MasterReportGenerator(summary)

        if args.format == "html": out = gen.to_html()
        elif args.format == "markdown": out = gen.to_markdown()
        else: out = gen.to_json()

        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] Saved Master LurkSec report to {os.path.abspath(args.output)}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
