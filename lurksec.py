import argparse
import json
import os
import socket
import sys
import time
import traceback
import webbrowser
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

SUMMARY_CACHE = {"timestamp": 0, "data": None}

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
from lurksec_core.edr_engine.policy_engine import EDRPolicyEngine

from lurksec_core.shield_engine.waf_inspector import WAFInspector
from lurksec_core.shield_engine.rate_limiter import RateLimiter
from lurksec_core.intel_engine.cti_engine import CTIFeedManager, IOCMatcher, MITREMapper
from lurksec_core.intel_engine.threat_feed import ThreatFeedManager
from lurksec_core.identity_engine.identity_engine import SecretScanner, PolicyAuditor
from lurksec_core.identity_engine.hibp_checker import HIBPChecker
from lurksec_core.cloud_engine.cloud_engine import AWSInspector, AzureInspector, BaselineAuditor

from lurksec_core.soar_engine.playbook_runner import PlaybookRunner
from lurksec_core.soar_engine.case_manager import CaseManager
from lurksec_core.hunt_engine.sigma_evaluator import SigmaEvaluator
from lurksec_core.hunt_engine.yara_scanner import YaraScanner

from lurksec_core.dns_engine.dns_sinkhole import DNSSinkhole
from lurksec_core.zero_engine.zero_trust import ZeroTrustEngine
from lurksec_core.vuln_engine.vuln_scanner import VulnerabilityScanner
from lurksec_core.sand_engine.malware_sandbox import MalwareSandbox
from lurksec_core.guard_engine.itdr_auditor import ITDRAuditor

DECOY_MANAGER = HoneypotManager()
DECOY_MANAGER.start_all()

EDR_ACTION_LOGS = []
WAF_BLOCK_LOG = []
WAF_RATE_LIMITER = RateLimiter()

SOAR_PLAYBOOKS = PlaybookRunner()
SOAR_CASES = CaseManager()
HUNT_SIGMA = SigmaEvaluator()
HUNT_YARA = YaraScanner()

DNS_ENGINE = DNSSinkhole()
ZERO_ENGINE = ZeroTrustEngine()
VULN_ENGINE = VulnerabilityScanner()
SAND_ENGINE = MalwareSandbox()
GUARD_ENGINE = ITDRAuditor()
POLICY_ENGINE = EDRPolicyEngine()
THREAT_FEED = ThreatFeedManager()
HUNT_HITS = []
AGENT_TELEMETRY_REGISTRY = {}



class LurkSecHandler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

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

            elif path == "/api/edr/policies":
                self.send_json({"policies": POLICY_ENGINE.get_rules()})

            elif path == "/api/intel/feed/sync":
                self.send_json(THREAT_FEED.fetch_live_feed())

            elif path == "/api/trace/tree":
                procs = ProcessAuditor.get_live_processes()
                nodes = []
                edges = []
                tree_lines = []
                pid_dict = {p["pid"]: p for p in procs}

                # Find parent processes that actually have children
                parent_counts = {}
                for p in procs:
                    pp = p.get("ppid", 0)
                    parent_counts[pp] = parent_counts.get(pp, 0) + 1

                # Include processes that are parent of multiple children or high/medium risk or shell executables
                active_parents = set(pp for pp, count in parent_counts.items() if count > 0 and pp != 0)

                relevant_procs = [
                    p for p in procs
                    if p.get("pid") in active_parents
                    or p.get("ppid") in active_parents
                    or p.get("severity") in ["HIGH", "MEDIUM"]
                    or p.get("name", "").lower() in ["powershell.exe", "cmd.exe", "explorer.exe", "mimikatz.exe"]
                ]
                if len(relevant_procs) > 45:
                    relevant_procs = relevant_procs[:45]

                rel_pids = set(p["pid"] for p in relevant_procs)


                for p in relevant_procs:
                    pid = p.get("pid")
                    ppid = p.get("ppid", 0)
                    name = p.get("name", "Unknown")
                    cmd = p.get("cmdline") or p.get("command_line") or name
                    parent_name = p.get("parent_name") or (pid_dict.get(ppid, {}).get("name") if ppid in pid_dict else "System")

                    is_susp = p.get("severity") == "HIGH" or any(s in cmd.lower() for s in ["-enc", "bypass", "downloadstring", "mimikatz", "temp"])
                    is_med = p.get("severity") == "MEDIUM"

                    group = "suspicious" if is_susp else ("warning" if is_med else "normal")

                    nodes.append({
                        "id": pid,
                        "label": f"{name}\nPID: {pid}",
                        "title": f"Process: {name}\nPID: {pid} | PPID: {ppid}\nParent: {parent_name}\nCmd: {cmd}",
                        "group": group
                    })

                    if ppid and ppid in rel_pids:
                        edges.append({"from": ppid, "to": pid})

                    branch = "├── " if ppid in rel_pids else "└── "
                    tree_lines.append({
                        "pid": pid,
                        "ppid": ppid,
                        "name": name,
                        "parent_name": parent_name,
                        "cmd": cmd,
                        "path": p.get("path", ""),
                        "severity": p.get("severity", "LOW")
                    })

                self.send_json({
                    "nodes": nodes,
                    "edges": edges,
                    "tree_items": tree_lines,
                    "total_processes": len(procs)
                })

            elif path == "/api/shield/inspect":
                from urllib.parse import unquote
                method = params.get("method", ["GET"])[0]
                uri = unquote(params.get("uri", ["/"])[0])
                client_ip = params.get("ip", ["127.0.0.1"])[0]
                result = WAFInspector.inspect_request(method, uri, {})
                result["client_ip"] = client_ip
                WAF_RATE_LIMITER.record_request(client_ip)
                WAF_BLOCK_LOG.insert(0, result)
                self.send_json(result)

            elif path == "/api/shield/summary":
                blocked = [r for r in WAF_BLOCK_LOG if r.get("blocked")]
                self.send_json({
                    "total_inspected": len(WAF_BLOCK_LOG),
                    "total_blocked": len(blocked),
                    "high_severity_blocks": len([r for r in blocked if r.get("severity") == "HIGH"]),
                    "block_log": WAF_BLOCK_LOG[:50],
                    "top_ips": WAF_RATE_LIMITER.get_top_ips(),
                    "blocked_ips": WAF_RATE_LIMITER.get_blocked_ips(),
                    "active_rules": WAFInspector.get_rule_summary()
                })

            elif path == "/api/intel/summary":
                threat_ips = CTIFeedManager.get_threat_ips()
                kev = CTIFeedManager.get_cisa_kev()
                active_ips = IOCMatcher.get_active_remote_ips()
                ioc_matches = IOCMatcher.match_iocs(active_ips, threat_ips)
                heatmap = MITREMapper.get_technique_heatmap(ioc_matches, [])
                self.send_json({
                    "threat_feed_size": len(threat_ips),
                    "active_connections": len(active_ips),
                    "ioc_matches": ioc_matches,
                    "mitre_heatmap": heatmap,
                    "cisa_kev": kev[:20],
                    "cisa_kev_count": len(kev)
                })

            elif path == "/api/identity/summary":
                findings = SecretScanner.scan_filesystem()
                policy_audits = PolicyAuditor.audit_password_policy()
                self.send_json({
                    "total_findings": len(findings),
                    "high_severity": len([f for f in findings if f.get("severity") == "HIGH"]),
                    "medium_severity": len([f for f in findings if f.get("severity") == "MEDIUM"]),
                    "findings": findings,
                    "policy_audits": policy_audits
                })

            elif path == "/api/identity/hibp":
                pw = params.get("pw", [""])[0]
                if pw:
                    self.send_json(HIBPChecker.check_password(pw))
                else:
                    self.send_json({"error": "No password provided."})

            elif path == "/api/cloud/summary":
                aws_available = AWSInspector.check_cli_available()
                azure_available = AzureInspector.check_cli_available()
                aws_s3 = AWSInspector.get_s3_findings() if aws_available else []
                aws_sg = AWSInspector.get_sg_findings() if aws_available else []
                aws_iam = AWSInspector.get_iam_findings() if aws_available else []
                aws_findings = aws_s3 + aws_sg + aws_iam
                azure_findings = (AzureInspector.get_nsg_findings() + AzureInspector.get_storage_findings()) if azure_available else []
                all_findings = aws_findings + azure_findings
                baseline = BaselineAuditor.audit()
                self.send_json({
                    "aws_available": aws_available,
                    "azure_available": azure_available,
                    "aws_findings": aws_findings,
                    "azure_findings": azure_findings,
                    "all_findings": all_findings,
                    "total_findings": len(all_findings),
                    "high_severity": len([f for f in all_findings if f.get("severity") == "HIGH"]),
                    "baseline": baseline
                })

            elif path == "/api/soar/summary":
                self.send_json({
                    "playbooks_count": len(SOAR_PLAYBOOKS.get_playbooks()),
                    "cases_count": len(SOAR_CASES.get_cases()),
                    "open_cases": len([c for c in SOAR_CASES.get_cases() if c["status"] in ["OPEN", "IN_PROGRESS"]]),
                    "playbooks": SOAR_PLAYBOOKS.get_playbooks(),
                    "cases": SOAR_CASES.get_cases(),
                    "history": SOAR_PLAYBOOKS.get_history()
                })

            elif path == "/api/soar/run":
                p_id = params.get("id", ["PB-001"])[0]
                ip = params.get("ip", ["192.168.1.100"])[0]
                res = SOAR_PLAYBOOKS.execute_playbook(p_id, {"ip": ip, "target_host": "LOCAL-HOST"})
                self.send_json(res)

            elif path == "/api/soar/case/update":
                c_id = params.get("id", [""])[0]
                status = params.get("status", [None])[0]
                note = params.get("note", [None])[0]
                res = SOAR_CASES.update_case(c_id, status=status, note=note)
                self.send_json(res)

            elif path == "/api/soar/case/create":
                title = params.get("title", ["Untitled Incident"])[0]
                desc = params.get("description", [""])[0]
                severity = params.get("severity", ["MEDIUM"])[0]
                assigned = params.get("assigned", ["Unassigned"])[0]
                new_case = SOAR_CASES.create_case(title, severity, desc, evidence=[desc] if desc else None)
                if assigned and assigned != "Unassigned":
                    SOAR_CASES.update_case(new_case["case_id"], assigned_to=assigned)
                    new_case["assigned_to"] = assigned
                self.send_json({"success": True, "case_id": new_case["case_id"], "case": new_case})

            elif path == "/api/hunt/summary":
                self.send_json({
                    "sigma_rules_count": len(HUNT_SIGMA.get_rules()),
                    "yara_sigs_count": len(HUNT_YARA.get_signatures()),
                    "hits_count": len(HUNT_HITS),
                    "sigma_rules": HUNT_SIGMA.get_rules(),
                    "yara_signatures": HUNT_YARA.get_signatures(),
                    "recent_hits": HUNT_HITS
                })

            elif path == "/api/hunt/scan":
                sample = params.get("sample", ["powershell.exe -enc aWYoMTEpew=="])[0]
                sigma_matches = HUNT_SIGMA.evaluate_text(sample)
                yara_matches = HUNT_YARA.scan_string(sample, source_name="Interactive Input")
                combined = sigma_matches + yara_matches
                for match in combined:
                    HUNT_HITS.insert(0, match)
                self.send_json({"matches_count": len(combined), "results": combined})

            elif path == "/api/dns/summary":
                self.send_json(DNS_ENGINE.get_summary())

            elif path == "/api/dns/query":
                domain = params.get("domain", ["example.com"])[0]
                ip = params.get("ip", ["127.0.0.1"])[0]
                self.send_json(DNS_ENGINE.inspect_query(domain, client_ip=ip))

            elif path == "/api/zero/summary":
                self.send_json(ZERO_ENGINE.get_summary())

            elif path == "/api/zero/verify":
                user = params.get("user", ["analyst@lurksec.io"])[0]
                dev = params.get("device", ["DEV-HOST-001"])[0]
                res_url = params.get("resource", ["/api/vault"])[0]
                mtls = params.get("mtls", ["true"])[0].lower() == "true"
                self.send_json(ZERO_ENGINE.verify_access(user, dev, res_url, mtls_valid=mtls))

            elif path == "/api/vuln/summary":
                self.send_json(VULN_ENGINE.audit_system_vulnerabilities())

            elif path == "/api/sand/summary":
                self.send_json(SAND_ENGINE.get_summary())

            elif path == "/api/sand/analyze":
                name = params.get("name", ["payload.exe"])[0]
                text = params.get("text", [""])[0]
                self.send_json(SAND_ENGINE.analyze_binary(name, sample_text=text))

            elif path == "/api/guard/summary":
                self.send_json(GUARD_ENGINE.audit_identity_threats())

            elif path == "/api/simulate":
                sim_type = params.get("type", ["rescan"])[0]
                now_str = time.strftime("%Y-%m-%d %H:%M:%S")

                procs = ProcessAuditor.get_live_processes()
                proc_alerts = ProcessAuditor.evaluate_anomalies(procs)
                id_audit = GUARD_ENGINE.audit_identity_threats()
                vuln_audit = VULN_ENGINE.audit_system_vulnerabilities()

                self.send_json({
                    "success": True,
                    "message": f"Real-time system telemetry rescan executed at {now_str}. Evaluated {len(procs)} processes, {len(vuln_audit.get('findings', []))} vulnerability baselines, and {len(id_audit.get('findings', []))} identity checks."
                })

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
                web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_console")
                clean_path = path.split('?')[0].lstrip("/")
                if not clean_path or clean_path == "index.html":
                    filepath = os.path.join(web_dir, "index.html")
                else:
                    filepath = os.path.normpath(os.path.join(web_dir, clean_path.replace("/", os.sep)))

                if filepath.startswith(web_dir) and os.path.isfile(filepath):
                    ctype = "text/html; charset=utf-8"
                    if filepath.endswith(".css"):
                        ctype = "text/css"
                    elif filepath.endswith(".js"):
                        ctype = "text/javascript"
                    elif filepath.endswith(".json"):
                        ctype = "application/json"
                    elif filepath.endswith(".png"):
                        ctype = "image/png"
                    elif filepath.endswith(".ico"):
                        ctype = "image/x-icon"

                    with open(filepath, "rb") as f:
                        content = f.read()

                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(content)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(content)
                    self.wfile.flush()
                else:
                    self.send_error(404, "File Not Found")

        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            traceback.print_exc()
            try:
                body = json.dumps({"error": str(e)}).encode()
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
            except Exception:
                pass

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

        for p in processes:
            cmd = p.get("command_line", "") or p.get("name", "")
            if cmd:
                sigma_m = HUNT_SIGMA.evaluate_text(cmd)
                yara_m = HUNT_YARA.scan_string(cmd, source_name=f"Process PID {p.get('pid')} ({p.get('name')})")
                for m in sigma_m + yara_m:
                    if not any(h.get("matched_sample") == m.get("matched_sample") or h.get("sig_id") == m.get("sig_id") for h in HUNT_HITS):
                        HUNT_HITS.insert(0, m)

        dns_sum = DNS_ENGINE.get_summary()
        zero_sum = ZERO_ENGINE.get_summary()
        vuln_sum = VULN_ENGINE.audit_system_vulnerabilities()
        sand_sum = SAND_ENGINE.get_summary()
        guard_sum = GUARD_ENGINE.audit_identity_threats()

        soc_incidents = SOCAggregator.aggregate_incidents(
            sockets, siem_alerts, decoy_summary, packet_alerts, process_alerts, audit_summary,
            edr_logs=EDR_ACTION_LOGS, waf_logs=WAF_BLOCK_LOG, soar_cases=SOAR_CASES.get_cases(), hunt_hits=HUNT_HITS,
            dns_summary=dns_sum, zero_summary=zero_sum, vuln_summary=vuln_sum, sand_summary=sand_sum, guard_summary=guard_sum
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
                "quarantined_files": FileQuarantiner.list_quarantined_files(),
                "policies": POLICY_ENGINE.get_rules(),
                "connected_agents": list(AGENT_TELEMETRY_REGISTRY.values())
            },

            "threat_feed": THREAT_FEED.get_summary(),
            "soar": {
                "playbooks_count": len(SOAR_PLAYBOOKS.get_playbooks()),
                "cases_count": len(SOAR_CASES.get_cases()),
                "open_cases": len([c for c in SOAR_CASES.get_cases() if c["status"] in ["OPEN", "IN_PROGRESS"]])
            },

            "hunt": {
                "sigma_rules_count": len(HUNT_SIGMA.get_rules()),
                "yara_sigs_count": len(HUNT_YARA.get_signatures()),
                "hits_count": len(HUNT_HITS)
            },
            "dns": dns_sum,
            "zero": zero_sum,
            "vuln": vuln_sum,
            "sand": sand_sum,
            "guard": guard_sum
        }

    def send_json(self, data):
        try:
            body = json.dumps(data, indent=2, default=str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (ConnectionAbortedError, BrokenPipeError):
            pass

    def send_text(self, text, mime_type):
        try:
            body = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (ConnectionAbortedError, BrokenPipeError):
            pass

    def do_POST(self):
        """Handle POST requests — used for SOAR case/playbook mutations."""
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length) if length else b'{}'
        try:
            body = json.loads(raw)
        except Exception:
            body = {}

        try:
            if path == "/api/soar/case/create":
                title = body.get("title", "Untitled Incident")
                desc = body.get("description", "")
                severity = body.get("severity", "MEDIUM")
                assigned = body.get("assigned", "Unassigned")
                new_case = SOAR_CASES.create_case(title, severity, desc, evidence=[desc] if desc else None)
                if assigned and assigned != "Unassigned":
                    SOAR_CASES.update_case(new_case["case_id"], assigned_to=assigned)
                    new_case["assigned_to"] = assigned
                self.send_json({"success": True, "case_id": new_case["case_id"], "case": new_case})

            elif path == "/api/soar/case/update":
                c_id = body.get("id", "")
                status = body.get("status")
                note = body.get("note")
                assigned = body.get("assigned")
                self.send_json(SOAR_CASES.update_case(c_id, status=status, note=note, assigned_to=assigned))

            elif path == "/api/soar/run":
                p_id = body.get("id", "PB-001")
                ip = body.get("ip", "")
                context = {"ip": ip, "target_host": "LOCAL-HOST"} if ip else {"target_host": "LOCAL-HOST"}
                self.send_json(SOAR_PLAYBOOKS.execute_playbook(p_id, context))

            elif path == "/api/edr/policy/add":
                name = body.get("name", "Custom Rule")
                proc_name = body.get("process_name", "")
                cmd = body.get("cmd_contains", "")
                action = body.get("action", "KILL_PROCESS")
                sev = body.get("severity", "HIGH")
                self.send_json(POLICY_ENGINE.add_rule(name, proc_name, cmd, action, sev))

            elif path == "/api/edr/policy/toggle":
                rule_id = body.get("id", "")
                self.send_json(POLICY_ENGINE.toggle_rule(rule_id))

            elif path == "/api/edr/policy/delete":
                rule_id = body.get("id", "")
                self.send_json(POLICY_ENGINE.delete_rule(rule_id))

            elif path == "/api/agent/telemetry":
                agent_id = body.get("agent_id", "LURK-AGENT-01")
                AGENT_TELEMETRY_REGISTRY[agent_id] = body
                self.send_json({"success": True, "message": "Agent telemetry ingested successfully", "agent_id": agent_id})

            elif path == "/api/terminal/exec":


                import subprocess
                cmd_str = body.get("command", "").strip()
                allowed = ["whoami", "netstat", "ipconfig", "tasklist", "ping", "nslookup", "systeminfo", "dir", "sc", "hostname"]
                first_word = cmd_str.split()[0].lower() if cmd_str else ""
                if not first_word or first_word not in allowed:
                    self.send_json({
                        "success": False,
                        "output": f"Command '{first_word}' restricted. Allowed diagnostic tools: {', '.join(allowed)}"
                    })
                else:
                    try:
                        out = subprocess.check_output(cmd_str, shell=True, text=True, errors="ignore", timeout=6)
                        self.send_json({"success": True, "output": out or "Command executed successfully (no output)."})
                    except subprocess.TimeoutExpired:
                        self.send_json({"success": False, "output": "Execution timed out (6s limit)."})
                    except Exception as e:
                        self.send_json({"success": False, "output": f"Execution error: {str(e)}"})

            else:
                self.send_json({"error": f"Unknown POST endpoint: {path}"})


        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            traceback.print_exc()
            try:
                self.send_json({"error": str(e)})
            except Exception:
                pass


class DualStackServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass
        super().server_bind()

def _free_port(port: int):
    import subprocess
    try:
        out = subprocess.check_output(
            f'netstat -ano | findstr ":{port} "',
            shell=True, text=True, errors="ignore"
        )
        pids = set()
        for line in out.splitlines():
            parts = line.split()
            if parts:
                try:
                    pids.add(int(parts[-1]))
                except ValueError:
                    pass
        our_pid = os.getpid()
        for pid in pids:
            if pid and pid != our_pid:
                try:
                    subprocess.call(f"taskkill /F /PID {pid}", shell=True,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print(f"[*] Freed port {port} from stale PID {pid}")
                except Exception:
                    pass
    except Exception:
        pass

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
        _free_port(args.port)
        import time as _time
        _time.sleep(0.5)

        httpd = None
        try:
            httpd = DualStackServer(("::", args.port), LurkSecHandler)
        except Exception:
            try:
                httpd = ThreadingHTTPServer(("0.0.0.0", args.port), LurkSecHandler)
            except OSError as e:
                print(f"[-] Failed to bind port {args.port}: {e}")
                sys.exit(1)

        url = f"http://127.0.0.1:{args.port}"
        print(f"[+] LurkSec Master Console listening on {url} (IPv4 & IPv6 Dual-Stack)")
        webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down LurkSec Server.")
        finally:
            httpd.server_close()

if __name__ == "__main__":
    main()
