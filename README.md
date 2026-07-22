# Master LurkSec Security Operations Command Suite

**LurkSec Suite** (by **Lurk**) is a master defensive security operations center (SOC) console unifying host network inspection, Windows Event Log SIEM correlation, deception honeypot telemetry, live PCAP packet inspection, process execution tree auditing, and OS hardening compliance into **one single web console**.

---

## ⚡ Master Security Engines

1. 🛡️ **LurkSOC (Master Incident Command)**: Correlates high-priority threats across all underlying engines into a single incident feed.
2. 🌐 **LurkSentinel (Network & Socket Inspector)**: Active listening sockets, PID process resolver, GeoIP flags (` Cloudflare`, ` Microsoft Azure`), 150-thread TCP port scanner.
3. 🔐 **LurkSIEM (Log Correlation Engine)**: Windows Event Log parser (Security, System, App), logon audit stream (4624/4625), brute-force rules.
4. 🍯 **LurkDecoy (Deception & Honeypots)**: Active low-interaction honeypot listeners (SSH:2222, FTP:2121, HTTP:8888, RDP:33890).
5. 📡 **LurkPacket (PCAP Protocol Inspector)**: DNS domain queries, HTTP headers, TLS SNI decoders, Wireshark `.pcap` export generator.
6. 🔍 **LurkTrace (Process Execution Auditor)**: `Win32_Process` parent-child execution tree, command line inspection, `%TEMP%` path anomaly rules.
7. 🔒 **LurkAudit (OS Hardening & Compliance)**: Scans Windows Firewall profiles, User Account Control (UAC), SMBv1 legacy protocol status, and administrative shares.

---

## 🚀 Quick Start

### Requirements
- Python 3.8+
- Windows 10/11 (or Windows Server)

### 1. Launch Master Command Suite
```bash
python lurksec.py serve --port 8000
```
Or double-click **`start_suite.bat`**. Open **`http://localhost:8000`** in your browser.

### 2. Run Master Security Audit (CLI)
```bash
python lurksec.py audit
```

### 3. Export Master Executive Security Report (CLI)
```bash
python lurksec.py report --format html --output master_security_report.html
```

---

## Directory Structure

```
LurkSecSuite/
├── lurksec_core/
│   ├── sys_info.py          # LurkSentinel network socket & port scan engine
│   ├── log_parser.py         # LurkSIEM Event Log parser
│   ├── threat_correlator.py  # LurkSIEM correlation rules
│   ├── honeypot_listeners.py # LurkDecoy honeypot manager
│   ├── packet_inspector.py   # LurkPacket PCAP & protocol decoder
│   ├── process_auditor.py    # LurkTrace Win32_Process hierarchy inspector
│   ├── system_auditor.py     # LurkAudit OS hardening scanner
│   ├── soc_aggregator.py     # LurkSOC master incident feed aggregator
│   └── report_generator.py  # Master report generator (HTML/MD/JSON)
├── web_console/
│   ├── index.html           # Master LurkSec Web Console
│   ├── css/
│   │   └── style.css        # Charcoal theme styling with fixed tables
│   └── js/
│       └── app.js           # Master JS controller & Wireshark PCAP export
├── lurksec.py               # Single Master Entry Point (Port 8000)
├── start_suite.bat          # Master 1-Click Launch Script
├── stop_suite.bat           # Master 1-Click Shutdown Script
├── README.md                # Master GitHub Documentation
└── LICENSE                  # MIT License
```

---

## Author
Created by **Lurk**. Distributed under the MIT License.
