# Master LurkSec Security Operations Command Suite

**LurkSec Suite** (by **Lurk** / **LurkSec**) is an enterprise-grade, master defensive security operations center (SOC) command suite unifying 11 security engines into **one unified web console**. 

Built entirely in pure Python (standard library) with zero external dependencies, it provides real-time telemetry, threat intelligence, endpoint detection and response, web application firewall protection, identity security, and cloud security posture management.

---

## ⚡ Master Security Engines (11 Integrated Modules)

1. 🛡️ **LurkSOC (Master Incident Command)**: Correlates high-priority threats across all underlying engines into a unified incident feed.
2. 🌐 **LurkSentinel (Network & Socket Inspector)**: Active listening sockets, PID process resolver, GeoIP flags (`Cloudflare`, `Microsoft Azure`), and 150-thread TCP port scanner.
3. 🔐 **LurkSIEM (Log Correlation Engine)**: Windows Event Log parser (Security, System, App), logon audit stream (4624/4625), and brute-force rules.
4. 🍯 **LurkDecoy (Deception & Honeypots)**: Active low-interaction honeypot listeners (SSH:2222, FTP:2121, HTTP:8888, RDP:33890).
5. 📡 **LurkPacket (PCAP Protocol Inspector)**: DNS domain queries, HTTP headers, TLS SNI decoders, and Wireshark `.pcap` export generator.
6. 🔍 **LurkTrace (Process Execution Auditor)**: `Win32_Process` parent-child execution tree, command line inspection, and `%TEMP%` path anomaly rules.
7. 🔒 **LurkAudit (OS Hardening & Compliance)**: Scans Windows Firewall profiles, User Account Control (UAC), SMBv1 legacy protocol status, and administrative shares.
8. 🛑 **LurkEDR (Endpoint Detection & Response)**: Active response actions (Process Killer, Windows Firewall IP Blocker, File Quarantiner, and Process Memory Carver).
9. 🛡️ **LurkShield (Web Application Firewall & Rate Limiting)**: OWASP Top 10 threat inspection (SQLi, XSS, RCE, LFI, Command Injection), and token-bucket per-IP rate limiter.
10. 🧠 **LurkIntel (Threat Intelligence & CTI Feed)**: Live Feodo CTI botnet feed parser, CISA Known Exploited Vulnerabilities (KEV) catalog, MITRE ATT&CK heatmap, and IOC matcher.
11. 🆔 **LurkIdentity (Identity Security & Credential Auditor)**: 10-pattern secret scanner (API keys, JWT, SSH keys), HaveIBeenPwned k-Anonymity hash-range breach checker, and password policy compliance.
12. ☁️ **LurkCloud (Multi-Cloud Security Posture Inspector)**: AWS S3/EC2/IAM & Azure NSG security posture auditor with graceful local baseline fallback.

---

## 🚀 Quick Start

### Requirements
- Python 3.8+
- Windows 10 / 11 / Windows Server

### 1. Launch Master Command Suite
```bash
python lurksec.py serve --port 8000
```
Or double-click **`start_suite.bat`**. Open **`http://localhost:8000`** in your browser.

### 2. Run Master Security Audit (CLI)
```bash
python lurksec.py audit
```

### 3. Clone with Submodules
To clone the suite alongside all standalone engine submodules:
```bash
git clone --recursive https://github.com/LurkSec/LurkSecSuite.git
```

---

## 📁 Repository & Directory Structure

```
LurkSecSuite/
├── lurkcloud-security-engine/      # [Submodule] LurkCloud Standalone Engine
├── lurkdecoy-security-engine/      # [Submodule] LurkDecoy Standalone Engine
├── lurkedr-security-engine/        # [Submodule] LurkEDR Standalone Engine
├── lurkidentity-security-engine/   # [Submodule] LurkIdentity Standalone Engine
├── lurkintel-security-engine/      # [Submodule] LurkIntel Standalone Engine
├── lurkpacket-security-engine/     # [Submodule] LurkPacket Standalone Engine
├── lurkshield-security-engine/     # [Submodule] LurkShield Standalone Engine
├── lurksiem-security-engine/       # [Submodule] LurkSIEM Standalone Engine
├── lurktrace-security-engine/      # [Submodule] LurkTrace Standalone Engine
├── netsentinel-security-suite/     # [Submodule] NetSentinel Standalone Engine
├── lurksec_core/                   # Core Python Engines & Sub-Packages
│   ├── sys_info.py                 # LurkSentinel network socket & port scan engine
│   ├── log_parser.py                # LurkSIEM Event Log parser
│   ├── threat_correlator.py         # LurkSIEM correlation rules
│   ├── honeypot_listeners.py        # LurkDecoy honeypot manager
│   ├── packet_inspector.py          # LurkPacket PCAP & protocol decoder
│   ├── process_auditor.py           # LurkTrace Win32_Process hierarchy inspector
│   ├── system_auditor.py            # LurkAudit OS hardening scanner
│   ├── soc_aggregator.py            # LurkSOC master incident feed aggregator
│   ├── report_generator.py         # Master Executive Report Generator (HTML/MD/JSON)
│   ├── edr_engine/                 # LurkEDR active response engine
│   ├── shield_engine/              # LurkShield WAF & Rate Limiter engine
│   ├── intel_engine/               # LurkIntel CTI feed & MITRE mapper
│   ├── identity_engine/            # LurkIdentity secret scanner & HIBP checker
│   └── cloud_engine/               # LurkCloud multi-cloud posture inspector
├── web_console/                    # Master Front-End Operations Console
│   ├── index.html                  # 13-Tab Navigation Web Console
│   ├── css/
│   │   └── style.css               # Dark Charcoal theme with custom glow scrollbars
│   └── js/
│       └── app.js                  # Master JS controller & Wireshark PCAP exporter
├── lurksec.py                      # Master Entry Point & HTTP API Server (Port 8000)
├── start_suite.bat                 # Master 1-Click Launch Script
├── stop_suite.bat                  # Master 1-Click Shutdown Script
├── .gitmodules                     # Submodule Mapping for all 10 Standalone Repositories
├── README.md                       # Master Suite Documentation
└── LICENSE                         # MIT License
```

---

## 👨‍💻 Author & License
Created by **Lurk** (**LurkSec**). Distributed under the MIT License.
