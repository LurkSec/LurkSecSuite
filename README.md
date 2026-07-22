# LurkSec Master Security Operations Suite

**LurkSec Suite** is an enterprise-grade defensive security operations center (SOC) command suite unifying **18 defensive security engines** into one unified web console — built entirely in pure Python with zero external dependencies.

It provides real-time telemetry correlation, automated IR playbooks, active EDR response, SIGMA/YARA threat hunting, DNS sinkholing, Zero Trust access verification, vulnerability management, true PE binary sandboxing, Active Directory ITDR, identity security, and multi-cloud posture auditing.

> **All telemetry is 100% live.** No mock data, no pre-seeded demo incidents, no synthetic injections. Every panel sources from real OS APIs, live Windows Event Logs, active network sockets, running process trees, real DNS resolution, and genuine binary file parsing.

---

## Security Modules (18 Engines)

### 1. Command Center
- **Master Threat Feed** (`LurkSOC`): Cross-engine incident correlation across all 18 engines with 1-click containment actions.

### 2. Automation & Response
- **Playbooks & Cases** (`LurkSOAR`): Automated remediation playbooks (IP firewall block, host isolation, file quarantine) and dynamic incident case management.
- **Endpoint Response** (`LurkEDR`): Active response — process termination, Windows Firewall IP blocker, file quarantine, and memory string carver.

### 3. Detection & Threat Hunting
- **Threat Hunting** (`LurkHunt`): SIGMA detection rule evaluator (8 rules) and YARA-style string pattern scanner against live running process command lines.
- **Vulnerabilities** (`LurkVuln`): Windows KB Hotfix patch compliance auditor via `Get-HotFix`, CVSS risk scoring against real patch baseline.
- **Malware Sandbox** (`LurkSand`): True PE binary analyzer — reads real files from disk, calculates Shannon entropy, parses DOS/COFF/Optional headers and all PE sections using `struct`, and inspects import tables for process injection APIs.
- **Threat Intelligence** (`LurkIntel`): Live Feodo CTI botnet IP feed, CISA Known Exploited Vulnerabilities (KEV) catalog, MITRE ATT&CK technique heatmap, and live IOC cross-reference against active `netstat` connections.
- **Windows Event Logs** (`LurkSIEM`): Real-time Windows Security/System/Application log parser (`Get-WinEvent`), logon audit stream (4624/4625), and brute-force correlation rules.
- **Process Trees** (`LurkTrace`): Live `Win32_Process` parent-child execution tree with full command line inspection and `%TEMP%` path anomaly detection.

### 4. Network & Boundary Defense
- **DNS Sinkhole** (`LurkDNS`): Live domain resolution via `socket.gethostbyname`, C2 domain blocklist sinkholing to `127.0.0.1`, and query inspection log.
- **Web Firewall** (`LurkShield`): OWASP Top 10 HTTP inspection (SQLi, XSS, RCE, LFI, Command Injection, SSRF, Sensitive File Access) with per-IP token-bucket rate limiting.
- **Sockets & Ports** (`LurkSentinel`): Live `netstat -ano` socket enumeration with PID process resolution and 150-thread TCP port scanner.
- **Packet Capture** (`LurkPacket`): Live DNS, HTTP header, and TLS SNI decode with Wireshark-compatible `.pcap` export.
- **Deception Honeypots** (`LurkDecoy`): Active low-interaction TCP honeypot listeners (SSH:2222, FTP:2121, HTTP:8888, RDP:33890) recording real probe connections.

### 5. Identity & Cloud
- **Zero Trust** (`LurkZero`): ZTNA mTLS certificate verification, JWT posture scoring, and device access decision engine.
- **Identity ITDR** (`LurkGuard`): Live local account auditing via `net localgroup Administrators`, `net user Guest`, `Win32_UserAccount` (non-expiring password check), and UAC registry (`EnableLUA`) posture.
- **Secrets & Passwords** (`LurkIdentity`): 10-pattern secret scanner (API keys, JWT, SSH keys, AWS credentials), HaveIBeenPwned k-Anonymity SHA-1 breach checker, and password policy compliance.
- **Cloud Security** (`LurkCloud`): AWS S3/EC2/IAM (via AWS CLI) and Azure NSG/Storage (via Azure CLI) posture auditor with graceful fallback when CLIs are not configured.
- **OS Hardening** (`LurkAudit`): Windows Firewall profile state, UAC, SMBv1, and hidden share compliance auditor.

---

## Quick Start

### Requirements
- Python 3.8+
- Windows 10 / 11 / Windows Server

### Launch
```bash
python lurksec.py
```
Or double-click **`start_suite.bat`**.  
Open **`http://localhost:8000`** in your browser.

### CLI Audit Mode
```bash
python lurksec.py audit
```
Runs a full cross-engine audit and prints all HIGH/MEDIUM severity incidents to stdout.

### Clone with Submodules
```bash
git clone --recursive https://github.com/LurkSec/LurkSecSuite.git
```

---

## Architecture

The server uses a dual-stack `AF_INET6` socket with `IPV6_V6ONLY = 0` to accept both IPv4 and IPv6 connections on Windows (fixes `ERR_EMPTY_RESPONSE` caused by Windows resolving `localhost` to `::1`).

All engines are initialized at server startup and hold live state in memory. The `/api/summary` endpoint is cached for 5 seconds to prevent redundant OS calls under rapid auto-refresh.

---

## Repository Structure

```
LurkSecSuite/
├── lurksec_core/                   # Core engine packages
│   ├── dns_engine/                 # LurkDNS: live socket DNS + C2 sinkhole
│   ├── zero_engine/                # LurkZero: ZTNA posture engine
│   ├── vuln_engine/                # LurkVuln: Get-HotFix patch compliance
│   ├── sand_engine/                # LurkSand: real PE struct parser + entropy
│   ├── guard_engine/               # LurkGuard: live AD/local account ITDR
│   ├── edr_engine/                 # LurkEDR: process kill, firewall block, quarantine
│   ├── shield_engine/              # LurkShield: WAF + rate limiter
│   ├── intel_engine/               # LurkIntel: CTI feed + MITRE mapper
│   ├── identity_engine/            # LurkIdentity: secret scanner + HIBP
│   ├── cloud_engine/               # LurkCloud: AWS + Azure posture
│   ├── soar_engine/                # LurkSOAR: playbooks + case manager
│   ├── hunt_engine/                # LurkHunt: SIGMA + YARA live scanner
│   ├── sys_info.py                 # LurkSentinel: netstat + port scanner
│   ├── log_parser.py               # LurkSIEM: Get-WinEvent log parser
│   ├── threat_correlator.py        # LurkSIEM: correlation rules engine
│   ├── honeypot_listeners.py       # LurkDecoy: TCP honeypot listener manager
│   ├── packet_inspector.py         # LurkPacket: PCAP decoder + pcap export
│   ├── process_auditor.py          # LurkTrace: Win32_Process tree inspector
│   ├── system_auditor.py           # LurkAudit: OS hardening scanner
│   └── soc_aggregator.py           # LurkSOC: master incident feed correlator
├── web_console/
│   ├── index.html                  # Master web console (single-page)
│   ├── css/style.css               # Dark theme
│   └── js/app.js                   # JS controller + PCAP exporter
├── lurksec.py                      # Entry point + HTTP API server (port 8000)
├── start_suite.bat                 # 1-click launch
├── stop_suite.bat                  # 1-click shutdown
└── README.md
```

---

## Author & License
Created by **LurkSec**. Distributed under the MIT License.
