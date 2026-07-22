# Master LurkSec Security Operations Command Suite

**LurkSec Suite** (by **Lurk** / **LurkSec**) is an enterprise-grade defensive security operations center (SOC) command suite unifying **18 defensive security engines** into **one unified web console**.

Built entirely in pure Python (standard library) with zero external dependencies, it provides real-time telemetry correlation, automated IR playbooks, active EDR response, SIGMA/YARA threat hunting, DNS sinkholing, Zero Trust access verification, vulnerability management, PE malware sandboxing, Active Directory ITDR, identity security, and multi-cloud posture auditing.

---

## Master Security Domains & Modules (18 Integrated Engines)

### 1. COMMAND CENTER
- **Master Threat Feed** (`LurkSOC`): Real-time incident correlation across all 17 underlying security engines with 1-click remediation.

### 2. AUTOMATION & RESPONSE
- **Playbooks & Cases** (`LurkSOAR`): Automated remediation playbooks (IP firewall blocks, host isolation, file quarantine) and incident case management.
- **Endpoint Response** (`LurkEDR`): Active response actions (Process Killer, Windows Firewall IP Blocker, File Quarantiner, Memory Carver).

### 3. DETECTION & THREAT HUNTING
- **Threat Hunting** (`LurkHunt`): SIGMA detection rule parser (8 rules) & YARA-style memory string pattern scanner.
- **Vulnerabilities** (`LurkVuln`): Installed software CVE auditor, Windows KB Patch compliance checker, and CVSS risk scoring.
- **Malware Sandbox** (`LurkSand`): PE binary header inspector, entropy calculation (packer detection), suspicious DLL API import auditor.
- **Threat Intelligence** (`LurkIntel`): Feodo CTI botnet feed parser, CISA Known Exploited Vulnerabilities (KEV) catalog, MITRE ATT&CK heatmap, and IOC matcher.
- **Windows Event Logs** (`LurkSIEM`): Windows Event Log parser (Security, System, App), logon audit stream (4624/4625), and brute-force rules.
- **Process Trees** (`LurkTrace`): `Win32_Process` parent-child execution tree, command line inspection, and `%TEMP%` path anomaly rules.

### 4. NETWORK & BOUNDARY DEFENSE
- **DNS Sinkhole** (`LurkDNS`): Malicious domain C2 sinkhole filter (blocks C2 domains to 127.0.0.1) and DNS-over-HTTPS (DoH) inspector.
- **Web Firewall** (`LurkShield`): OWASP Top 10 threat inspection (SQLi, XSS, RCE, LFI, Command Injection) and token-bucket per-IP rate limiter.
- **Sockets & Ports** (`LurkSentinel`): Active listening sockets, PID process resolver, GeoIP flags (`Cloudflare`, `Microsoft Azure`), and 150-thread TCP port scanner.
- **Packet Capture** (`LurkPacket`): DNS domain queries, HTTP headers, TLS SNI decoders, and Wireshark `.pcap` export generator.
- **Deception Honeypots** (`LurkDecoy`): Active low-interaction honeypot listeners (SSH:2222, FTP:2121, HTTP:8888, RDP:33890).

### 5. IDENTITY & CLOUD HYGIENE
- **Zero Trust** (`LurkZero`): Zero Trust Network Access (ZTNA) mTLS client certificate verification, JWT session tokens, and device posture scores.
- **Identity ITDR** (`LurkGuard`): Active Directory & LDAP security baseline auditor, Kerberoasting risk checker, AS-REP Roastable account auditor, and DCSync rights checker.
- **Secrets & Passwords** (`LurkIdentity`): 10-pattern secret scanner (API keys, JWT, SSH keys), HaveIBeenPwned k-Anonymity hash-range breach checker, and password policy compliance.
- **Cloud Security** (`LurkCloud`): AWS S3/EC2/IAM & Azure NSG security posture auditor with local baseline fallback.
- **OS Hardening** (`LurkAudit`): Windows Firewall profiles, UAC, SMBv1, and hidden share compliance auditor.

---

## Quick Start

### Requirements
- Python 3.8+
- Windows 10 / 11 / Windows Server

### 1. Launch Master Command Suite
```bash
python lurksec.py serve --port 8000
```
Or double-click **`start_suite.bat`**. Open **`http://localhost:8000`** in your browser.

### 2. Run Master Security Audit across all 18 Engines (CLI)
```bash
python lurksec.py audit
```

### 3. Clone Suite with Submodules
To clone the suite alongside all 17 standalone engine submodules:
```bash
git clone --recursive https://github.com/LurkSec/LurkSecSuite.git
```

---

## SOC Telemetry & Detection Validation Controls

The Master Web Console includes a professional **Detection Validation Panel** at the top of the feed:
- **`Inject SIGMA Ransomware Event`**: Injects process/shadow-copy deletion telemetry -> triggers `LurkHunt` hit + spawns `LurkSOAR` case.
- **`Test WAF OWASP SQLi Payload`**: Injects SQLi request -> logs into `LurkShield` WAF block stream.
- **`Generate Deception Probe Telemetry`**: Injects probe telemetry into `LurkDecoy` SSH listener.

---

## Repository & Directory Structure

```
LurkSecSuite/
├── lurkcloud-security-engine/      # [Submodule] LurkCloud Standalone Engine
├── lurkdecoy-security-engine/      # [Submodule] LurkDecoy Standalone Engine
├── lurkdns-security-engine/        # [Submodule] LurkDNS Standalone Engine
├── lurkedr-security-engine/        # [Submodule] LurkEDR Standalone Engine
├── lurkguard-security-engine/      # [Submodule] LurkGuard Standalone Engine
├── lurkhunt-security-engine/       # [Submodule] LurkHunt Standalone Engine
├── lurkidentity-security-engine/   # [Submodule] LurkIdentity Standalone Engine
├── lurkintel-security-engine/      # [Submodule] LurkIntel Standalone Engine
├── lurkpacket-security-engine/     # [Submodule] LurkPacket Standalone Engine
├── lurksand-security-engine/       # [Submodule] LurkSand Standalone Engine
├── lurkshield-security-engine/     # [Submodule] LurkShield Standalone Engine
├── lurksiem-security-engine/       # [Submodule] LurkSIEM Standalone Engine
├── lurksoar-security-engine/       # [Submodule] LurkSOAR Standalone Engine
├── lurktrace-security-engine/      # [Submodule] LurkTrace Standalone Engine
├── lurkvuln-security-engine/       # [Submodule] LurkVuln Standalone Engine
├── lurkzero-security-engine/       # [Submodule] LurkZero Standalone Engine
├── netsentinel-security-suite/     # [Submodule] NetSentinel Standalone Engine
├── lurksec_core/                   # Core Python Sub-Packages (18 Security Engines)
│   ├── dns_engine/                 # LurkDNS Sinkhole engine
│   ├── zero_engine/                # LurkZero ZTNA engine
│   ├── vuln_engine/                # LurkVuln patch auditor engine
│   ├── sand_engine/                # LurkSand PE sandbox engine
│   ├── guard_engine/               # LurkGuard AD ITDR auditor engine
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
│   ├── cloud_engine/               # LurkCloud multi-cloud posture inspector
│   ├── soar_engine/                # LurkSOAR playbooks & case manager
│   └── hunt_engine/                # LurkHunt SIGMA & YARA engine
├── web_console/                    # Master Operations Console
│   ├── index.html                  # Categorized Master Web Console
│   ├── css/
│   │   └── style.css               # Dark Charcoal theme with custom scrollbars
│   └── js/
│       └── app.js                  # Master JS controller & Wireshark PCAP exporter
├── lurksec.py                      # Master Entry Point & HTTP API Server (Port 8000)
├── start_suite.bat                 # Master 1-Click Launch Script
├── stop_suite.bat                  # Master 1-Click Shutdown Script
├── .gitmodules                     # Submodule Mapping for all 17 Standalone Repositories
├── README.md                       # Master Suite Documentation
└── LICENSE                         # MIT License
```

---

## Author & License
Created by **Lurk** (**LurkSec**). Distributed under the MIT License.
