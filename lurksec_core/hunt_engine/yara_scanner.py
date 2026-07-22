import re
from typing import Dict, List, Any

class YaraScanner:
    """
    LurkHunt YARA-style Binary & Memory Signature Pattern Matching Engine.
    Scans process memory buffers, disk artifacts, and payload strings for malicious signatures.
    """

    SIGNATURES = [
        {
            "id": "YARA-001",
            "name": "Cobalt_Strike_Reflective_Loader",
            "type": "HEX_AND_STRING",
            "severity": "CRITICAL",
            "pattern": r"(?i)(ReflectiveLoader|BeaconGetSpawn|4d5a900003000000)",
            "description": "Matches Cobalt Strike reflective loader export and header signatures."
        },
        {
            "id": "YARA-002",
            "name": "Metasploit_Reverse_TCP_Shellcode",
            "type": "SHELLCODE",
            "severity": "HIGH",
            "pattern": r"(?i)(eb0b5b31c0|ws2_32\.dll|connectex)",
            "description": "Matches shellcode sequences for Windows x86/x64 reverse TCP payloads."
        },
        {
            "id": "YARA-003",
            "name": "Generic_Ransomware_Note_Artifact",
            "type": "STRING",
            "severity": "CRITICAL",
            "pattern": r"(?i)(README_FOR_DECRYPT|YOUR_FILES_ARE_ENCRYPTED|\.lockbit|\.wcry)",
            "description": "Matches ransom note artifacts and extension markers associated with LockBit/WannaCry."
        },
        {
            "id": "YARA-004",
            "name": "Mimikatz_WDigest_Memory_Pattern",
            "type": "STRING",
            "severity": "HIGH",
            "pattern": r"(?i)(wdigest\.dll|lsass\.exe.*sekurlsa|kerberos\.dll)",
            "description": "Matches LSA security module references used during credential extraction."
        },
        {
            "id": "YARA-005",
            "name": "Reverse_Shell_PowerShell_Launcher",
            "type": "STRING",
            "severity": "MEDIUM",
            "pattern": r"(?i)(powershell.*-nop.*-w\s+hidden.*Net\.Sockets\.TCPClient)",
            "description": "Matches stealthy PowerShell TCP socket launcher syntax."
        }
    ]

    def get_signatures(self) -> List[Dict[str, Any]]:
        return self.SIGNATURES

    def scan_string(self, text: str, source_name: str = "Memory Buffer") -> List[Dict[str, Any]]:
        hits = []
        for sig in self.SIGNATURES:
            if re.search(sig["pattern"], text):
                hits.append({
                    "sig_id": sig["id"],
                    "sig_name": sig["name"],
                    "severity": sig["severity"],
                    "source": source_name,
                    "matched_pattern": sig["pattern"],
                    "description": sig["description"]
                })
        return hits
