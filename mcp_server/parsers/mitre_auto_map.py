"""
Rule-based MITRE ATT&CK technique auto-mapper.

Maps specific forensic findings to ATT&CK technique IDs without requiring
the RAG pipeline to be seeded. This ensures every tool result has a
MITRE mapping even on first run with an empty knowledge base.
"""
from __future__ import annotations

# Ordered list of (keyword_pattern, technique_id, technique_name)
# Checked in order; first match wins for primary technique.
_PROCESS_RULES: list[tuple[str, str, str]] = [
    ("masquerade", "T1036.005", "Masquerading: Match Legitimate Name or Location"),
    ("wrong parent", "T1055", "Process Injection"),
    ("unexpected parent", "T1055", "Process Injection"),
    ("zero thread", "T1055.012", "Process Hollowing"),
    ("too many instance", "T1055", "Process Injection"),
    ("not in.*baseline", "T1036", "Masquerading"),
    ("hollow", "T1055.012", "Process Hollowing"),
]

_INJECTION_RULES: list[tuple[str, str, str]] = [
    ("reflective_dll", "T1055.001", "Dynamic-link Library Injection"),
    ("process_hollowing", "T1055.012", "Process Hollowing"),
    ("shellcode", "T1055", "Process Injection"),
    ("suspicious_exec_region", "T1055", "Process Injection"),
]

_NETWORK_RULES: list[tuple[str, str, str]] = [
    ("rdp", "T1021.001", "Remote Services: Remote Desktop Protocol"),
    ("3389", "T1021.001", "Remote Services: Remote Desktop Protocol"),
    ("port.*4444", "T1571", "Non-Standard Port"),
    ("port.*1337", "T1571", "Non-Standard Port"),
    ("9050", "T1090.003", "Multi-hop Proxy (Tor)"),
    ("9001", "T1090.003", "Multi-hop Proxy (Tor)"),
    ("established.*external", "T1041", "Exfiltration Over C2 Channel"),
]

_CMDLINE_RULES: list[tuple[str, str, str]] = [
    ("base64", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ("encodedcommand", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ("-enc ", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ("bypass", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ("invoke-expression", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ("downloadstring", "T1105", "Ingress Tool Transfer"),
    ("certutil", "T1140", "Deobfuscate/Decode Files or Information"),
    ("bitsadmin", "T1197", "BITS Jobs"),
    ("mshta", "T1218.005", "Signed Binary Proxy Execution: Mshta"),
    ("regsvr32", "T1218.010", "Signed Binary Proxy Execution: Regsvr32"),
    ("rundll32", "T1218.011", "Signed Binary Proxy Execution: Rundll32"),
    ("net user", "T1136", "Create Account"),
    ("net localgroup", "T1069", "Permission Groups Discovery"),
    ("mimikatz", "T1003.001", "OS Credential Dumping: LSASS Memory"),
    ("sekurlsa", "T1003.001", "OS Credential Dumping: LSASS Memory"),
    ("procdump", "T1003.001", "OS Credential Dumping: LSASS Memory"),
]

_SERVICE_RULES: list[tuple[str, str, str]] = [
    ("service.*install", "T1543.003", "Create or Modify System Process: Windows Service"),
    ("suspicious.*path", "T1543.003", "Create or Modify System Process: Windows Service"),
    ("appdata", "T1543.003", "Create or Modify System Process: Windows Service"),
    ("temp", "T1036.005", "Masquerading: Match Legitimate Name or Location"),
]

_REGISTRY_RULES: list[tuple[str, str, str]] = [
    ("run key", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys"),
    ("run\\b", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys"),
    ("services", "T1543.003", "Create or Modify System Process: Windows Service"),
    ("userinit", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys"),
    ("shell", "T1546.002", "Event Triggered Execution: Screensaver"),
]

_EVENT_RULES: list[tuple[str, str, str]] = [
    ("7045", "T1543.003", "Create or Modify System Process: Windows Service"),
    ("4697", "T1543.003", "Create or Modify System Process: Windows Service"),
    ("4698", "T1053.005", "Scheduled Task/Job: Scheduled Task"),
    ("106", "T1053.005", "Scheduled Task/Job: Scheduled Task"),
    ("4104", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ("4103", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ("5861", "T1546.003", "Event Triggered Execution: Windows Management Instrumentation"),
    ("5860", "T1546.003", "Event Triggered Execution: Windows Management Instrumentation"),
    ("4625", "T1110", "Brute Force"),
    ("1149", "T1021.001", "Remote Services: Remote Desktop Protocol"),
    ("4778", "T1021.001", "Remote Services: Remote Desktop Protocol"),
    ("4672", "T1078", "Valid Accounts"),
]

_HIDDEN_PROCESS_RULES: list[tuple[str, str, str]] = [
    ("hidden", "T1014", "Rootkit"),
    ("dkom", "T1014", "Rootkit"),
    ("not in pslist", "T1014", "Rootkit"),
]

_TIMESTAMP_RULES: list[tuple[str, str, str]] = [
    ("timestamp_anomaly", "T1070.006", "Indicator Removal: Timestomp"),
    ("modified.*before.*created", "T1070.006", "Indicator Removal: Timestomp"),
]

_CREDENTIAL_RULES: list[tuple[str, str, str]] = [
    ("lsass", "T1003.001", "OS Credential Dumping: LSASS Memory"),
    ("ntds", "T1003.003", "OS Credential Dumping: NTDS"),
    ("sam ", "T1003.002", "OS Credential Dumping: Security Account Manager"),
]

_EXFIL_RULES: list[tuple[str, str, str]] = [
    ("onedrive", "T1567.002", "Exfiltration to Cloud Storage"),
    ("dropbox", "T1567.002", "Exfiltration to Cloud Storage"),
    ("google drive", "T1567.002", "Exfiltration to Cloud Storage"),
    ("icloud", "T1567.002", "Exfiltration to Cloud Storage"),
    ("sharepoint", "T1567.002", "Exfiltration to Cloud Storage"),
    ("usb", "T1052.001", "Exfiltration over Physical Medium: USB"),
    ("cloud_exfil", "T1567.002", "Exfiltration to Cloud Storage"),
    ("large_volume_transfer", "T1048", "Exfiltration Over Alternative Protocol"),
    ("dns_tunneling", "T1071.004", "Application Layer Protocol: DNS"),
    ("dns_exfil", "T1071.004", "Application Layer Protocol: DNS"),
]

_LATERAL_RULES: list[tuple[str, str, str]] = [
    ("psexec", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    ("admin\\$", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    ("wmic", "T1047", "Windows Management Instrumentation"),
    ("winrm", "T1021.006", "Remote Services: Windows Remote Management"),
    ("rdp bitmap", "T1021.001", "Remote Services: Remote Desktop Protocol"),
]

# Browser / web rules
_BROWSER_RULES: list[tuple[str, str, str]] = [
    ("cloud_exfil_domain", "T1567.002", "Exfiltration to Cloud Storage"),
    ("c2_pattern", "T1071.001", "Application Layer Protocol: Web Protocols"),
    ("suspicious_download", "T1105", "Ingress Tool Transfer"),
    ("url_shortener", "T1036", "Masquerading"),
    ("executable_downloaded", "T1105", "Ingress Tool Transfer"),
    ("malicious extension", "T1176", "Browser Extensions"),
]

# Document / file rules
_DOCUMENT_RULES: list[tuple[str, str, str]] = [
    ("web_shell", "T1505.003", "Server Software Component: Web Shell"),
    ("vba macro", "T1059.005", "Command and Scripting Interpreter: VBA"),
    ("autoopen", "T1059.005", "Command and Scripting Interpreter: VBA"),
    ("dde", "T1559.002", "Dynamic Data Exchange"),
    ("pdf.*javascript", "T1059.007", "Command and Scripting Interpreter: JavaScript"),
    ("openaction", "T1566.001", "Phishing: Spearphishing Attachment"),
    ("equation editor", "T1203", "Exploitation for Client Execution"),
    ("zip bomb", "T1027", "Obfuscated Files or Information"),
    ("nested zip", "T1027", "Obfuscated Files or Information"),
    ("path_traversal", "T1083", "File and Directory Discovery"),
]

# Anti-forensics rules
_AF_RULES: list[tuple[str, str, str]] = [
    ("timestomp", "T1070.006", "Indicator Removal: Timestomp"),
    ("si.*fn.*delta", "T1070.006", "Indicator Removal: Timestomp"),
    ("log.*clear", "T1070.001", "Indicator Removal: Clear Windows Event Logs"),
    ("sdelete", "T1070.004", "Indicator Removal: File Deletion"),
    ("secure.delet", "T1070.004", "Indicator Removal: File Deletion"),
    ("bleachbit", "T1070.004", "Indicator Removal: File Deletion"),
    ("vss.*delete", "T1490", "Inhibit System Recovery"),
    ("ads.*stream", "T1564.004", "Hide Artifacts: NTFS File Attributes"),
    ("history.*wipe", "T1070.003", "Indicator Removal: Clear Command History"),
]

# Linux forensics rules
_LINUX_RULES: list[tuple[str, str, str]] = [
    ("ld_preload", "T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking"),
    ("hidden.*module", "T1014", "Rootkit"),
    ("syscall.*hook", "T1014", "Rootkit"),
    ("crontab", "T1053.003", "Scheduled Task/Job: Cron"),
    ("bash.*history", "T1070.003", "Indicator Removal: Clear Command History"),
    ("xmrig|cryptominer|minerd", "T1496", "Resource Hijacking"),
    ("reverse shell", "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    ("/dev/tcp", "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    ("useradd.*sudo", "T1136.001", "Create Account: Local Account"),
]

# Network log rules
_NETLOG_RULES: list[tuple[str, str, str]] = [
    ("web_shell_access", "T1505.003", "Server Software Component: Web Shell"),
    ("sql_injection", "T1190", "Exploit Public-Facing Application"),
    ("directory_traversal", "T1083", "File and Directory Discovery"),
    ("scanner.*agent", "T1595.001", "Active Scanning"),
    ("port_scan", "T1046", "Network Service Discovery"),
    ("zeek.*beacon", "T1071.001", "Application Layer Protocol: Web Protocols"),
    ("rdp.*cache", "T1021.001", "Remote Services: Remote Desktop Protocol"),
    ("netflow.*exfil", "T1041", "Exfiltration Over C2 Channel"),
]

# Disk / file carving rules
_DISK_RULES: list[tuple[str, str, str]] = [
    ("slack.*space.*ioc", "T1027", "Obfuscated Files or Information"),
    ("carved.*executable", "T1105", "Ingress Tool Transfer"),
    ("hash.*mismatch", "T1565", "Data Manipulation"),
    ("integrity.*broken", "T1565", "Data Manipulation"),
    ("masquerade_suspected", "T1036.007", "Masquerading: Double File Extension"),
]

# Threat intel rules
_THREAT_INTEL_RULES: list[tuple[str, str, str]] = [
    ("malicious.*hash", "T1036", "Masquerading"),
    ("high.*detection.*ratio", "T1027", "Obfuscated Files or Information"),
    ("fuzzy.*similar", "T1027", "Obfuscated Files or Information"),
    ("newly.*registered.*domain", "T1583.001", "Acquire Infrastructure: Domains"),
]

# All rule groups
_ALL_RULE_GROUPS = (
    _PROCESS_RULES + _INJECTION_RULES + _NETWORK_RULES +
    _CMDLINE_RULES + _SERVICE_RULES + _REGISTRY_RULES +
    _EVENT_RULES + _HIDDEN_PROCESS_RULES + _TIMESTAMP_RULES +
    _CREDENTIAL_RULES + _EXFIL_RULES + _LATERAL_RULES +
    _BROWSER_RULES + _DOCUMENT_RULES + _AF_RULES +
    _LINUX_RULES + _NETLOG_RULES + _DISK_RULES + _THREAT_INTEL_RULES
)


def map_finding_to_techniques(text: str) -> list[dict]:
    """
    Map a text finding to MITRE ATT&CK techniques using rule-based matching.

    Args:
        text: Any string describing a forensic finding (anomaly, cmdline, event, etc.)

    Returns:
        List of {'technique_id': ..., 'technique_name': ..., 'url': ...} dicts.
        Empty list if no rules matched.
    """
    import re
    text_lower = text.lower()
    seen: dict[str, str] = {}  # tid → name; dedup while preserving first match

    for pattern, tid, name in _ALL_RULE_GROUPS:
        try:
            if re.search(pattern, text_lower):
                seen.setdefault(tid, name)
        except re.error:
            if pattern in text_lower:
                seen.setdefault(tid, name)

    return [
        {
            "technique_id": tid,
            "technique_name": name,
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
        }
        for tid, name in seen.items()
    ]


def map_process_anomalies(anomalies: list[str]) -> list[dict]:
    """Convenience wrapper: map a list of process anomaly strings."""
    combined = " ".join(anomalies)
    return map_finding_to_techniques(combined)


def map_injection(injection_type: str, protection: str) -> list[dict]:
    """Map a malfind injection type to ATT&CK."""
    return map_finding_to_techniques(f"{injection_type} {protection}")


def map_network_connection(ioc_flags: list[str]) -> list[dict]:
    """Map network IOC flags to ATT&CK."""
    return map_finding_to_techniques(" ".join(ioc_flags))


def map_cmdline(cmdline: str) -> list[dict]:
    """Map a suspicious command line to ATT&CK."""
    return map_finding_to_techniques(cmdline)


def map_event_id(event_id: str | int) -> list[dict]:
    """Map a Windows Event ID to ATT&CK."""
    return map_finding_to_techniques(str(event_id))
