"""
Network log middleware parser.

Classifies IIS, Apache, Zeek, and firewall log entries into threat categories.
Provides structured findings with MITRE technique mappings.
"""
from __future__ import annotations
import re

# Web shell extensions that should never receive POST requests from external IPs
_WEB_SHELL_EXTS = {".asp", ".aspx", ".php", ".jsp", ".jspx", ".cfm", ".shtml", ".cgi", ".pl"}

# Scanner user agents
_SCANNER_UA_RE = re.compile(
    r"(nikto|sqlmap|nessus|masscan|nmap|gobuster|dirbuster|wfuzz"
    r"|hydra|zgrab|shodan|censys|burpsuite|acunetix|owasp|nuclei"
    r"|w3af|skipfish|vega|arachni|openvas)",
    re.IGNORECASE,
)

# SQL injection patterns in URIs
_SQLI_RE = re.compile(
    r"(union\s+select|or\s+1=1|'\s*or\s*'|xp_cmdshell|exec\s*\("
    r"|INFORMATION_SCHEMA|waitfor\s+delay|sleep\(\d|benchmark\("
    r"|char\(\d+\)\+char|0x[0-9a-f]{4,})",
    re.IGNORECASE,
)

# Directory traversal patterns
_TRAVERSAL_RE = re.compile(
    r"(\.\./|\.\.%2[fF]|%2[eE]%2[eE]|%252[eE]%252[fF]|\.\.\\)",
    re.IGNORECASE,
)

# Log4Shell and other critical CVE patterns
_CRITICAL_VULN_RE = re.compile(
    r"(\$\{jndi:|<\?php|\{\{.*\}\}|{7-fuzz}|\.\./proc/self|/etc/passwd"
    r"|\\x[0-9a-f]{2}.*exec|cmd\.exe|/bin/sh|/bin/bash|nc\s+-e)",
    re.IGNORECASE,
)

# Private IP ranges
_PRIVATE_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)"
)

# DNS exfiltration: excessively long subdomain
_DNS_EXFIL_MIN_LEN = 40


def classify_web_log_entry(entry: dict) -> list[str]:
    """
    Classify a single web log entry (IIS/Apache/Nginx format dict).

    Expected fields: method, uri, status, client_ip, user_agent, dst_ip (optional).
    Returns list of threat flags.
    """
    flags: list[str] = []
    method = str(entry.get("method", "")).upper()
    uri = str(entry.get("uri", entry.get("cs-uri-stem", "")))
    status = str(entry.get("status", entry.get("sc-status", "")))
    ua = str(entry.get("user_agent", entry.get("cs(User-Agent)", "")))
    client_ip = str(entry.get("client_ip", entry.get("c-ip", entry.get("ip", ""))))

    # Web shell: POST to script extension with success
    if method == "POST" and status == "200":
        ext = ("." + uri.rsplit(".", 1)[-1].lower()) if "." in uri else ""
        if ext in _WEB_SHELL_EXTS:
            flags.append("WEB_SHELL_ACCESS")

    if _SCANNER_UA_RE.search(ua):
        flags.append("SCANNER_USER_AGENT")

    if _SQLI_RE.search(uri):
        flags.append("SQL_INJECTION_ATTEMPT")

    if _TRAVERSAL_RE.search(uri):
        flags.append("DIRECTORY_TRAVERSAL")

    if _CRITICAL_VULN_RE.search(uri):
        flags.append("CRITICAL_EXPLOIT_ATTEMPT")

    # External-to-internal large POST
    if method == "POST" and client_ip and not _PRIVATE_IP_RE.match(client_ip):
        size = int(entry.get("bytes_received", entry.get("cs-bytes", 0)) or 0)
        if size > 500_000:
            flags.append("LARGE_INBOUND_POST")

    return flags


def flags_to_mitre(flags: list[str]) -> str:
    """Map web log threat flags to MITRE ATT&CK techniques."""
    mapping = {
        "WEB_SHELL_ACCESS": "T1505.003 — Server Software Component: Web Shell",
        "SCANNER_USER_AGENT": "T1595.001 — Active Scanning: Scanning IP Blocks",
        "SQL_INJECTION_ATTEMPT": "T1190 — Exploit Public-Facing Application",
        "DIRECTORY_TRAVERSAL": "T1083 — File and Directory Discovery",
        "CRITICAL_EXPLOIT_ATTEMPT": "T1190 — Exploit Public-Facing Application",
        "LARGE_INBOUND_POST": "T1190 — Exploit Public-Facing Application",
    }
    return "; ".join(dict.fromkeys(mapping[f] for f in flags if f in mapping))


def classify_dns_query(query: str, answer: str = "") -> list[str]:
    """
    Classify a DNS query for exfiltration and C2 indicators.
    """
    flags: list[str] = []
    parts = query.rstrip(".").split(".")
    # Excessively long subdomain component = DNS tunneling
    if any(len(p) > _DNS_EXFIL_MIN_LEN for p in parts):
        flags.append("DNS_TUNNELING")
    # High number of subdomain labels
    if len(parts) > 6:
        flags.append("DNS_EXFIL_SUBDOMAIN")
    # Base64-looking subdomain
    if any(re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", p) for p in parts):
        flags.append("BASE64_IN_SUBDOMAIN")
    return flags


def detect_port_scan(entries: list[dict], threshold: int = 10) -> list[dict]:
    """
    Detect port scan behaviour from a list of connection/firewall log entries.

    Returns list of source IPs with their probed port counts.
    """
    src_ports: dict[str, set] = {}
    for e in entries:
        src = str(e.get("src", e.get("client_ip", e.get("ip", ""))))
        dst_port = str(e.get("dst_port", e.get("dpt", "")))
        if src and dst_port:
            src_ports.setdefault(src, set()).add(dst_port)

    scanners: list[dict] = []
    for src, ports in src_ports.items():
        if len(ports) >= threshold:
            scanners.append({
                "source_ip": src,
                "unique_ports_probed": len(ports),
                "sample_ports": sorted(ports)[:20],
                "mitre": "T1046 — Network Service Discovery",
                "threat_flags": ["PORT_SCAN"],
            })
    return sorted(scanners, key=lambda x: x["unique_ports_probed"], reverse=True)


def classify_network_log_entries(entries: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Classify a batch of web log entries.

    Returns (all_entries_with_flags, suspicious_entries).
    """
    suspicious: list[dict] = []
    for entry in entries:
        flags = classify_web_log_entry(entry)
        if flags:
            entry["threat_flags"] = flags
            entry["mitre"] = flags_to_mitre(flags)
            suspicious.append(entry)
    return entries, suspicious
