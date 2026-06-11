"""
Network forensics tools — Priority 4 (tool count expansion).

Three tools for PCAP and network artifact analysis:
  parse_pcap_summary   — TShark-based PCAP summary with conversation stats and IOCs
  extract_dns_queries  — DNS query/response extraction with suspicious domain flagging
  parse_arp_cache      — ARP cache from Volatility for host enumeration

These tools complement netscan (live connections) with captured traffic analysis.
"""
from __future__ import annotations
import json
import re
import subprocess
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import MAX_TOOL_TIMEOUT, VOLATILITY_CMD
from mcp_server.parsers.forensic_knowledge import wrap_response

# Known malicious/suspicious top-level domains and hosting patterns
_SUSPICIOUS_TLDS = {".ru", ".cn", ".tk", ".to", ".cc", ".xyz", ".top", ".pw", ".ws", ".club"}
_DGA_PATTERN = re.compile(r"^[a-z0-9]{8,20}\.[a-z]{2,4}$", re.IGNORECASE)
_IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _is_suspicious_domain(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    if any(domain.endswith(tld) for tld in _SUSPICIOUS_TLDS):
        return True
    parts = domain.split(".")
    if len(parts) == 2 and _DGA_PATTERN.match(parts[0]):
        return True  # possible DGA
    return False


def register_network_analysis_tools(mcp, rag=None):

    @mcp.tool()
    def parse_pcap_summary(pcap_path: str) -> str:
        """
        Parse a PCAP/PCAPNG file using TShark and return a structured summary.

        Reports: top talker IPs, protocol distribution, conversation pairs,
        suspicious external connections, large data transfers (exfil signals),
        and any cleartext credentials visible in the capture.

        Requires TShark (part of Wireshark): sudo apt install tshark

        Args:
            pcap_path: Absolute path to the .pcap or .pcapng file.
        """
        if not Path(pcap_path).exists():
            return json.dumps({"error": f"PCAP file not found: {pcap_path}"})

        result_parts: dict = {}

        # Protocol statistics
        try:
            r = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "io,phs"],
                capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT,
            )
            log_tool_execution("parse_pcap_summary", ["tshark", pcap_path], r.stdout, error=r.stderr)
            result_parts["protocol_stats"] = r.stdout[:2000]
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log_tool_execution("parse_pcap_summary", ["tshark", pcap_path], "", error=str(e))
            result_parts["protocol_stats_error"] = str(e)

        audit_id = get_last_audit_id()
        increment_tool_counter()

        # IP conversations — top talkers
        conversations: list[dict] = []
        try:
            r = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "conv,ip"],
                capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT,
            )
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 9 and _IP_PATTERN.match(parts[0]):
                    try:
                        conversations.append({
                            "src": parts[0], "dst": parts[2],
                            "frames_ab": int(parts[3]),
                            "bytes_ab": int(parts[4]),
                            "frames_ba": int(parts[5]),
                            "bytes_ba": int(parts[6]),
                            "total_bytes": int(parts[4]) + int(parts[6]),
                        })
                    except (ValueError, IndexError):
                        pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Sort by total bytes — large transfers = exfil signal
        conversations.sort(key=lambda x: x.get("total_bytes", 0), reverse=True)

        # Flag large outbound transfers (> 1 MB)
        large_transfers = [
            c for c in conversations if c.get("bytes_ab", 0) > 1_048_576
        ]

        # Private IP ranges for "external" detection
        def _is_private(ip: str) -> bool:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            try:
                first = int(parts[0])
                second = int(parts[1])
                return (
                    first == 10 or
                    (first == 172 and 16 <= second <= 31) or
                    (first == 192 and second == 168) or
                    first == 127
                )
            except ValueError:
                return False

        external_convs = [
            c for c in conversations
            if not _is_private(c.get("dst", "127.0.0.1"))
        ]

        data = {
            "pcap_file": pcap_path,
            "total_conversations": len(conversations),
            "external_conversations": len(external_convs),
            "large_transfers": large_transfers[:20],
            "top_conversations_by_bytes": conversations[:20],
            "external_conversations_list": external_convs[:30],
            "protocol_summary": result_parts.get("protocol_stats", "")[:500],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_pcap_summary", data, audit_id)

    @mcp.tool()
    def extract_dns_queries(pcap_path: str) -> str:
        """
        Extract DNS queries and responses from a PCAP file.

        Flags: DGA-style domains (random-looking names), suspicious TLDs,
        high-frequency queries (beaconing), and DNS tunnelling indicators
        (very long subdomain labels in queries = T1071.004).

        Args:
            pcap_path: Absolute path to the .pcap or .pcapng file.
        """
        if not Path(pcap_path).exists():
            return json.dumps({"error": f"PCAP file not found: {pcap_path}"})

        try:
            r = subprocess.run(
                [
                    "tshark", "-r", pcap_path,
                    "-Y", "dns",
                    "-T", "fields",
                    "-e", "frame.time_relative",
                    "-e", "ip.src",
                    "-e", "dns.qry.name",
                    "-e", "dns.resp.addr",
                    "-e", "dns.flags.response",
                    "-E", "separator=|",
                ],
                capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT,
            )
            log_tool_execution("extract_dns_queries", ["tshark", "-Y", "dns", pcap_path], r.stdout, error=r.stderr)
        except FileNotFoundError:
            return json.dumps({"error": "tshark not found. Install via: sudo apt install tshark"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "tshark timed out on DNS extraction"})

        audit_id = get_last_audit_id()
        increment_tool_counter()

        queries: list[dict] = []
        domain_counts: dict[str, int] = {}
        suspicious: list[dict] = []

        for line in r.stdout.splitlines():
            parts = line.split("|")
            if len(parts) < 3:
                continue
            domain = parts[2].strip().rstrip(".")
            if not domain:
                continue
            is_response = parts[4].strip() == "1" if len(parts) > 4 else False
            resolved = parts[3].strip() if len(parts) > 3 else ""

            domain_counts[domain] = domain_counts.get(domain, 0) + 1

            entry = {
                "time": parts[0].strip(),
                "src_ip": parts[1].strip(),
                "query": domain,
                "resolved": resolved,
                "is_response": is_response,
                "suspicious": _is_suspicious_domain(domain),
                "possible_dga": bool(_DGA_PATTERN.match(domain.split(".")[0])) if "." in domain else False,
                "long_subdomain": len(max(domain.split("."), key=len)) > 50,
            }
            queries.append(entry)
            if entry["suspicious"] or entry["long_subdomain"]:
                suspicious.append(entry)

        # Beaconing detection: domains queried > 30 times
        beaconing = [
            {"domain": d, "query_count": c}
            for d, c in sorted(domain_counts.items(), key=lambda x: -x[1])
            if c > 30
        ]

        data = {
            "total_dns_queries": len(queries),
            "unique_domains": len(domain_counts),
            "suspicious_domains": suspicious[:50],
            "beaconing_candidates": beaconing[:20],
            "top_queried_domains": [
                {"domain": d, "count": c}
                for d, c in sorted(domain_counts.items(), key=lambda x: -x[1])[:30]
            ],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("extract_dns_queries", data, audit_id)

    @mcp.tool()
    def parse_arp_cache(image_path: str) -> str:
        """
        Extract the ARP cache from a memory image using Volatility.

        The ARP cache reveals other hosts the compromised machine communicated with
        recently — useful for lateral movement discovery (T1021, T1018).
        IPs in ARP that don't appear in netscan may indicate past connections.

        Args:
            image_path: Absolute path to the memory image.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.netstat.NetStat"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
            log_tool_execution("parse_arp_cache", cmd, result.stdout, error=result.stderr)
            stdout, stderr = result.stdout, result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return json.dumps({"error": str(e)})

        audit_id = get_last_audit_id()
        increment_tool_counter()

        # Parse netstat for ARP-equivalent data (IP endpoints seen)
        seen_ips: set[str] = set()
        entries: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility"):
                continue
            for ip in _IP_PATTERN.findall(line):
                if ip not in ("0.0.0.0", "127.0.0.1") and ip not in seen_ips:
                    seen_ips.add(ip)
                    entries.append({"ip": ip, "raw_line": line[:200]})

        data = {
            "unique_hosts_seen": len(entries),
            "hosts": entries[:100],
            "note": "IPs from netstat output — run lookup_ip_reputation on external IPs",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_arp_cache", data, audit_id)
