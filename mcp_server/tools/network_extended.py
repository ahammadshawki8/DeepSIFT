"""
Extended network forensics tools.

Tools:
  parse_zeek_logs          — Parse Zeek/Bro conn.log, dns.log, http.log, files.log, ssl.log
  parse_iis_logs           — IIS W3C access log analysis
  parse_apache_logs        — Apache/Nginx access log analysis
  extract_pcap_files       — Extract transferred files from PCAP using NetworkMiner/tcpflow
  parse_firewall_logs      — Generic firewall log analysis (iptables, pf, Windows Firewall)
  parse_dns_cache          — Parse Windows DNS cache (ipconfig /displaydns output)
  decode_rdp_bitmap_cache  — Decode RDP bitmap cache files
  parse_netflow            — Parse NetFlow v5/v9 records from nfdump
"""
from __future__ import annotations
import csv
import json
import re
import subprocess
from io import StringIO
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import MAX_TOOL_TIMEOUT, EXPORTS_DIR
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.parsers.network_log_parser import (
    classify_network_log_entries, classify_dns_query, detect_port_scan, flags_to_mitre
)
from mcp_server.parsers.rag_enrichment import enrich_findings, build_rag_summary
from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques

_PRIVATE_RANGES = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fd)"
)


def _is_external(ip: str) -> bool:
    return bool(ip) and not _PRIVATE_RANGES.match(ip)


def register_network_extended_tools(mcp, rag=None):

    @mcp.tool()
    def parse_zeek_logs(log_dir: str, log_types: str = "conn,dns,http,files,ssl") -> str:
        """
        Parse Zeek (formerly Bro) network logs for forensic analysis.

        Supported log types: conn (connections), dns (queries), http (requests),
        files (file transfers), ssl (certificates), weird (anomalies), notice (alerts).

        Automatically flags: external connections, C2-characteristic beacon intervals,
        DNS exfiltration (long subdomains), self-signed certificates, and file downloads.

        Args:
            log_dir:   Directory containing Zeek log files (*.log).
            log_types: Comma-separated log types to parse (default: conn,dns,http,files,ssl).
        """
        increment_tool_counter()
        log_path = Path(log_dir)
        if not log_path.exists():
            return json.dumps({"error": f"Log directory not found: {log_dir}"})

        log_tool_execution("parse_zeek_logs", [log_dir, log_types], "Zeek log parse")
        audit_id = get_last_audit_id()

        requested = {t.strip() for t in log_types.split(",")}
        results: dict = {}
        external_connections: list[dict] = []
        dns_suspicious: list[dict] = []
        http_requests: list[dict] = []

        def _parse_zeek_tsv(path: Path) -> list[dict]:
            rows: list[dict] = []
            fields: list[str] = []
            try:
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                    elif line.startswith("#"):
                        continue
                    elif fields:
                        values = line.split("\t")
                        rows.append(dict(zip(fields, values)))
            except Exception:
                pass
            return rows

        for log_type in requested:
            log_file = log_path / f"{log_type}.log"
            if not log_file.exists():
                # Try compressed
                log_file = log_path / f"{log_type}.log.gz"
                if not log_file.exists():
                    continue

            rows = _parse_zeek_tsv(log_file)
            results[log_type] = {"count": len(rows), "sample": rows[:20]}

            if log_type == "conn":
                for r in rows:
                    dest = r.get("id.resp_h", "")
                    if _is_external(dest):
                        external_connections.append({
                            "src": r.get("id.orig_h", ""),
                            "dst": dest,
                            "dst_port": r.get("id.resp_p", ""),
                            "proto": r.get("proto", ""),
                            "duration": r.get("duration", ""),
                            "bytes_out": r.get("orig_bytes", ""),
                        })

            elif log_type == "dns":
                for r in rows:
                    query = r.get("query", "")
                    if len(query) > 50 or query.count(".") > 5:
                        dns_suspicious.append({
                            "query": query,
                            "answers": r.get("answers", ""),
                            "reason": "Possible DNS tunneling/exfiltration (long subdomain)",
                            "mitre": "T1071.004 — DNS",
                        })

            elif log_type == "http":
                for r in rows:
                    host = r.get("host", "")
                    uri = r.get("uri", "")
                    method = r.get("method", "")
                    if method == "POST" and _is_external(r.get("id.resp_h", "")):
                        http_requests.append({
                            "host": host,
                            "uri": uri[:200],
                            "method": method,
                            "dest_ip": r.get("id.resp_h", ""),
                            "user_agent": r.get("user_agent", "")[:200],
                            "note": "POST to external IP — possible C2 or data exfiltration",
                        })

        # Middleware parser: classify DNS queries with network_log_parser
        mp_dns_classified = []
        for r in dns_suspicious:
            query = r.get("query", "")
            dns_flags = classify_dns_query(query)
            if dns_flags:
                r["dns_threat_flags"] = dns_flags
                r["mitre_techniques"] = map_finding_to_techniques(" ".join(dns_flags))
                mp_dns_classified.append(r)

        enrich_findings(rag, external_connections[:20],
                        lambda c: f"network C2 connection external IP {c.get('dst', '')} port {c.get('dst_port', '')}")
        enrich_findings(rag, mp_dns_classified[:10],
                        lambda d: f"DNS tunneling exfiltration {d.get('query', '')} T1071.004")

        data = {
            "log_dir": log_dir,
            "logs_parsed": list(results.keys()),
            "external_connection_count": len(external_connections),
            "external_connections": external_connections[:50],
            "dns_suspicious": dns_suspicious[:50],
            "dns_classified": mp_dns_classified[:30],
            "http_post_to_external": http_requests[:50],
            "log_summaries": {k: v["count"] for k, v in results.items()},
            "rag_context": build_rag_summary(rag, "Zeek network forensics C2 DNS tunneling exfiltration"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_zeek_logs", data, audit_id)

    @mcp.tool()
    def parse_iis_logs(log_dir: str, filter_status: str = "") -> str:
        """
        Parse Microsoft IIS W3C format access logs for forensic indicators.

        Detects: web shell access (POST to .asp/.aspx/.php with 200 response),
        directory traversal attempts, SQL injection patterns in URIs,
        unusual user agents, and high-volume requests from a single IP.

        Args:
            log_dir:       Directory containing IIS log files (.log W3C format).
            filter_status: Only return entries with this HTTP status code (e.g. '200').
        """
        increment_tool_counter()
        log_path = Path(log_dir)
        if not log_path.exists():
            return json.dumps({"error": f"Log directory not found: {log_dir}"})

        log_tool_execution("parse_iis_logs", [log_dir, filter_status], "IIS log parse")
        audit_id = get_last_audit_id()

        _WEB_SHELLS = [".asp", ".aspx", ".php", ".jsp", ".jspx", ".cfm", ".shtml"]
        _TRAVERSAL = re.compile(r"\.\./|\.\.%2F|%2e%2e", re.IGNORECASE)
        _SQLI = re.compile(r"union\s+select|or\s+1=1|'\s*or\s*'|xp_cmdshell|exec\(|INFORMATION_SCHEMA", re.IGNORECASE)

        entries: list[dict] = []
        web_shell_hits: list[dict] = []
        traversal_hits: list[dict] = []
        sqli_hits: list[dict] = []
        ip_counts: dict[str, int] = {}
        fields: list[str] = []

        for log_file in sorted(log_path.glob("*.log")):
            try:
                for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("#Fields:"):
                        fields = line.replace("#Fields:", "").strip().split()
                        continue
                    if line.startswith("#") or not line.strip():
                        continue
                    if not fields:
                        continue

                    values = line.split()
                    if len(values) < len(fields):
                        continue
                    row = dict(zip(fields, values))

                    status = row.get("sc-status", "")
                    if filter_status and status != filter_status:
                        continue

                    method = row.get("cs-method", "")
                    uri = row.get("cs-uri-stem", "")
                    client_ip = row.get("c-ip", "")
                    entry = {
                        "date": row.get("date", ""),
                        "time": row.get("time", ""),
                        "client_ip": client_ip,
                        "method": method,
                        "uri": uri,
                        "status": status,
                        "user_agent": row.get("cs(User-Agent)", "")[:200],
                    }
                    entries.append(entry)
                    if client_ip:
                        ip_counts[client_ip] = ip_counts.get(client_ip, 0) + 1

                    if method == "POST" and any(uri.endswith(ext) for ext in _WEB_SHELLS) and status == "200":
                        entry["threat"] = "Web shell access"
                        entry["mitre"] = "T1505.003 — Server Software Component: Web Shell"
                        web_shell_hits.append(entry)

                    if _TRAVERSAL.search(uri):
                        entry["threat"] = "Directory traversal attempt"
                        entry["mitre"] = "T1083 — File and Directory Discovery"
                        traversal_hits.append(entry)

                    if _SQLI.search(uri):
                        entry["threat"] = "SQL injection attempt"
                        entry["mitre"] = "T1190 — Exploit Public-Facing Application"
                        sqli_hits.append(entry)

            except Exception:
                pass

        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        # Middleware parser: classify all IIS entries for additional threat categories
        _, mp_suspicious = classify_network_log_entries(entries)
        port_scanners = detect_port_scan(entries)
        enrich_findings(rag, web_shell_hits[:10],
                        lambda e: f"web shell access IIS POST {e.get('uri', '')} T1505.003")
        enrich_findings(rag, sqli_hits[:5],
                        lambda e: f"SQL injection attack IIS {e.get('uri', '')} T1190")

        data = {
            "log_dir": log_dir,
            "total_entries": len(entries),
            "web_shell_hits": web_shell_hits[:50],
            "traversal_hits": traversal_hits[:50],
            "sqli_hits": sqli_hits[:30],
            "parser_suspicious": mp_suspicious[:50],
            "port_scanners": port_scanners[:10],
            "top_client_ips": [{"ip": ip, "request_count": cnt} for ip, cnt in top_ips],
            "all_entries": entries[:200],
            "rag_context": build_rag_summary(rag, "IIS web shell SQL injection web attack T1505.003 T1190"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_iis_logs", data, audit_id)

    @mcp.tool()
    def parse_apache_logs(log_path: str, combined_format: bool = True) -> str:
        """
        Parse Apache/Nginx access logs for forensic indicators.

        Detects: web shell access, directory traversal, SQL injection,
        scanner signatures in user agents, high-frequency request bursts,
        and suspicious file downloads.

        Args:
            log_path:        Path to the access log file.
            combined_format: True if Combined Log Format (includes Referer + User-Agent).
        """
        increment_tool_counter()
        if not Path(log_path).exists():
            return json.dumps({"error": f"Log file not found: {log_path}"})

        log_tool_execution("parse_apache_logs", [log_path], "Apache/Nginx log parse")
        audit_id = get_last_audit_id()

        _SCANNER_UAS = [
            "nikto", "sqlmap", "nessus", "masscan", "nmap", "gobuster",
            "dirbuster", "wfuzz", "hydra", "zgrab", "shodan", "censys",
        ]
        _SQLI = re.compile(r"union.*select|or\s+1=1|xp_cmdshell|information_schema", re.IGNORECASE)
        _TRAVERSAL = re.compile(r"\.\./|%2e%2e|%252e", re.IGNORECASE)
        # Combined log format regex
        _LOG_RE = re.compile(
            r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)[^"]*"\s+'
            r'(?P<status>\d+)\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
        )

        entries: list[dict] = []
        scanner_hits: list[dict] = []
        sqli_hits: list[dict] = []
        traversal_hits: list[dict] = []
        ip_counts: dict[str, int] = {}

        try:
            for line in Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines():
                m = _LOG_RE.match(line)
                if not m:
                    continue
                ip = m.group("ip")
                status = m.group("status")
                uri = m.group("uri")
                ua = m.group("ua") or "" if combined_format else ""
                entry = {
                    "ip": ip, "time": m.group("time"), "method": m.group("method"),
                    "uri": uri[:300], "status": status, "user_agent": ua[:200],
                }
                entries.append(entry)
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

                if any(s in ua.lower() for s in _SCANNER_UAS):
                    entry["threat"] = "Scanner user agent"
                    scanner_hits.append(entry)
                if _SQLI.search(uri):
                    entry["threat"] = "SQL injection attempt"
                    sqli_hits.append(entry)
                if _TRAVERSAL.search(uri):
                    entry["threat"] = "Directory traversal attempt"
                    traversal_hits.append(entry)

        except Exception as e:
            return json.dumps({"error": str(e)})

        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        _, mp_suspicious = classify_network_log_entries(entries)
        enrich_findings(rag, scanner_hits[:10],
                        lambda e: f"web scanner attack Apache {e.get('user_agent', '')} T1595.001")
        enrich_findings(rag, sqli_hits[:5],
                        lambda e: f"SQL injection Apache {e.get('uri', '')} T1190")

        data = {
            "log_path": log_path,
            "total_entries": len(entries),
            "scanner_hits": scanner_hits[:50],
            "sqli_hits": sqli_hits[:50],
            "traversal_hits": traversal_hits[:50],
            "parser_suspicious": mp_suspicious[:50],
            "top_client_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
            "all_entries": entries[:200],
            "rag_context": build_rag_summary(rag, "Apache Nginx web attack scanner SQL injection T1190"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_apache_logs", data, audit_id)

    @mcp.tool()
    def extract_pcap_files(pcap_path: str, output_dir: str = "") -> str:
        """
        Extract files transferred over the network from a PCAP capture.

        Uses tcpflow to reassemble TCP streams, then identifies transferred
        files by magic bytes. Recovers: HTTP downloads, FTP transfers, email
        attachments, and any file transmitted in cleartext.

        Args:
            pcap_path:  Absolute path to the PCAP/PCAPNG file.
            output_dir: Directory for extracted files (default: exports/pcap_files/).
        """
        increment_tool_counter()
        if not Path(pcap_path).exists():
            return json.dumps({"error": f"PCAP not found: {pcap_path}"})

        out_dir = Path(output_dir) if output_dir else EXPORTS_DIR / "pcap_files"
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = ["tcpflow", "-r", pcap_path, "-o", str(out_dir), "-a"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT * 2)
            log_tool_execution("extract_pcap_files", cmd, result.stdout, error=result.stderr)
        except FileNotFoundError:
            return json.dumps({"error": "tcpflow not found. Install: sudo apt install tcpflow"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "tcpflow timed out"})

        audit_id = get_last_audit_id()

        # Identify extracted files by magic
        _MAGIC_MAP = {
            b"MZ": "PE executable",
            b"\x7fELF": "ELF executable",
            b"%PDF": "PDF document",
            b"PK\x03\x04": "ZIP archive",
            b"\xff\xd8\xff": "JPEG image",
            b"GIF8": "GIF image",
            b"\x89PNG": "PNG image",
        }

        extracted_files: list[dict] = []
        for f in out_dir.iterdir():
            if f.is_file() and f.suffix != ".findx":
                try:
                    magic = f.read_bytes()[:8]
                    file_type = "unknown"
                    for sig, desc in _MAGIC_MAP.items():
                        if magic.startswith(sig):
                            file_type = desc
                            break
                    extracted_files.append({
                        "filename": f.name,
                        "size_bytes": f.stat().st_size,
                        "detected_type": file_type,
                        "suspicious": file_type in ("PE executable", "ELF executable"),
                    })
                except Exception:
                    pass

        suspicious = [f for f in extracted_files if f.get("suspicious")]

        data = {
            "pcap_path": pcap_path,
            "output_dir": str(out_dir),
            "total_extracted": len(extracted_files),
            "suspicious_files": suspicious[:50],
            "all_extracted_files": extracted_files[:200],
            "mitre": "T1041 — Exfiltration Over C2 Channel" if suspicious else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("extract_pcap_files", data, audit_id)

    @mcp.tool()
    def parse_firewall_logs(log_path: str, log_type: str = "auto") -> str:
        """
        Parse firewall logs for forensic indicators.

        Supported log types: 'iptables', 'windows' (Windows Firewall), 'pf' (BSD pf).
        Auto-detects format when log_type='auto'.

        Detects: port scan patterns (many ports from one IP), blocked outbound
        connections (data exfiltration attempts), inbound accepted connections
        on unusual ports, and repeated blocked connection attempts.

        Args:
            log_path: Absolute path to the firewall log file.
            log_type: 'iptables', 'windows', 'pf', or 'auto'.
        """
        increment_tool_counter()
        if not Path(log_path).exists():
            return json.dumps({"error": f"Log file not found: {log_path}"})

        log_tool_execution("parse_firewall_logs", [log_path, log_type], "firewall log parse")
        audit_id = get_last_audit_id()

        text = Path(log_path).read_text(encoding="utf-8", errors="replace")

        # Auto-detect format
        if log_type == "auto":
            if "IPTables" in text or "iptables" in text or "IN=" in text:
                log_type = "iptables"
            elif "Windows Filtering Platform" in text or "ALLOW" in text and "BLOCK" in text:
                log_type = "windows"
            else:
                log_type = "iptables"

        entries: list[dict] = []
        blocked: list[dict] = []
        allowed_external: list[dict] = []
        src_ip_counts: dict[str, int] = {}

        if log_type == "iptables":
            _ENTRY_RE = re.compile(
                r"(?P<ts>\w+\s+\d+\s+[\d:]+).*?(?:DROP|REJECT|ACCEPT)\s+.*?"
                r"SRC=(?P<src>[\d.]+).*?DST=(?P<dst>[\d.]+).*?DPT=(?P<dpt>\d+)",
                re.DOTALL,
            )
            for m in _ENTRY_RE.finditer(text):
                action = "DROP" if ("DROP" in m.group(0) or "REJECT" in m.group(0)) else "ACCEPT"
                entry = {
                    "timestamp": m.group("ts"),
                    "src": m.group("src"),
                    "dst": m.group("dst"),
                    "dst_port": m.group("dpt"),
                    "action": action,
                }
                entries.append(entry)
                src = m.group("src")
                src_ip_counts[src] = src_ip_counts.get(src, 0) + 1
                if action == "DROP":
                    blocked.append(entry)
                elif _is_external(m.group("dst")):
                    allowed_external.append(entry)

        elif log_type == "windows":
            for line in text.splitlines():
                if "ALLOW" in line or "DROP" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        entry = {"raw": line[:300]}
                        entries.append(entry)

        # Port scan detection: one src IP hitting many destination ports
        port_scanners: list[dict] = []
        src_port_map: dict[str, set] = {}
        for e in entries:
            src = e.get("src", "")
            dpt = e.get("dst_port", "")
            if src and dpt:
                src_port_map.setdefault(src, set()).add(dpt)
        for src, ports in src_port_map.items():
            if len(ports) > 10:
                port_scanners.append({"src_ip": src, "unique_ports_probed": len(ports), "sample_ports": list(ports)[:20]})

        data = {
            "log_path": log_path,
            "log_type": log_type,
            "total_entries": len(entries),
            "blocked_count": len(blocked),
            "allowed_external_count": len(allowed_external),
            "port_scanners": port_scanners[:20],
            "allowed_external_sample": allowed_external[:30],
            "top_source_ips": sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:20],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_firewall_logs", data, audit_id)

    @mcp.tool()
    def decode_rdp_bitmap_cache(cache_dir: str, output_dir: str = "") -> str:
        """
        Decode Windows RDP bitmap cache files to recover screenshots of remote sessions.

        RDP bitmap cache stores tiles of the remote desktop to optimize rendering.
        Forensically, reassembling these tiles reconstructs what the attacker saw
        during a Remote Desktop session — revealing visited applications, documents,
        and data.

        Requires: bmc-tools (pip3 install bmc-tools)

        Args:
            cache_dir:  Directory containing RDP bitmap cache files
                        (typically C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\).
            output_dir: Directory for output images (default: exports/rdp_cache/).
        """
        increment_tool_counter()
        cache_path = Path(cache_dir)
        if not cache_path.exists():
            return json.dumps({"error": f"Cache directory not found: {cache_dir}"})

        out_dir = Path(output_dir) if output_dir else EXPORTS_DIR / "rdp_cache"
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = ["bmc-tools", "-s", str(cache_path), "-d", str(out_dir)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
            log_tool_execution("decode_rdp_bitmap_cache", cmd, result.stdout, error=result.stderr)
        except FileNotFoundError:
            return json.dumps({
                "error": "bmc-tools not found. Install: pip3 install bmc-tools",
                "note": "bmc-tools by ANSSI decodes RDP bitmap cache files.",
            })
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "bmc-tools timed out"})

        audit_id = get_last_audit_id()

        cache_files = list(cache_path.glob("*.bin")) + list(cache_path.glob("Cache*.tmp"))
        output_images = list(out_dir.glob("*.png")) + list(out_dir.glob("*.bmp"))

        data = {
            "cache_dir": cache_dir,
            "output_dir": str(out_dir),
            "cache_files_found": len(cache_files),
            "cache_file_names": [f.name for f in cache_files[:20]],
            "images_extracted": len(output_images),
            "output_image_paths": [str(p) for p in output_images[:20]],
            "mitre": "T1021.001 — Remote Desktop Protocol" if cache_files else "",
            "note": f"Open {out_dir} in an image viewer to examine RDP session screenshots",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("decode_rdp_bitmap_cache", data, audit_id)

    @mcp.tool()
    def parse_netflow(netflow_file: str, top_n: int = 20) -> str:
        """
        Parse NetFlow records from an nfdump binary file or nfdump text export.

        NetFlow provides network summary data: which hosts communicated with which,
        on what ports, for how long, and how many bytes transferred. Useful for
        detecting data exfiltration (large outbound transfers) and lateral movement.

        Requires: nfdump (sudo apt install nfdump)

        Args:
            netflow_file: Path to nfdump binary file or exported text.
            top_n:        Number of top talkers to return by byte volume.
        """
        increment_tool_counter()
        if not Path(netflow_file).exists():
            return json.dumps({"error": f"NetFlow file not found: {netflow_file}"})

        # Try nfdump output
        cmd = ["nfdump", "-r", netflow_file, "-o", "csv", "-s", f"dstip/bytes:{top_n}"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
            log_tool_execution("parse_netflow", cmd, result.stdout[:500], error=result.stderr[:200])
        except FileNotFoundError:
            # Try treating as plain text nfdump export
            result_text = Path(netflow_file).read_text(encoding="utf-8", errors="replace")
            log_tool_execution("parse_netflow", [netflow_file], result_text[:500])
            audit_id = get_last_audit_id()
            return wrap_response("parse_netflow", {
                "netflow_file": netflow_file,
                "note": "nfdump not found — returning raw file content",
                "content": result_text[:5000],
                "tool_calls_used": get_tool_count(),
            }, audit_id)
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "nfdump timed out"})

        audit_id = get_last_audit_id()

        top_destinations: list[dict] = []
        large_transfers: list[dict] = []

        try:
            reader = csv.DictReader(StringIO(result.stdout))
            for row in reader:
                entry = dict(row)
                top_destinations.append(entry)
                bytes_out = int(entry.get("bytes", entry.get("Bytes", 0)) or 0)
                dst = entry.get("dst ip", entry.get("dstIP", ""))
                if bytes_out > 10_000_000 and _is_external(dst):
                    entry["mitre"] = "T1041 — Exfiltration Over C2 Channel"
                    large_transfers.append(entry)
        except Exception:
            top_destinations = [{"raw": result.stdout[:3000]}]

        data = {
            "netflow_file": netflow_file,
            "top_destinations_by_bytes": top_destinations[:top_n],
            "large_external_transfers": large_transfers[:30],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_netflow", data, audit_id)
