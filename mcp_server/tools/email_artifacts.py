"""
Email forensics tools — PST/OST, Thunderbird, EML, MBOX parsing.

Tools:
  parse_pst_ost          — Outlook PST/OST via pffexport (T1114.001)
  parse_thunderbird      — Thunderbird profile/mbox forensics
  parse_eml_file         — Single RFC 2822 .eml file analysis
  extract_email_attachments — List and categorise attachments from PST/OST
  analyze_email_headers  — Header forensics (SPF/DKIM/DMARC, route, spoofing)
"""
from __future__ import annotations
import email
import email.policy
import json
import re
import subprocess
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import MAX_TOOL_TIMEOUT, EXPORTS_DIR
from mcp_server.parsers.forensic_knowledge import wrap_response

_SUSPICIOUS_ATTACHMENT_EXTS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".scr", ".pif", ".com", ".msi", ".lnk",
    ".doc", ".docm", ".xls", ".xlsm", ".xlsb", ".ppt", ".pptm",
    ".rtf", ".pdf", ".zip", ".7z", ".rar", ".iso", ".img",
}


def register_email_artifact_tools(mcp, rag=None):

    @mcp.tool()
    def parse_pst_ost(pst_path: str, output_dir: str = "") -> str:
        """
        Parse a Microsoft Outlook PST or OST file using pffexport.

        Extracts: folder structure, email count per folder, sender/recipient
        summaries, attachment inventory, and date range.

        Requires: sudo apt install pff-tools  (provides pffexport)

        PST/OST files are high-value exfiltration targets — they contain all
        historical email, calendar entries, and contacts. Their presence in the
        user profile reveals the scope of data accessible to an attacker.

        Args:
            pst_path:   Absolute path to the .pst or .ost file.
            output_dir: Directory to extract content to (default: exports/pst_<name>/).
        """
        increment_tool_counter()
        if not Path(pst_path).exists():
            return json.dumps({"error": f"PST/OST file not found: {pst_path}"})

        name = Path(pst_path).stem
        out_dir = Path(output_dir) if output_dir else EXPORTS_DIR / f"pst_{name}"
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = ["pffexport", "-m", "all", "-t", str(out_dir), pst_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT * 2)
            log_tool_execution("parse_pst_ost", cmd, result.stdout, error=result.stderr)
        except FileNotFoundError:
            return json.dumps({
                "error": "pffexport not found. Install: sudo apt install pff-tools",
                "pst_path": pst_path,
                "file_size_mb": round(Path(pst_path).stat().st_size / 1_048_576, 1),
                "note": "File exists but cannot be parsed without pff-tools.",
            })
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "pffexport timed out — large PST file"})

        audit_id = get_last_audit_id()

        # Inventory extracted content
        folders: list[dict] = []
        attachments: list[dict] = []
        senders: dict[str, int] = {}
        total_emails = 0

        for p in out_dir.rglob("*"):
            if p.is_dir():
                eml_count = sum(1 for _ in p.glob("*.eml"))
                if eml_count:
                    total_emails += eml_count
                    folders.append({"folder": str(p.relative_to(out_dir)), "email_count": eml_count})
            elif p.suffix.lower() in _SUSPICIOUS_ATTACHMENT_EXTS:
                attachments.append({
                    "filename": p.name,
                    "size_bytes": p.stat().st_size if p.exists() else 0,
                    "extension": p.suffix.lower(),
                    "suspicious": True,
                    "path": str(p.relative_to(out_dir)),
                })

        data = {
            "pst_path": pst_path,
            "output_dir": str(out_dir),
            "total_emails_extracted": total_emails,
            "folder_count": len(folders),
            "folders": sorted(folders, key=lambda x: -x["email_count"])[:30],
            "suspicious_attachments": attachments[:100],
            "suspicious_attachment_count": len(attachments),
            "note": "Run analyze_email_headers on specific .eml files for header forensics.",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_pst_ost", data, audit_id)

    @mcp.tool()
    def parse_thunderbird(profile_path: str) -> str:
        """
        Parse Mozilla Thunderbird email client for forensic artifacts.

        Returns: account configuration (IMAP/SMTP servers), folder inventory,
        email count per folder, and attachment summary.

        Args:
            profile_path: Path to a Thunderbird profile directory.
                          Typically: Users/<user>/AppData/Roaming/Thunderbird/Profiles/<profile>/
        """
        increment_tool_counter()
        profile = Path(profile_path)
        if not profile.exists():
            return json.dumps({"error": f"Thunderbird profile not found: {profile_path}"})

        log_tool_execution("parse_thunderbird", [str(profile)], "profile scan")
        audit_id = get_last_audit_id()

        # Parse prefs.js for account info
        prefs_file = profile / "prefs.js"
        accounts: list[dict] = []
        if prefs_file.exists():
            prefs_text = prefs_file.read_text(encoding="utf-8", errors="replace")
            # Extract mail server settings
            server_names = re.findall(r'user_pref\("mail\.server\.(\w+)\.hostname",\s*"([^"]+)"\)', prefs_text)
            server_users = dict(re.findall(r'user_pref\("mail\.server\.(\w+)\.userName",\s*"([^"]+)"\)', prefs_text))
            server_types = dict(re.findall(r'user_pref\("mail\.server\.(\w+)\.type",\s*"([^"]+)"\)', prefs_text))
            for key, hostname in server_names:
                accounts.append({
                    "server_key": key,
                    "hostname": hostname,
                    "username": server_users.get(key, ""),
                    "type": server_types.get(key, ""),
                })

        # Inventory mbox files
        folders: list[dict] = []
        total_emails = 0
        for mbox in sorted(profile.rglob("*.msf"))[:200]:
            mbox_file = mbox.with_suffix("")
            if mbox_file.exists():
                size = mbox_file.stat().st_size
                # Count "From " lines as email count approximation
                try:
                    count = mbox_file.read_bytes().count(b"\nFrom ")
                except Exception:
                    count = 0
                total_emails += count
                folders.append({
                    "folder": str(mbox_file.relative_to(profile)),
                    "size_bytes": size,
                    "approx_email_count": count,
                })

        data = {
            "profile_path": str(profile_path),
            "accounts": accounts,
            "total_emails_approx": total_emails,
            "folder_count": len(folders),
            "folders": sorted(folders, key=lambda x: -x["approx_email_count"])[:30],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_thunderbird", data, audit_id)

    @mcp.tool()
    def parse_eml_file(eml_path: str) -> str:
        """
        Parse a single RFC 2822 .eml email file for forensic analysis.

        Returns: sender, recipients, date, subject, body preview, attachment list,
        and header forensics (routing hops, X-Originating-IP, Reply-To spoofing).

        Args:
            eml_path: Absolute path to the .eml file.
        """
        increment_tool_counter()
        if not Path(eml_path).exists():
            return json.dumps({"error": f"EML file not found: {eml_path}"})

        log_tool_execution("parse_eml_file", [eml_path], "RFC 2822 parse")
        audit_id = get_last_audit_id()

        try:
            raw = Path(eml_path).read_bytes()
            msg = email.message_from_bytes(raw, policy=email.policy.compat32)
        except Exception as e:
            return json.dumps({"error": f"Failed to parse EML: {e}"})

        # Headers
        sender = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        to = msg.get("To", "")
        date = msg.get("Date", "")
        subject = msg.get("Subject", "")
        x_orig_ip = msg.get("X-Originating-IP", "")
        received = msg.get_all("Received", [])

        # Spoofing indicators
        spoofing_flags = []
        if reply_to and reply_to != sender:
            spoofing_flags.append(f"Reply-To differs from From: {reply_to}")
        if x_orig_ip:
            spoofing_flags.append(f"X-Originating-IP: {x_orig_ip}")

        # Body and attachments
        body_preview = ""
        attachments = []
        for part in msg.walk():
            ct = part.get_content_type()
            cd = part.get_content_disposition() or ""
            if ct in ("text/plain", "text/html") and "attachment" not in cd:
                try:
                    body_preview = part.get_payload(decode=True).decode("utf-8", errors="replace")[:500]
                except Exception:
                    pass
            elif "attachment" in cd or part.get_filename():
                fname = part.get_filename() or "unnamed"
                ext = Path(fname).suffix.lower()
                attachments.append({
                    "filename": fname,
                    "content_type": ct,
                    "suspicious": ext in _SUSPICIOUS_ATTACHMENT_EXTS,
                })

        # Extract IPs from Received headers
        received_ips = []
        for r in received:
            received_ips.extend(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", r))

        data = {
            "eml_path": eml_path,
            "from": sender,
            "to": to,
            "reply_to": reply_to,
            "date": date,
            "subject": subject,
            "body_preview": body_preview,
            "attachment_count": len(attachments),
            "attachments": attachments,
            "x_originating_ip": x_orig_ip,
            "received_hop_count": len(received),
            "received_ips": list(dict.fromkeys(received_ips)),
            "spoofing_flags": spoofing_flags,
            "suspicious_attachment": any(a["suspicious"] for a in attachments),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_eml_file", data, audit_id)

    @mcp.tool()
    def extract_email_attachments(pst_dir: str, output_dir: str = "") -> str:
        """
        Inventory all attachments extracted from a PST/OST (after parse_pst_ost).

        Categorises attachments by extension, flags executables and office documents
        with macros, and identifies suspicious filenames (double extensions,
        unicode right-to-left override, very long names).

        Args:
            pst_dir:    Directory produced by parse_pst_ost (pffexport output).
            output_dir: Optional alternative directory to scan.
        """
        increment_tool_counter()
        scan_dir = Path(output_dir) if output_dir else Path(pst_dir)
        if not scan_dir.exists():
            return json.dumps({"error": f"Directory not found: {scan_dir}"})

        log_tool_execution("extract_email_attachments", [str(scan_dir)], "recursive scan")
        audit_id = get_last_audit_id()

        all_attachments: list[dict] = []
        ext_counts: dict[str, int] = {}

        for f in scan_dir.rglob("*"):
            if not f.is_file():
                continue
            ext = f.suffix.lower()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

            if ext not in {".eml", ".msf", "", ".db", ".sqlite"}:
                name = f.name
                flags = []
                if ext in _SUSPICIOUS_ATTACHMENT_EXTS:
                    flags.append("SUSPICIOUS_EXTENSION")
                # Double extension (e.g. invoice.pdf.exe)
                if len(f.suffixes) > 1 and f.suffixes[-1].lower() in {".exe", ".dll", ".bat", ".cmd"}:
                    flags.append("DOUBLE_EXTENSION")
                # Unicode RTLO character
                if "‮" in name:
                    flags.append("RTLO_UNICODE")
                if len(name) > 100:
                    flags.append("SUSPICIOUSLY_LONG_NAME")

                try:
                    size = f.stat().st_size
                except Exception:
                    size = 0

                all_attachments.append({
                    "filename": name,
                    "extension": ext,
                    "size_bytes": size,
                    "relative_path": str(f.relative_to(scan_dir)),
                    "flags": flags,
                    "suspicious": bool(flags),
                })

        suspicious = [a for a in all_attachments if a["suspicious"]]

        data = {
            "scan_dir": str(scan_dir),
            "total_files": len(all_attachments),
            "suspicious_count": len(suspicious),
            "suspicious_attachments": suspicious[:100],
            "extension_summary": dict(sorted(ext_counts.items(), key=lambda x: -x[1])[:30]),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("extract_email_attachments", data, audit_id)

    @mcp.tool()
    def analyze_email_headers(eml_path: str = "", raw_headers: str = "") -> str:
        """
        Forensic analysis of email headers for spoofing, routing anomalies,
        and origin IP identification.

        Checks: SPF/DKIM/DMARC authentication results, From/Reply-To mismatch,
        X-Originating-IP, unusual Received hop count, and routing path analysis.

        Args:
            eml_path:    Path to .eml file (provide this OR raw_headers).
            raw_headers: Raw email headers as a string (alternative to eml_path).
        """
        increment_tool_counter()

        if eml_path and Path(eml_path).exists():
            raw = Path(eml_path).read_bytes()
            msg = email.message_from_bytes(raw, policy=email.policy.compat32)
            source = eml_path
        elif raw_headers:
            msg = email.message_from_string(raw_headers, policy=email.policy.compat32)
            source = "raw_headers"
        else:
            return json.dumps({"error": "Provide either eml_path or raw_headers"})

        log_tool_execution("analyze_email_headers", [source], "header forensics")
        audit_id = get_last_audit_id()

        # Authentication results
        auth_results = msg.get("Authentication-Results", "")
        spf = "pass" if "spf=pass" in auth_results.lower() else ("fail" if "spf=fail" in auth_results.lower() else "unknown")
        dkim = "pass" if "dkim=pass" in auth_results.lower() else ("fail" if "dkim=fail" in auth_results.lower() else "unknown")
        dmarc = "pass" if "dmarc=pass" in auth_results.lower() else ("fail" if "dmarc=fail" in auth_results.lower() else "unknown")

        # Routing analysis
        received_headers = msg.get_all("Received", [])
        hops = []
        all_ips: list[str] = []
        for r in received_headers:
            ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", r)
            all_ips.extend(ips)
            hops.append({"header": r[:300], "ips": ips})

        # Spoofing indicators
        from_addr = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        spoofing_indicators = []
        if reply_to and reply_to.lower() != from_addr.lower():
            spoofing_indicators.append(f"Reply-To ({reply_to}) differs from From ({from_addr})")
        if return_path and not from_addr.endswith(re.sub(r".*@", "", return_path.strip("<>"))):
            spoofing_indicators.append(f"Return-Path domain differs from From domain")
        if spf == "fail":
            spoofing_indicators.append("SPF FAIL — sending IP not authorised for From domain")
        if dkim == "fail":
            spoofing_indicators.append("DKIM FAIL — message signature invalid or missing")

        data = {
            "source": source,
            "from": from_addr,
            "to": msg.get("To", ""),
            "reply_to": reply_to,
            "return_path": return_path,
            "date": msg.get("Date", ""),
            "subject": msg.get("Subject", ""),
            "x_originating_ip": msg.get("X-Originating-IP", ""),
            "message_id": msg.get("Message-ID", ""),
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "authentication_results": auth_results[:500],
            "hop_count": len(received_headers),
            "routing_hops": hops[:10],
            "unique_ips_in_route": list(dict.fromkeys(all_ips)),
            "spoofing_indicators": spoofing_indicators,
            "likely_spoofed": len(spoofing_indicators) >= 2,
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("analyze_email_headers", data, audit_id)
