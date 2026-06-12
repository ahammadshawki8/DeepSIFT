"""
Extended Windows Registry forensics — EZ Tools extensions and direct hive parsing.

Tools beyond the basic parse_registry_hive already in windows_artifacts.py:
  parse_shellbags          — SbECmd: folder navigation history (T1083)
  parse_windows_timeline   — WxTCmd: Windows 10/11 Activities Cache (execution + browsing)
  parse_bam_dam            — Background Activity Moderator: execution timestamps (Win10 1709+)
  parse_typed_paths        — Explorer TypedPaths: manually typed folder paths
  parse_run_mru            — Run dialog execution history
  parse_open_save_mru      — Open/Save dialog recent file access
  parse_wordwheelquery     — Windows Search query history
  parse_installed_software — SOFTWARE hive installed programs inventory
  parse_sam_hive           — SAM hive: local user accounts and last logon info
  parse_logon_history      — Security hive: cached domain credentials + last logon
"""
import json
import subprocess
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import EZ_TOOLS_DIR, MAX_TOOL_TIMEOUT, EXPORTS_DIR
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.parsers.rag_enrichment import enrich_findings, build_rag_summary
from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques

_EZ = EZ_TOOLS_DIR


def _run_ez(tool: str, args: list[str]) -> tuple[str, str]:
    """Run an EZ Tool and return (stdout, stderr).

    Resolves the tool cross-platform: native ``<Tool>.exe`` on Windows, otherwise
    the .NET ``<Tool>.dll`` (subdir-aware) via ``dotnet`` on SANS SIFT (Linux).
    """
    import os
    name = tool[:-4] if tool.lower().endswith(".exe") else tool
    exe = _EZ / f"{name}.exe"
    if os.name == "nt" and exe.exists():
        cmd = [str(exe)] + args
    else:
        hits = list(_EZ.glob(f"**/{name}.dll"))
        if hits:
            cmd = ["dotnet", str(hits[0])] + args
        elif exe.exists():
            cmd = [str(exe)] + args
        else:
            return "", f"{name} not found under {_EZ} (.exe or .dll)"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return "", f"{name} timed out"
    except Exception as e:
        return "", str(e)


def _run_recmd(hive_path: str, batch_or_key: str, is_batch: bool = False) -> tuple[str, str]:
    """Run RECmd on a registry hive."""
    out_dir = str(EXPORTS_DIR)
    if is_batch:
        return _run_ez("RECmd.exe", ["-f", hive_path, "--bn", batch_or_key, "--csv", out_dir, "--csvf", "regscan.csv", "-q"])
    return _run_ez("RECmd.exe", ["-f", hive_path, "--kn", batch_or_key, "--csv", out_dir, "--csvf", "regscan.csv", "-q"])


def _parse_csv_output(csv_text: str, max_rows: int = 500) -> list[dict]:
    """Parse simple CSV output from EZ Tools."""
    import csv as _csv
    from io import StringIO
    rows: list[dict] = []
    try:
        reader = _csv.DictReader(StringIO(csv_text))
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            rows.append({k.strip(): v.strip()[:500] for k, v in row.items() if v})
    except Exception:
        pass
    return rows


def register_registry_extended_tools(mcp, rag=None):

    @mcp.tool()
    def parse_shellbags(ntuser_path: str = "", usrclass_path: str = "") -> str:
        """
        Parse Windows Shellbag artifacts using SbECmd.

        Shellbags record the size, position, and last-access time of folders
        that were browsed in Windows Explorer — INCLUDING folders on removable
        media, network shares, and deleted directories.

        Key forensic value:
        - Proves a user/attacker BROWSED specific directories (T1083)
        - Persists even after the target folder is deleted
        - Shows access to external drives, network shares, zip contents

        Args:
            ntuser_path:  Path to NTUSER.DAT hive (required).
            usrclass_path: Path to UsrClass.dat hive (enhances results; optional).
        """
        increment_tool_counter()
        if not ntuser_path or not Path(ntuser_path).exists():
            return json.dumps({"error": f"NTUSER.DAT not found: {ntuser_path}"})

        out_dir = str(EXPORTS_DIR)
        args = ["-d", str(Path(ntuser_path).parent), "--csv", out_dir, "--csvf", "shellbags.csv", "-q"]
        if usrclass_path and Path(usrclass_path).exists():
            args = ["-d", str(Path(ntuser_path).parent), "--csv", out_dir, "--csvf", "shellbags.csv", "-q"]

        stdout, stderr = _run_ez("SbECmd.exe", args)
        log_tool_execution("parse_shellbags", ["SbECmd.exe"] + args, stdout, error=stderr)
        audit_id = get_last_audit_id()

        # Parse output CSV
        csv_file = EXPORTS_DIR / "shellbags.csv"
        entries: list[dict] = []
        if csv_file.exists():
            entries = _parse_csv_output(csv_file.read_text(encoding="utf-8-sig", errors="replace"))

        # Flag interesting paths
        suspicious_paths = [
            e for e in entries
            if any(kw in str(e).lower() for kw in [
                "temp", "appdata", "recycle", "usb", "removable", "network", r"\\",
                "admin$", "c$", "system32", "powershell", "cmd.exe",
            ])
        ]

        for s in suspicious_paths:
            s["mitre_techniques"] = map_finding_to_techniques(
                f"shellbag folder access {str(s)}")
        enrich_findings(rag, suspicious_paths[:5],
                        lambda s: f"shellbag folder navigation {str(s)[:200]} T1083 T1021.002")

        data = {
            "ntuser_path": ntuser_path,
            "total_shellbag_entries": len(entries),
            "suspicious_path_accesses": suspicious_paths[:50],
            "all_entries": entries[:200],
            "forensic_note": (
                "Shellbags persist after the target folder is deleted. "
                "Network paths (\\\\server\\share) prove SMB access (T1021.002). "
                "Removable media paths prove USB/external drive access (T1052.001)."
            ),
            "rag_context": build_rag_summary(rag, "shellbag folder access lateral movement USB T1083 T1021.002"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_shellbags", data, audit_id)

    @mcp.tool()
    def parse_windows_timeline(wxt_db_path: str) -> str:
        """
        Parse the Windows 10/11 Activities Cache (Windows Timeline) using WxTCmd.

        The Activities Cache database records:
        - Applications launched with timestamps
        - Documents opened (with file paths)
        - Web pages visited (in Edge/IE)
        - Clipboard contents (if enabled)
        - Focus time per application

        This is one of the most comprehensive execution and file access records
        on Windows 10+, covering activity across reboots.

        Args:
            wxt_db_path: Path to ActivitiesCache.db.
                         Typically: Users/<user>/AppData/Local/ConnectedDevicesPlatform/
                         L.<username>/ActivitiesCache.db
        """
        increment_tool_counter()
        if not Path(wxt_db_path).exists():
            return json.dumps({"error": f"ActivitiesCache.db not found: {wxt_db_path}"})

        out_dir = str(EXPORTS_DIR)
        args = ["-f", wxt_db_path, "--csv", out_dir, "--csvf", "timeline.csv", "-q"]
        stdout, stderr = _run_ez("WxTCmd.exe", args)
        log_tool_execution("parse_windows_timeline", ["WxTCmd.exe"] + args, stdout, error=stderr)
        audit_id = get_last_audit_id()

        csv_file = EXPORTS_DIR / "timeline.csv"
        entries: list[dict] = []
        if csv_file.exists():
            entries = _parse_csv_output(csv_file.read_text(encoding="utf-8-sig", errors="replace"))

        # Categorise entries
        file_opens = [e for e in entries if e.get("ActivityType", "").lower() in ("open", "5")]
        app_launches = [e for e in entries if "launch" in e.get("ActivityType", "").lower() or e.get("ActivityType") == "6"]

        data = {
            "db_path": wxt_db_path,
            "total_activities": len(entries),
            "file_open_count": len(file_opens),
            "app_launch_count": len(app_launches),
            "file_opens": file_opens[:100],
            "app_launches": app_launches[:100],
            "all_activities": entries[:200],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_windows_timeline", data, audit_id)

    @mcp.tool()
    def parse_bam_dam(system_hive_path: str) -> str:
        """
        Parse Background Activity Moderator (BAM) and Desktop Activity Moderator (DAM)
        from the SYSTEM registry hive.

        BAM/DAM record the last execution time of every user-mode executable on
        Windows 10 version 1709+. Unlike Prefetch, BAM works even when Prefetch
        is disabled (e.g. on SSDs). Each entry has the executable path and last
        execution timestamp per user SID.

        Forensic value: proves execution of specific binaries even if Prefetch/
        Shimcache/Amcache have been cleared.

        Args:
            system_hive_path: Path to the SYSTEM hive file.
        """
        increment_tool_counter()
        if not Path(system_hive_path).exists():
            return json.dumps({"error": f"SYSTEM hive not found: {system_hive_path}"})

        # RECmd to extract BAM key
        bam_key = r"ControlSet001\Services\bam\State\UserSettings"
        stdout, stderr = _run_recmd(system_hive_path, bam_key, is_batch=False)
        log_tool_execution("parse_bam_dam", ["RECmd.exe", system_hive_path, bam_key], stdout, error=stderr)
        audit_id = get_last_audit_id()

        csv_file = EXPORTS_DIR / "regscan.csv"
        entries: list[dict] = []
        if csv_file.exists():
            entries = _parse_csv_output(csv_file.read_text(encoding="utf-8-sig", errors="replace"))

        # Flag suspicious executables
        suspicious = [
            e for e in entries
            if any(kw in str(e).lower() for kw in [
                "temp", r"\appdata", "powershell", "cmd", "wscript", "cscript",
                "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin",
            ])
        ]

        for s in suspicious:
            s["mitre_techniques"] = map_finding_to_techniques(f"execution BAM {str(s)[:200]}")
        enrich_findings(rag, suspicious[:5],
                        lambda s: f"BAM execution suspicious binary {str(s)[:200]}")

        data = {
            "system_hive_path": system_hive_path,
            "total_bam_entries": len(entries),
            "suspicious_executions": suspicious[:50],
            "all_entries": entries[:200],
            "forensic_note": (
                "BAM provides last-execution timestamps per user SID. "
                "Unlike Prefetch, BAM works on SSDs with SuperFetch disabled. "
                "Entries persist even after manual Prefetch deletion."
            ),
            "rag_context": build_rag_summary(rag, "BAM execution history registry persistence T1547"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_bam_dam", data, audit_id)

    @mcp.tool()
    def parse_typed_paths(ntuser_path: str) -> str:
        """
        Parse the Explorer TypedPaths MRU from NTUSER.DAT.

        TypedPaths records every path a user MANUALLY TYPED into the Windows
        Explorer address bar. This includes:
        - Network share paths (\\\\server\\share) — lateral movement indicator
        - External drive paths (D:\\, E:\\) — removable media access
        - Admin share access (\\\\server\\c$) — T1021.002

        Args:
            ntuser_path: Path to NTUSER.DAT hive.
        """
        increment_tool_counter()
        if not Path(ntuser_path).exists():
            return json.dumps({"error": f"NTUSER.DAT not found: {ntuser_path}"})

        key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
        stdout, stderr = _run_recmd(ntuser_path, key)
        log_tool_execution("parse_typed_paths", ["RECmd.exe", ntuser_path, key], stdout, error=stderr)
        audit_id = get_last_audit_id()

        csv_file = EXPORTS_DIR / "regscan.csv"
        entries: list[dict] = []
        if csv_file.exists():
            entries = _parse_csv_output(csv_file.read_text(encoding="utf-8-sig", errors="replace"))

        network_paths = [e for e in entries if "\\\\" in str(e)]
        removable = [e for e in entries if any(f"{d}:\\" in str(e) for d in "DEFGHIJKLMNOPQRSTUVWXYZ")]

        data = {
            "ntuser_path": ntuser_path,
            "total_typed_paths": len(entries),
            "network_share_paths": network_paths,
            "removable_media_paths": removable,
            "all_typed_paths": entries[:100],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_typed_paths", data, audit_id)

    @mcp.tool()
    def parse_run_mru(ntuser_path: str) -> str:
        """
        Parse the Run dialog MRU (Most Recently Used) list from NTUSER.DAT.

        The Run dialog MRU records every command typed into Windows+R. Attackers
        commonly use this to launch tools: cmd.exe, powershell.exe, mmc.exe,
        and remote paths (\\\\attacker\\share\\payload.exe).

        Args:
            ntuser_path: Path to NTUSER.DAT hive.
        """
        increment_tool_counter()
        if not Path(ntuser_path).exists():
            return json.dumps({"error": f"NTUSER.DAT not found: {ntuser_path}"})

        key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        stdout, stderr = _run_recmd(ntuser_path, key)
        log_tool_execution("parse_run_mru", ["RECmd.exe", ntuser_path, key], stdout, error=stderr)
        audit_id = get_last_audit_id()

        csv_file = EXPORTS_DIR / "regscan.csv"
        entries: list[dict] = []
        if csv_file.exists():
            entries = _parse_csv_output(csv_file.read_text(encoding="utf-8-sig", errors="replace"))

        suspicious = [
            e for e in entries
            if any(kw in str(e).lower() for kw in [
                "powershell", "cmd", "wscript", "mshta", "regsvr32",
                "rundll32", "certutil", "msiexec", "\\\\", "http",
                "base64", "-enc", "-nop", "-bypass",
            ])
        ]

        for s in suspicious:
            s["mitre_techniques"] = map_finding_to_techniques(f"run dialog command {str(s)[:200]}")
        enrich_findings(rag, suspicious[:5],
                        lambda s: f"Windows Run dialog command execution {str(s)[:200]} T1059")

        data = {
            "ntuser_path": ntuser_path,
            "total_run_mru_entries": len(entries),
            "suspicious_run_commands": suspicious,
            "all_run_mru": entries[:100],
            "rag_context": build_rag_summary(rag, "Windows Run MRU command execution T1059 T1547"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_run_mru", data, audit_id)

    @mcp.tool()
    def parse_open_save_mru(ntuser_path: str) -> str:
        """
        Parse the OpenSavePidlMRU and LastVisitedPidlMRU from NTUSER.DAT.

        These MRU lists record files accessed via the Windows Open/Save dialog,
        revealing which documents a user (or attacker) opened or saved, and which
        applications were used to open them. Critical for exfiltration investigation.

        Args:
            ntuser_path: Path to NTUSER.DAT hive.
        """
        increment_tool_counter()
        if not Path(ntuser_path).exists():
            return json.dumps({"error": f"NTUSER.DAT not found: {ntuser_path}"})

        key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
        stdout, stderr = _run_recmd(ntuser_path, key)
        log_tool_execution("parse_open_save_mru", ["RECmd.exe", ntuser_path, key], stdout, error=stderr)
        audit_id = get_last_audit_id()

        csv_file = EXPORTS_DIR / "regscan.csv"
        entries = _parse_csv_output(csv_file.read_text(encoding="utf-8-sig", errors="replace")) if (EXPORTS_DIR / "regscan.csv").exists() else []

        data = {
            "ntuser_path": ntuser_path,
            "total_open_save_entries": len(entries),
            "entries": entries[:200],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_open_save_mru", data, audit_id)

    @mcp.tool()
    def parse_wordwheelquery(ntuser_path: str) -> str:
        """
        Parse the Windows Search (WordWheelQuery) history from NTUSER.DAT.

        Records every search term entered in the Windows Start Menu search box
        or File Explorer search. Search terms reveal what an attacker was
        looking for on the system (T1083 — File and Directory Discovery).

        Args:
            ntuser_path: Path to NTUSER.DAT hive.
        """
        increment_tool_counter()
        if not Path(ntuser_path).exists():
            return json.dumps({"error": f"NTUSER.DAT not found: {ntuser_path}"})

        key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
        stdout, stderr = _run_recmd(ntuser_path, key)
        log_tool_execution("parse_wordwheelquery", ["RECmd.exe", ntuser_path, key], stdout, error=stderr)
        audit_id = get_last_audit_id()

        csv_file = EXPORTS_DIR / "regscan.csv"
        entries = _parse_csv_output(csv_file.read_text(encoding="utf-8-sig", errors="replace")) if (EXPORTS_DIR / "regscan.csv").exists() else []

        suspicious_searches = [
            e for e in entries
            if any(kw in str(e).lower() for kw in [
                "password", "secret", "confidential", "salary", "invoice",
                "vpn", "backup", ".kdbx", ".pfx", "private", "key",
                "source code", "intellectual", "proprietary",
            ])
        ]

        for s in suspicious_searches:
            s["mitre_techniques"] = map_finding_to_techniques(f"search discovery {str(s)[:200]} T1083")
        enrich_findings(rag, suspicious_searches[:5],
                        lambda s: f"Windows search query sensitive file discovery {str(s)[:200]} T1083")

        data = {
            "ntuser_path": ntuser_path,
            "total_search_terms": len(entries),
            "suspicious_searches": suspicious_searches,
            "all_search_terms": entries[:100],
            "rag_context": build_rag_summary(rag, "Windows search sensitive file discovery T1083"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_wordwheelquery", data, audit_id)

    @mcp.tool()
    def parse_installed_software(software_hive_path: str) -> str:
        """
        Parse the installed software inventory from the SOFTWARE registry hive.

        Returns: all installed programs (name, version, install date, publisher,
        install path), with flags for remote access tools, hacking utilities,
        and recently installed software relative to the incident date.

        Args:
            software_hive_path: Path to the SOFTWARE hive file.
        """
        increment_tool_counter()
        if not Path(software_hive_path).exists():
            return json.dumps({"error": f"SOFTWARE hive not found: {software_hive_path}"})

        key = r"Microsoft\Windows\CurrentVersion\Uninstall"
        stdout, stderr = _run_recmd(software_hive_path, key)
        log_tool_execution("parse_installed_software", ["RECmd.exe", software_hive_path, key], stdout, error=stderr)
        audit_id = get_last_audit_id()

        csv_file = EXPORTS_DIR / "regscan.csv"
        entries = _parse_csv_output(csv_file.read_text(encoding="utf-8-sig", errors="replace")) if (EXPORTS_DIR / "regscan.csv").exists() else []

        _RAT_KEYWORDS = {
            "anydesk", "teamviewer", "logmein", "radmin", "ammyy", "dameware",
            "vnc", "ultraviewer", "ncat", "netcat", "nmap", "masscan",
            "metasploit", "cobalt", "empire", "pupy", "mimikatz", "procdump",
            "wireshark", "rawcap", "sysinternals", "pskill", "psexec",
        }
        rat_software = [e for e in entries if any(kw in str(e).lower() for kw in _RAT_KEYWORDS)]

        for r in rat_software:
            r["mitre_techniques"] = map_finding_to_techniques(f"remote access tool {str(r)[:200]}")
        enrich_findings(rag, rat_software[:5],
                        lambda r: f"remote access tool installed {str(r)[:200]} T1219 T1021")

        data = {
            "software_hive_path": software_hive_path,
            "total_installed_programs": len(entries),
            "suspicious_software": rat_software,
            "all_software": entries[:300],
            "rag_context": build_rag_summary(rag, "remote access tool RAT installed software T1219 T1021"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_installed_software", data, audit_id)

    @mcp.tool()
    def parse_sam_hive(sam_hive_path: str) -> str:
        """
        Parse the SAM (Security Account Manager) hive for local user account forensics.

        Returns: local user accounts, account creation timestamps, last logon times,
        login failure counts, and account status (enabled/disabled/locked).

        NOTE: Password hashes are NOT extracted by this tool (requires SYSTEM key
        from SYSTEM hive + impacket/secretsdump — use get_hashdump via Volatility
        for memory-resident hash extraction instead).

        Args:
            sam_hive_path: Path to the SAM hive file.
        """
        increment_tool_counter()
        if not Path(sam_hive_path).exists():
            return json.dumps({"error": f"SAM hive not found: {sam_hive_path}"})

        key = r"SAM\Domains\Account\Users"
        stdout, stderr = _run_recmd(sam_hive_path, key)
        log_tool_execution("parse_sam_hive", ["RECmd.exe", sam_hive_path, key], stdout, error=stderr)
        audit_id = get_last_audit_id()

        csv_file = EXPORTS_DIR / "regscan.csv"
        entries = _parse_csv_output(csv_file.read_text(encoding="utf-8-sig", errors="replace")) if (EXPORTS_DIR / "regscan.csv").exists() else []

        data = {
            "sam_hive_path": sam_hive_path,
            "total_account_entries": len(entries),
            "entries": entries[:100],
            "note": "Password hashes require SYSTEM hive key. Use get_hashdump for memory-based extraction.",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_sam_hive", data, audit_id)

    @mcp.tool()
    def parse_logon_history(security_hive_path: str) -> str:
        """
        Parse the SECURITY hive for cached domain credentials and logon history.

        The SECURITY hive stores:
        - Cached domain logon credentials (DCC2 hashes) — proves domain accounts logged in
        - LSA secrets (service account passwords, auto-logon credentials)
        - Domain account last logon timestamps

        Args:
            security_hive_path: Path to the SECURITY hive file.
        """
        increment_tool_counter()
        if not Path(security_hive_path).exists():
            return json.dumps({"error": f"SECURITY hive not found: {security_hive_path}"})

        key = r"Cache"
        stdout, stderr = _run_recmd(security_hive_path, key)
        log_tool_execution("parse_logon_history", ["RECmd.exe", security_hive_path, key], stdout, error=stderr)
        audit_id = get_last_audit_id()

        csv_file = EXPORTS_DIR / "regscan.csv"
        entries = _parse_csv_output(csv_file.read_text(encoding="utf-8-sig", errors="replace")) if (EXPORTS_DIR / "regscan.csv").exists() else []

        data = {
            "security_hive_path": security_hive_path,
            "total_cache_entries": len(entries),
            "entries": entries[:100],
            "forensic_note": (
                "Cached logon credentials (DCC2) prove domain accounts previously authenticated "
                "on this machine. Each entry = a user who logged in while domain-connected. "
                "Presence of unexpected accounts indicates unauthorized access."
            ),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_logon_history", data, audit_id)
