"""
EZ Tools / Windows artifact MCP tool wrappers.
One function = one typed MCP tool.

Every response includes audit_id (chain-of-custody) plus forensic knowledge envelope.
"""
import csv as _csv
import json
import subprocess
from pathlib import Path

from mcp_server.config import EZ_TOOLS_DIR, EXPORTS_DIR, MAX_TOOL_TIMEOUT
from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter
from mcp_server.parsers.mitre_auto_map import map_event_id, map_finding_to_techniques
from mcp_server.parsers.forensic_knowledge import wrap_response


_SUSPICIOUS_DIRS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
    "\\appdata\\roaming\\", "\\downloads\\", "\\desktop\\",
    "\\recycler\\", "\\$recycle.bin\\", "\\windows\\temp\\",
    "\\programdata\\", "\\users\\public\\",
)
_EXEC_EXTS = (".exe", ".dll", ".ps1", ".bat", ".vbs", ".cmd", ".com", ".scr", ".hta")


def _is_suspicious_path(path: str) -> bool:
    p = path.lower()
    return (
        any(d in p for d in _SUSPICIOUS_DIRS)
        and any(p.endswith(ext) for ext in _EXEC_EXTS)
    )


def _categorize_events(events: list[dict]) -> dict:
    cats: dict[str, list] = {
        "failed_logons": [],
        "privileged_logons": [],
        "explicit_credential_logons": [],
        "service_installs": [],
        "scheduled_task_creates": [],
        "powershell_script_blocks": [],
        "wmi_persistence": [],
        "rdp_sessions": [],
    }
    for e in events:
        eid = str(e.get("event_id", ""))
        if eid == "4625":
            cats["failed_logons"].append(e)
        elif eid == "4672":
            cats["privileged_logons"].append(e)
        elif eid == "4648":
            cats["explicit_credential_logons"].append(e)
        elif eid in ("7045", "4697"):
            cats["service_installs"].append(e)
        elif eid in ("4698", "106"):
            cats["scheduled_task_creates"].append(e)
        elif eid in ("4103", "4104"):
            cats["powershell_script_blocks"].append(e)
        elif eid in ("5860", "5861"):
            cats["wmi_persistence"].append(e)
        elif eid in ("4778", "4779", "1149"):
            cats["rdp_sessions"].append(e)
    return {k: v[:20] for k, v in cats.items()}


def _run(cmd: list[str], tool_name: str) -> tuple[str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
        log_tool_execution(tool_name, cmd, result.stdout, error=result.stderr)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        msg = f"'{tool_name}' timed out"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg
    except FileNotFoundError:
        msg = f"Tool not found: {cmd[0]}. Check EZ_TOOLS_DIR in .env"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg


def _ez(tool: str) -> list[str]:
    """Resolve an EZ Tool to an executable command list.

    On Windows the native ``<Tool>.exe`` is used directly. On SANS SIFT (Linux)
    the tools ship as .NET assemblies, so ``<Tool>.dll`` (which may live in a
    subdirectory, e.g. ``EvtxeCmd/EvtxECmd.dll``) is run via ``dotnet``. Returns a
    command-prefix list so call sites do ``_ez("Tool.exe") + [args...]``.
    """
    import os
    name = tool[:-4] if tool.lower().endswith(".exe") else tool
    exe = EZ_TOOLS_DIR / f"{name}.exe"
    # Only exec the native .exe on Windows — on Linux those PE launchers can't run.
    if os.name == "nt" and exe.exists():
        return [str(exe)]
    hits = list(EZ_TOOLS_DIR.glob(f"**/{name}.dll"))
    if hits:
        return ["dotnet", str(hits[0])]
    if exe.exists():
        return [str(exe)]
    # Fall back to a top-level dll path; _run() reports a clear error if missing.
    return ["dotnet", str(EZ_TOOLS_DIR / f"{name}.dll")]


def _read_csv_dir(output_dir: str, max_rows: int = 500) -> list[dict]:
    """Read all CSV files from a directory, return combined rows (up to max_rows)."""
    rows: list[dict] = []
    p = Path(output_dir)
    if not p.exists():
        return rows
    for csv_file in sorted(p.glob("*.csv")):
        try:
            with open(csv_file, encoding="utf-8-sig") as f:
                rows.extend(list(_csv.DictReader(f)))
            if len(rows) >= max_rows:
                return rows[:max_rows]
        except Exception:
            continue
    return rows[:max_rows]


def register_windows_artifact_tools(mcp, rag=None):

    @mcp.tool()
    def parse_event_logs(evtx_dir: str, event_ids: str = "") -> str:
        """
        Parse Windows Event Log (.evtx) files using EvtxECmd.

        Default filter covers: logon/logoff (4624/4625/4648/4672), service installs (7045),
        scheduled tasks (4698-4702), PowerShell script blocks (4103/4104),
        WMI persistence (5860/5861), RDP (4778/4779).

        Args:
            evtx_dir:  Path to directory containing .evtx files.
            event_ids: Comma-separated event IDs to include. Empty = default IR set.
        """
        output_dir = str(EXPORTS_DIR / "evtx")
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        DEFAULT_IDS = (
            "4624,4625,4634,4647,4648,4672,4688,4697,4698,4699,4700,4701,4702,"
            "4720,4726,5857,5860,5861,7034,7035,7036,7040,7045,4103,4104,4778,4779,1149"
        )
        filter_ids = event_ids.strip() if event_ids.strip() else DEFAULT_IDS

        cmd = _ez("EvtxECmd.exe") + [ "-d", evtx_dir,
            "--csv", output_dir, "--csvf", "evtx_output.csv",
            "--inc", filter_ids,
        ]
        _run(cmd, "parse_event_logs")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        events = []
        for csv_file in sorted(Path(output_dir).glob("*.csv")):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    for row in _csv.DictReader(f):
                        events.append({
                            "timestamp": row.get("TimeCreated", ""),
                            "event_id": row.get("EventId", ""),
                            "level": row.get("Level", ""),
                            "channel": row.get("Channel", ""),
                            "computer": row.get("Computer", ""),
                            "user_name": row.get("UserName", ""),
                            "map_description": row.get("MapDescription", ""),
                            "payload_data1": row.get("PayloadData1", "")[:300],
                            "payload_data2": row.get("PayloadData2", "")[:300],
                        })
            except Exception:
                continue

        events.sort(key=lambda x: x.get("timestamp", ""))
        summary = _categorize_events(events)

        mitre_by_category: dict[str, dict] = {}
        for eid_str in filter_ids.split(","):
            eid = eid_str.strip()
            if eid:
                for m in map_event_id(eid):
                    mitre_by_category.setdefault(m["technique_id"], m)

        rag_context = ""
        if rag:
            if summary.get("service_installs"):
                rag_context += rag.query("malicious service installation persistence T1543")
            if summary.get("failed_logons"):
                rag_context += rag.query("brute force failed logon T1110")

        data = {
            "total_events": len(events),
            "summary": summary,
            "mitre_techniques": list(mitre_by_category.values()),
            "rag_context": rag_context,
            "events": events[:500],
        }
        return wrap_response("parse_event_logs", data, audit_id)

    @mcp.tool()
    def parse_shimcache(system_hive_path: str) -> str:
        """
        Parse Application Compatibility Cache (Shimcache) from SYSTEM registry hive.

        On Windows 8+: proves executable EXISTED on disk, not that it ran.
        Location: SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache

        Args:
            system_hive_path: Path to extracted SYSTEM hive file.
        """
        output_dir = str(EXPORTS_DIR / "shimcache")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("AppCompatCacheParser.exe") + ["-f", system_hive_path, "--csv", output_dir]
        _run(cmd, "parse_shimcache")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = []
        for csv_file in Path(output_dir).glob("*.csv"):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    for row in _csv.DictReader(f):
                        entries.append({
                            "path": row.get("Path", ""),
                            "last_modified_utc": row.get("LastModifiedTimeUTC", ""),
                            "executed": row.get("Executed", ""),
                        })
            except Exception:
                continue

        suspicious = [e for e in entries if _is_suspicious_path(e.get("path", ""))]
        for e in suspicious:
            e["mitre_techniques"] = map_finding_to_techniques(
                f"executable in temp appdata suspicious path {e.get('path', '')}"
            )

        data = {
            "total_shimcache_entries": len(entries),
            "suspicious_entries": suspicious[:50],
            "all_entries": entries[:500],
        }
        return wrap_response("parse_shimcache", data, audit_id)

    @mcp.tool()
    def parse_amcache(amcache_path: str) -> str:
        """
        Parse Amcache.hve to recover executable metadata including SHA1 hashes.

        Amcache records every executed program with path and SHA1 (use for VirusTotal lookup).
        Location: C:\\Windows\\AppCompat\\Programs\\Amcache.hve

        Args:
            amcache_path: Path to the Amcache.hve file.
        """
        output_dir = str(EXPORTS_DIR / "amcache")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("AmcacheParser.exe") + ["-f", amcache_path, "--csv", output_dir]
        _run(cmd, "parse_amcache")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = []
        for csv_file in Path(output_dir).glob("*.csv"):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    for row in _csv.DictReader(f):
                        entries.append({
                            "path": row.get("FullPath", ""),
                            "first_run_utc": row.get("FileIDLastWriteTimestamp", ""),
                            "sha1": row.get("SHA1", ""),
                            "file_description": row.get("FileDescription", ""),
                            "product_name": row.get("ProductName", ""),
                            "company_name": row.get("CompanyName", ""),
                        })
            except Exception:
                continue

        suspicious = [e for e in entries if _is_suspicious_path(e.get("path", ""))]
        data = {
            "total_amcache_entries": len(entries),
            "suspicious_entries": suspicious[:50],
            "all_entries": entries[:500],
        }
        return wrap_response("parse_amcache", data, audit_id)

    @mcp.tool()
    def parse_prefetch(prefetch_dir: str) -> str:
        """
        Parse Windows Prefetch files to recover program execution history.

        Records last 8 run times per executable. Proves execution (unlike Shimcache).
        Location: C:\\Windows\\Prefetch\\

        Args:
            prefetch_dir: Path to directory containing .pf files.
        """
        output_dir = str(EXPORTS_DIR / "prefetch")
        cmd = _ez("PECmd.exe") + ["-d", prefetch_dir, "--csv", output_dir]
        _run(cmd, "parse_prefetch")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = []
        for csv_file in (Path(output_dir).glob("*.csv") if Path(output_dir).exists() else []):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    for row in _csv.DictReader(f):
                        entries.append({
                            "executable": row.get("ExecutableName", ""),
                            "run_count": row.get("RunCount", ""),
                            "last_run": row.get("LastRun", ""),
                            "previous_runs": row.get("PreviousRun0", ""),
                            "volume_name": row.get("VolumeSerialNumber", ""),
                        })
            except Exception:
                continue

        data = {
            "total_prefetch_entries": len(entries),
            "entries": sorted(entries, key=lambda x: x.get("last_run", ""), reverse=True)[:100],
        }
        return wrap_response("parse_prefetch", data, audit_id)

    @mcp.tool()
    def parse_mft(mft_path: str) -> str:
        """
        Parse the NTFS Master File Table ($MFT) for full file-system timeline.

        Detects timestamp anomalies (modified before created = copied from elsewhere).
        Returns only executables and scripts for conciseness.

        Args:
            mft_path: Path to extracted $MFT file from evidence volume.
        """
        output_dir = str(EXPORTS_DIR / "mft")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("MFTECmd.exe") + ["-f", mft_path, "--csv", output_dir]
        _run(cmd, "parse_mft")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = []
        for csv_file in Path(output_dir).glob("*.csv"):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    for row in _csv.DictReader(f):
                        file_name = row.get("FileName", "")
                        ext = file_name.lower().rsplit(".", 1)[-1] if "." in file_name else ""
                        if ext not in ("exe", "dll", "sys", "bat", "ps1", "vbs", "js", "cmd", "com", "scr", "hta"):
                            continue
                        entry = {
                            "file_name": file_name,
                            "parent_path": row.get("ParentPath", ""),
                            "created_0x10": row.get("Created0x10", ""),
                            "created_0x30": row.get("Created0x30", ""),
                            "last_modified_0x10": row.get("LastModified0x10", ""),
                            "last_modified_0x30": row.get("LastModified0x30", ""),
                            "in_use": row.get("InUse", "True"),
                            "file_size": row.get("FileSize", ""),
                        }
                        try:
                            if (entry["last_modified_0x10"] and entry["created_0x10"]
                                    and entry["last_modified_0x10"] < entry["created_0x10"]):
                                entry["timestamp_anomaly"] = True
                        except Exception:
                            pass
                        entries.append(entry)
            except Exception:
                continue

        anomalies = [e for e in entries if e.get("timestamp_anomaly")]
        deleted = [e for e in entries if e.get("in_use") == "False"]

        data = {
            "total_executable_entries": len(entries),
            "timestamp_anomalies_count": len(anomalies),
            "deleted_executables_count": len(deleted),
            "timestamp_anomalies": anomalies[:50],
            "deleted_executables": deleted[:50],
            "all_entries": entries[:500],
        }
        return wrap_response("parse_mft", data, audit_id)

    @mcp.tool()
    def parse_lnk_files(lnk_dir: str) -> str:
        """
        Parse Windows LNK (shortcut) files to recover recently accessed file paths.

        LNK files record target path, timestamps, and volume information.
        Found in Recent Items (AppData\\Roaming\\Microsoft\\Windows\\Recent).

        Args:
            lnk_dir: Path to directory containing .lnk files.
        """
        output_dir = str(EXPORTS_DIR / "lnk")
        cmd = _ez("LECmd.exe") + ["-d", lnk_dir, "--csv", output_dir]
        _run(cmd, "parse_lnk_files")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = []
        for csv_file in (Path(output_dir).glob("*.csv") if Path(output_dir).exists() else []):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    for row in _csv.DictReader(f):
                        entries.append({
                            "source_file": row.get("SourceFile", ""),
                            "target_path": row.get("LocalPath", ""),
                            "network_path": row.get("NetworkPath", ""),
                            "created": row.get("TargetCreated", ""),
                            "modified": row.get("TargetModified", ""),
                            "accessed": row.get("TargetAccessed", ""),
                        })
            except Exception:
                continue

        data = {"total_lnk_files": len(entries), "entries": entries[:100]}
        return wrap_response("parse_lnk_files", data, audit_id)

    @mcp.tool()
    def parse_jump_lists(jumplist_dir: str) -> str:
        """
        Parse Windows Jump List files for recent file and application activity.

        Jump Lists are stored at:
        AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\
        AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\

        Args:
            jumplist_dir: Path to directory containing jump list files.
        """
        output_dir = str(EXPORTS_DIR / "jumplists")
        cmd = _ez("JLECmd.exe") + ["-d", jumplist_dir, "--csv", output_dir]
        _run(cmd, "parse_jump_lists")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = _read_csv_dir(output_dir)
        data = {"total_jumplist_entries": len(entries), "entries": entries[:100]}
        return json.dumps(data, default=str)

    @mcp.tool()
    def parse_registry_hive(hive_path: str, search_pattern: str = "") -> str:
        """
        Parse a registry hive file using RECmd.

        Args:
            hive_path:      Absolute path to the hive file (NTUSER.DAT, SOFTWARE, SYSTEM, etc.).
            search_pattern: Optional keyword to search within key names or values.
        """
        output_dir = str(EXPORTS_DIR / "registry")
        cmd = _ez("RECmd.exe") + ["-f", hive_path, "--csv", output_dir]
        if search_pattern:
            cmd += ["--sk", search_pattern]

        _run(cmd, "parse_registry_hive")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = []
        for csv_file in (Path(output_dir).glob("*.csv") if Path(output_dir).exists() else []):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    for row in _csv.DictReader(f):
                        entries.append({
                            "key_path": row.get("KeyPath", ""),
                            "value_name": row.get("ValueName", ""),
                            "value_type": row.get("ValueType", ""),
                            "value_data": row.get("ValueData", "")[:500],
                            "last_write": row.get("LastWriteTimestamp", ""),
                        })
            except Exception:
                continue

        data = {
            "hive": hive_path, "search_pattern": search_pattern,
            "total_entries": len(entries), "entries": entries[:200],
        }
        return json.dumps(data, default=str)

    @mcp.tool()
    def parse_recycle_bin(recycle_bin_path: str) -> str:
        """
        Parse Windows Recycle Bin $I files to recover deleted file metadata.

        Location: C:\\$Recycle.Bin\\<user-SID>\\

        Args:
            recycle_bin_path: Path to $Recycle.Bin directory or SID subdirectory.
        """
        output_dir = str(EXPORTS_DIR / "recycle_bin")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("RBCmd.exe") + ["-d", recycle_bin_path, "--csv", output_dir]
        _run(cmd, "parse_recycle_bin")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = []
        for csv_file in Path(output_dir).glob("*.csv"):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    for row in _csv.DictReader(f):
                        entries.append({
                            "original_path": row.get("FileName", ""),
                            "deleted_on": row.get("DeletedOn", ""),
                            "file_size": row.get("FileSize", ""),
                            "source_file": row.get("SourceFile", ""),
                        })
            except Exception:
                continue

        suspicious = [e for e in entries if _is_suspicious_path(e.get("original_path", ""))]
        data = {
            "total_deleted_files": len(entries),
            "suspicious_deleted_files": suspicious[:50],
            "all_deleted_files": entries[:200],
        }
        return wrap_response("parse_recycle_bin", data, audit_id)

    @mcp.tool()
    def parse_srum(srum_path: str) -> str:
        """
        Parse the System Resource Usage Monitor (SRUM) database.

        SRUM records per-application network usage (bytes sent/received), CPU time,
        and energy consumption. Stored at C:\\Windows\\System32\\sru\\SRUDB.dat.

        Use to confirm data exfiltration volume per cloud service app.
        Critical for ROCBA-style cases where cloud sync services are suspected exfil channels.

        Args:
            srum_path: Absolute path to SRUDB.dat extracted from the evidence volume.
        """
        output_dir = str(EXPORTS_DIR / "srum")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("SrumECmd.exe") + ["-f", srum_path, "--csv", output_dir]
        _run(cmd, "parse_srum")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        # SrumECmd outputs multiple CSVs: NetworkUsage, AppResourceUseInfo, etc.
        network_usage: list[dict] = []
        app_usage: list[dict] = []

        for csv_file in Path(output_dir).glob("*.csv"):
            fname = csv_file.name.lower()
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    rows = list(_csv.DictReader(f))
            except Exception:
                continue

            if "networkusage" in fname:
                for row in rows:
                    app = row.get("AppId", row.get("ExeInfo", ""))
                    network_usage.append({
                        "timestamp": row.get("TimeStamp", row.get("Timestamp", "")),
                        "app": app,
                        "bytes_sent": row.get("BytesSent", row.get("BackgroundBytesSent", "0")),
                        "bytes_received": row.get("BytesRecvd", row.get("BackgroundBytesRecvd", "0")),
                        "interface": row.get("InterfaceType", row.get("L2ProfileId", "")),
                    })
            elif "appresource" in fname or "appuse" in fname:
                for row in rows:
                    app_usage.append({
                        "timestamp": row.get("TimeStamp", row.get("Timestamp", "")),
                        "app": row.get("AppId", row.get("ExeInfo", "")),
                        "cpu_time_ms": row.get("CpuTimeInMs", ""),
                        "background_bytes_sent": row.get("BackgroundBytesSent", ""),
                        "background_bytes_received": row.get("BackgroundBytesRecvd", ""),
                        "foreground_bytes_sent": row.get("ForegroundBytesSent", ""),
                        "foreground_bytes_received": row.get("ForegroundBytesRecvd", ""),
                    })

        # Aggregate by app for network usage
        by_app: dict[str, dict] = {}
        for rec in network_usage:
            app = rec["app"]
            if app not in by_app:
                by_app[app] = {"app": app, "total_bytes_sent": 0, "total_bytes_received": 0, "records": 0}
            try:
                by_app[app]["total_bytes_sent"] += int(rec.get("bytes_sent") or 0)
                by_app[app]["total_bytes_received"] += int(rec.get("bytes_received") or 0)
                by_app[app]["records"] += 1
            except (ValueError, TypeError):
                pass

        network_summary = sorted(
            by_app.values(),
            key=lambda x: x["total_bytes_sent"] + x["total_bytes_received"],
            reverse=True,
        )[:30]

        data = {
            "network_usage_records": len(network_usage),
            "app_usage_records": len(app_usage),
            "network_usage_by_app": network_summary,
            "network_usage_raw": network_usage[:200],
            "app_resource_usage": app_usage[:200],
            "investigation_note": (
                "High bytes_sent for OneDrive/GoogleDrive/Dropbox/iCloud confirms data exfiltration surface. "
                "Cross-reference timestamps with parse_event_logs logon sessions."
            ),
        }
        return wrap_response("parse_srum", data, audit_id)

    @mcp.tool()
    def parse_usn_journal(usn_path: str) -> str:
        """
        Parse the NTFS USN Change Journal ($UsnJrnl:$J) for file system activity.

        The USN Journal records every file create, modify, rename, and delete operation.
        Critical for detecting anti-forensic cleanup (burst deletions after incident).

        Location: Extract $Extend\\$UsnJrnl:$J from the evidence volume.
        Use MFTECmd.exe syntax: MFTECmd.exe -f "$J" --csv output/

        Args:
            usn_path: Absolute path to the extracted $UsnJrnl:$J file.
        """
        output_dir = str(EXPORTS_DIR / "usn_journal")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("MFTECmd.exe") + ["-f", usn_path, "--csv", output_dir]
        _run(cmd, "parse_usn_journal")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries: list[dict] = []
        for csv_file in Path(output_dir).glob("*.csv"):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    for row in _csv.DictReader(f):
                        reason = row.get("Reason", row.get("UpdateReasons", ""))
                        name = row.get("Name", row.get("FileName", ""))
                        entries.append({
                            "timestamp": row.get("UpdateTimestamp", row.get("TimeStamp", "")),
                            "name": name,
                            "parent_path": row.get("ParentPath", ""),
                            "reason": reason,
                            "entry_number": row.get("EntryNumber", ""),
                        })
            except Exception:
                continue

        # Identify suspicious patterns
        deletions = [e for e in entries if "FILE_DELETE" in e.get("reason", "") or "Delete" in e.get("reason", "")]
        suspicious_deletions = [
            e for e in deletions
            if any(ext in e.get("name", "").lower() for ext in (".log", ".evtx", ".exe", ".dll", ".ps1"))
        ]

        # Detect burst deletions (many deletes in a short window)
        burst_threshold = 10
        burst_windows: list[dict] = []
        if len(deletions) >= burst_threshold:
            times = sorted(e.get("timestamp", "") for e in deletions if e.get("timestamp"))
            if times:
                burst_windows.append({
                    "first_deletion": times[0],
                    "last_deletion": times[-1],
                    "total_deletions": len(deletions),
                    "suspicious": len(deletions) >= burst_threshold,
                })

        data = {
            "total_usn_entries": len(entries),
            "total_deletions": len(deletions),
            "suspicious_file_deletions": suspicious_deletions[:50],
            "burst_deletion_windows": burst_windows,
            "all_entries": entries[:500],
            "investigation_note": (
                "Burst deletions of .log/.evtx/.exe files shortly after incident window "
                "indicate anti-forensic cleanup (T1070). "
                "Cross-reference timestamps with parse_event_logs logon sessions."
            ),
        }
        return wrap_response("parse_usn_journal", data, audit_id)

    @mcp.tool()
    def lookup_ip_reputation(ip_address: str) -> str:
        """
        Check an IP address against AbuseIPDB and VirusTotal threat intelligence.

        Run this for every external IP found by get_network_connections.

        Args:
            ip_address: IPv4 or IPv6 address to check.
        """
        import requests
        from mcp_server.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY

        increment_tool_counter()
        result: dict = {"ip": ip_address, "abuseipdb": None, "virustotal": None}

        if ABUSEIPDB_API_KEY:
            try:
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
                    params={"ipAddress": ip_address, "maxAgeInDays": 90},
                    timeout=10,
                )
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    result["abuseipdb"] = {
                        "abuse_confidence_score": d.get("abuseConfidenceScore"),
                        "country": d.get("countryCode"),
                        "isp": d.get("isp"),
                        "total_reports": d.get("totalReports"),
                        "last_reported": d.get("lastReportedAt"),
                        "is_whitelisted": d.get("isWhitelisted"),
                    }
            except Exception as e:
                result["abuseipdb"] = {"error": str(e)}

        if VIRUSTOTAL_API_KEY:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                    timeout=10,
                )
                if r.status_code == 200:
                    attrs = r.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    result["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "country": attrs.get("country"),
                        "as_owner": attrs.get("as_owner"),
                        "reputation": attrs.get("reputation"),
                    }
            except Exception as e:
                result["virustotal"] = {"error": str(e)}

        return wrap_response("lookup_ip_reputation", result)

    @mcp.tool()
    def parse_userassist(ntuser_path: str) -> str:
        """
        Parse UserAssist registry keys from NTUSER.DAT to recover GUI program
        execution history with run counts and last execution timestamps.

        UserAssist proves GUI execution (not just file existence) and provides
        run counts — useful for showing repeated attacker tool usage (T1059, T1036).

        Args:
            ntuser_path: Path to the NTUSER.DAT hive file for a specific user.
        """
        output_dir = str(EXPORTS_DIR / "userassist")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        batch_file = str(EZ_TOOLS_DIR / "BatchExamples" / "UserAssist.reb")
        cmd = _ez("RECmd.exe") + ["-f", ntuser_path, "--bn", batch_file, "--csv", output_dir]
        _run(cmd, "parse_userassist")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = _read_csv_dir(output_dir)
        useful = []
        for row in entries:
            path = row.get("ValueName", row.get("Path", ""))
            count = row.get("RunCounter", row.get("Count", ""))
            last_run = row.get("LastExecuted", row.get("LastWriteTimestamp", ""))
            if path:
                useful.append({"path": path, "run_count": count, "last_run": last_run,
                               "suspicious": _is_suspicious_path(path)})

        suspicious = [e for e in useful if e.get("suspicious")]
        data = {
            "total_userassist_entries": len(useful),
            "suspicious_entries": suspicious[:50],
            "all_entries": useful[:200],
        }
        return wrap_response("parse_userassist", data, audit_id)

    @mcp.tool()
    def parse_recentdocs(ntuser_path: str) -> str:
        """
        Parse RecentDocs registry keys to recover recently accessed document paths.

        RecentDocs records files opened via Explorer/file dialogs — reveals
        documents staged for exfiltration or accessed by the attacker (T1083, T1567).

        Args:
            ntuser_path: Path to the NTUSER.DAT hive file for a specific user.
        """
        output_dir = str(EXPORTS_DIR / "recentdocs")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("RECmd.exe") + [ "-f", ntuser_path,
            "--kn", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            "--csv", output_dir,
        ]
        _run(cmd, "parse_recentdocs")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = _read_csv_dir(output_dir)
        data = {
            "total_recentdocs": len(entries),
            "entries": entries[:200],
        }
        return wrap_response("parse_recentdocs", data, audit_id)

    @mcp.tool()
    def parse_network_history(system_hive_path: str) -> str:
        """
        Parse network connection history from the SYSTEM registry hive.

        Records WiFi SSIDs, wired connections, and connection timestamps.
        Reveals if the compromised machine connected to attacker-controlled
        networks or changed network profiles during the incident (T1020, T1048).

        Args:
            system_hive_path: Path to the SYSTEM hive file.
        """
        output_dir = str(EXPORTS_DIR / "network_history")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("RECmd.exe") + [ "-f", system_hive_path,
            "--kn", "CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
            "--csv", output_dir,
        ]
        _run(cmd, "parse_network_history")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = _read_csv_dir(output_dir)
        data = {
            "total_network_entries": len(entries),
            "entries": entries[:200],
        }
        return wrap_response("parse_network_history", data, audit_id)

    @mcp.tool()
    def parse_usb_history(system_hive_path: str) -> str:
        """
        Parse USB device connection history from the SYSTEM registry hive.

        Records device serial numbers, friendly names, first/last connection times.
        USB connections during the incident window may indicate physical data
        exfiltration (T1052.001) or hardware implants.

        Args:
            system_hive_path: Path to the SYSTEM hive file.
        """
        output_dir = str(EXPORTS_DIR / "usb_history")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("RECmd.exe") + [ "-f", system_hive_path,
            "--kn", "CurrentControlSet\\Enum\\USBSTOR",
            "--csv", output_dir,
        ]
        _run(cmd, "parse_usb_history")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = _read_csv_dir(output_dir)
        data = {
            "total_usb_devices": len(entries),
            "entries": entries[:100],
            "note": "Cross-reference connection timestamps with logon events (4624) "
                    "to identify which user account was active during USB insertion.",
        }
        return wrap_response("parse_usb_history", data, audit_id)
