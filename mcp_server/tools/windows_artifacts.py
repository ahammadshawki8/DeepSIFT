"""EZ Tools / Windows artifact MCP tool wrappers."""
from __future__ import annotations
import json
import subprocess
from pathlib import Path

from mcp_server.config import EZ_TOOLS_DIR, EXPORTS_DIR, MAX_TOOL_TIMEOUT
from mcp_server.audit import log_tool_execution


_SUSPICIOUS_DIRS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
    "\\appdata\\roaming\\", "\\downloads\\", "\\desktop\\",
    "\\recycler\\", "\\$recycle.bin\\", "\\windows\\temp\\",
    "\\programdata\\", "\\users\\public\\",
)
_EXEC_EXTS = (".exe", ".dll", ".ps1", ".bat", ".vbs", ".cmd", ".com", ".scr", ".hta")


def _is_suspicious_path(path: str) -> bool:
    """Flag executables/scripts found in user-writable or temp locations."""
    p = path.lower()
    return (
        any(d in p for d in _SUSPICIOUS_DIRS)
        and any(p.endswith(ext) for ext in _EXEC_EXTS)
    )


def _categorize_events(events: list[dict]) -> dict:
    """Group parsed event log entries into IR-relevant categories."""
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


def _ez(tool: str) -> str:
    return str(EZ_TOOLS_DIR / tool)


def register_windows_artifact_tools(mcp, rag=None):

    @mcp.tool()
    def parse_prefetch(prefetch_dir: str) -> str:
        """
        Parses Windows Prefetch files to recover program execution history.

        Prefetch files record the last 8 run times and file paths accessed.
        Critical for proving what programs ran on a system and when.
        Prefetch is located at C:\\Windows\\Prefetch\\ on the evidence volume.

        Args:
            prefetch_dir: Path to the directory containing .pf files.
        """
        output_dir = str(EXPORTS_DIR / "prefetch")
        cmd = [_ez("PECmd.exe"), "-d", prefetch_dir, "--csv", output_dir]
        stdout, stderr = _run(cmd, "parse_prefetch")

        output_path = Path(output_dir)
        csv_files = list(output_path.glob("*.csv")) if output_path.exists() else []

        entries = []
        for csv_file in csv_files:
            try:
                import csv as _csv
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        entries.append({
                            "executable": row.get("ExecutableName", ""),
                            "run_count": row.get("RunCount", ""),
                            "last_run": row.get("LastRun", ""),
                            "previous_runs": row.get("PreviousRun0", ""),
                            "volume_name": row.get("VolumeSerialNumber", ""),
                        })
            except Exception:
                continue

        return json.dumps({
            "total_prefetch_entries": len(entries),
            "entries": sorted(entries, key=lambda x: x.get("last_run", ""), reverse=True)[:100],
        }, default=str)

    @mcp.tool()
    def parse_lnk_files(lnk_dir: str) -> str:
        """
        Parses Windows LNK (shortcut) files to recover recently accessed file paths.

        LNK files record the target file path, timestamps, volume information, and
        network path. Found in Recent Items and user Desktop.

        Args:
            lnk_dir: Path to directory containing .lnk files.
        """
        output_dir = str(EXPORTS_DIR / "lnk")
        cmd = [_ez("LECmd.exe"), "-d", lnk_dir, "--csv", output_dir]
        stdout, stderr = _run(cmd, "parse_lnk_files")

        output_path = Path(output_dir)
        entries = []
        for csv_file in output_path.glob("*.csv") if output_path.exists() else []:
            try:
                import csv as _csv
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
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

        return json.dumps({
            "total_lnk_files": len(entries),
            "entries": entries[:100],
        }, default=str)

    @mcp.tool()
    def parse_jump_lists(jumplist_dir: str) -> str:
        """
        Parses Windows Jump List files to recover recent file and application activity.

        Jump Lists are stored in AppData\\Roaming\\Microsoft\\Windows\\Recent\\
        in AutomaticDestinations\\ and CustomDestinations\\ subdirectories.

        Args:
            jumplist_dir: Path to directory containing jump list files.
        """
        output_dir = str(EXPORTS_DIR / "jumplists")
        cmd = [_ez("JLECmd.exe"), "-d", jumplist_dir, "--csv", output_dir]
        stdout, stderr = _run(cmd, "parse_jump_lists")

        output_path = Path(output_dir)
        entries = []
        for csv_file in output_path.glob("*.csv") if output_path.exists() else []:
            try:
                import csv as _csv
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        entries.append(dict(row))
            except Exception:
                continue

        return json.dumps({
            "total_jumplist_entries": len(entries),
            "entries": entries[:100],
        }, default=str)

    @mcp.tool()
    def parse_registry_hive(hive_path: str, search_pattern: str = "") -> str:
        """
        Parse a registry hive file using RECmd and return key/value data.

        Useful for examining offline registry hives extracted from evidence.
        Can search for specific patterns within the hive.

        Args:
            hive_path: Absolute path to the registry hive file (e.g. NTUSER.DAT, SOFTWARE).
            search_pattern: Optional keyword to search for within key names or values.
        """
        output_dir = str(EXPORTS_DIR / "registry")
        cmd = [_ez("RECmd.exe"), "-f", hive_path, "--csv", output_dir]
        if search_pattern:
            cmd += ["--sk", search_pattern]

        stdout, stderr = _run(cmd, "parse_registry_hive")

        output_path = Path(output_dir)
        entries = []
        for csv_file in output_path.glob("*.csv") if output_path.exists() else []:
            try:
                import csv as _csv
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        entries.append({
                            "key_path": row.get("KeyPath", ""),
                            "value_name": row.get("ValueName", ""),
                            "value_type": row.get("ValueType", ""),
                            "value_data": row.get("ValueData", "")[:500],
                            "last_write": row.get("LastWriteTimestamp", ""),
                        })
            except Exception:
                continue

        return json.dumps({
            "hive": hive_path,
            "search_pattern": search_pattern,
            "total_entries": len(entries),
            "entries": entries[:200],
        }, default=str)

    @mcp.tool()
    def parse_event_logs(evtx_dir: str, event_ids: str = "") -> str:
        """
        Parse Windows Event Log (.evtx) files using EvtxECmd to surface IR-relevant events.

        Default filter covers: logon/logoff (4624/4625/4648/4672), service installs (7045),
        scheduled tasks (4698-4702), PowerShell script blocks (4103/4104),
        WMI persistence (5860/5861), RDP (4778/4779).

        Args:
            evtx_dir: Path to directory containing .evtx files
                      (e.g. /cases/E01_mount/Windows/System32/winevt/logs).
            event_ids: Comma-separated event IDs to include. Leave empty for default security set.
        """
        import csv as _csv

        output_dir = str(EXPORTS_DIR / "evtx")
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        DEFAULT_IDS = (
            "4624,4625,4634,4647,4648,4672,4688,4697,4698,4699,4700,4701,4702,"
            "4720,4726,5857,5860,5861,7034,7035,7036,7040,7045,4103,4104,4778,4779,1149"
        )
        filter_ids = event_ids.strip() if event_ids.strip() else DEFAULT_IDS

        cmd = [
            _ez("EvtxECmd.exe"), "-d", evtx_dir,
            "--csv", output_dir,
            "--csvf", "evtx_output.csv",
            "--inc", filter_ids,
        ]
        stdout, stderr = _run(cmd, "parse_event_logs")

        output_path = Path(output_dir)
        events = []
        for csv_file in sorted(output_path.glob("*.csv")):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
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
                            "payload_data3": row.get("PayloadData3", "")[:200],
                        })
            except Exception:
                continue

        events.sort(key=lambda x: x.get("timestamp", ""))
        summary = _categorize_events(events)

        rag_context = ""
        if rag and summary.get("service_installs"):
            rag_context = rag.query("malicious service installation persistence T1543")

        return json.dumps({
            "total_events": len(events),
            "summary": summary,
            "rag_context": rag_context,
            "events": events[:500],
        }, default=str)

    @mcp.tool()
    def parse_shimcache(system_hive_path: str) -> str:
        """
        Parse Application Compatibility Cache (Shimcache) from SYSTEM registry hive.

        Shimcache records executables seen by Windows including last modified time.
        Proves a malicious executable existed on disk even after deletion.
        Hive location: SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache

        Args:
            system_hive_path: Path to extracted SYSTEM hive file.
        """
        import csv as _csv

        output_dir = str(EXPORTS_DIR / "shimcache")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = [_ez("AppCompatCacheParser.exe"), "-f", system_hive_path, "--csv", output_dir]
        stdout, stderr = _run(cmd, "parse_shimcache")

        output_path = Path(output_dir)
        entries = []
        for csv_file in output_path.glob("*.csv"):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        entries.append({
                            "path": row.get("Path", ""),
                            "last_modified_utc": row.get("LastModifiedTimeUTC", ""),
                            "executed": row.get("Executed", ""),
                        })
            except Exception:
                continue

        suspicious = [e for e in entries if _is_suspicious_path(e.get("path", ""))]
        return json.dumps({
            "total_shimcache_entries": len(entries),
            "suspicious_entries": suspicious[:50],
            "all_entries": entries[:500],
        }, default=str)

    @mcp.tool()
    def parse_amcache(amcache_path: str) -> str:
        """
        Parse Amcache.hve to recover executable metadata including SHA1 hashes.

        Amcache records every executable run with its full path and SHA1 hash.
        The SHA1 can be matched against VirusTotal or malware databases.
        Location: C:\\Windows\\AppCompat\\Programs\\Amcache.hve

        Args:
            amcache_path: Path to the Amcache.hve file extracted from evidence.
        """
        import csv as _csv

        output_dir = str(EXPORTS_DIR / "amcache")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = [_ez("AmcacheParser.exe"), "-f", amcache_path, "--csv", output_dir]
        stdout, stderr = _run(cmd, "parse_amcache")

        output_path = Path(output_dir)
        entries = []
        for csv_file in output_path.glob("*.csv"):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
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
        return json.dumps({
            "total_amcache_entries": len(entries),
            "suspicious_entries": suspicious[:50],
            "all_entries": entries[:500],
        }, default=str)

    @mcp.tool()
    def parse_mft(mft_path: str) -> str:
        """
        Parse the NTFS Master File Table ($MFT) to enumerate files with full timestamps.

        The $MFT contains metadata for every file: created, modified, accessed times.
        A Last-Modified time before the Created time proves the file was copied from
        another volume (e.g. malware dropped from USB or attacker machine).
        Only returns executables and scripts to keep output manageable.

        Args:
            mft_path: Path to extracted $MFT file from evidence volume.
        """
        import csv as _csv

        output_dir = str(EXPORTS_DIR / "mft")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = [_ez("MFTECmd.exe"), "-f", mft_path, "--csv", output_dir]
        stdout, stderr = _run(cmd, "parse_mft")

        output_path = Path(output_dir)
        entries = []
        for csv_file in output_path.glob("*.csv"):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
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
                        # Timestamp anomaly: modified before created = copied from elsewhere
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

        return json.dumps({
            "total_executable_entries": len(entries),
            "timestamp_anomalies_count": len(anomalies),
            "deleted_executables_count": len(deleted),
            "timestamp_anomalies": anomalies[:50],
            "deleted_executables": deleted[:50],
            "all_entries": entries[:500],
        }, default=str)

    @mcp.tool()
    def parse_recycle_bin(recycle_bin_path: str) -> str:
        """
        Parse Windows Recycle Bin $I files to recover deleted file metadata.

        Each deleted file has a $I (Information) file recording the original path
        and deletion timestamp. Can prove malware existed and was subsequently deleted.
        Location: C:\\$Recycle.Bin\\<user-SID>\\ on the evidence volume.

        Args:
            recycle_bin_path: Path to $Recycle.Bin directory or specific SID subdirectory.
        """
        import csv as _csv

        output_dir = str(EXPORTS_DIR / "recycle_bin")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = [_ez("RBCmd.exe"), "-d", recycle_bin_path, "--csv", output_dir]
        stdout, stderr = _run(cmd, "parse_recycle_bin")

        output_path = Path(output_dir)
        entries = []
        for csv_file in output_path.glob("*.csv"):
            try:
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        entries.append({
                            "original_path": row.get("FileName", ""),
                            "deleted_on": row.get("DeletedOn", ""),
                            "file_size": row.get("FileSize", ""),
                            "source_file": row.get("SourceFile", ""),
                        })
            except Exception:
                continue

        suspicious = [e for e in entries if _is_suspicious_path(e.get("original_path", ""))]
        return json.dumps({
            "total_deleted_files": len(entries),
            "suspicious_deleted_files": suspicious[:50],
            "all_deleted_files": entries[:200],
        }, default=str)

    @mcp.tool()
    def lookup_ip_reputation(ip_address: str) -> str:
        """
        Check an IP address against AbuseIPDB and VirusTotal threat intelligence.

        Use this for every external IP found by get_network_connections.
        Returns abuse confidence score, ISP, country, and known malicious activity.

        Args:
            ip_address: IPv4 or IPv6 address to check.
        """
        import requests
        from mcp_server.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY

        result = {"ip": ip_address, "abuseipdb": None, "virustotal": None}

        if ABUSEIPDB_API_KEY:
            try:
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
                    params={"ipAddress": ip_address, "maxAgeInDays": 90},
                    timeout=10,
                )
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    result["abuseipdb"] = {
                        "abuse_confidence_score": data.get("abuseConfidenceScore"),
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "total_reports": data.get("totalReports"),
                        "last_reported": data.get("lastReportedAt"),
                        "is_whitelisted": data.get("isWhitelisted"),
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

        return json.dumps(result)
