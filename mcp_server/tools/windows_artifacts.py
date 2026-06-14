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
from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, guard_command
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


def _fresh_outdir(name: str) -> str:
    """Return this tool's CSV output dir under EXPORTS_DIR, emptied of CSVs left by
    previous runs.

    EZ Tools write a timestamped CSV here and the caller then reads back *every*
    CSV in the dir. Without clearing, a later run — or a DIFFERENT CASE — re-reads
    stale rows (e.g. a prior case's LNK output under the 'fredr' profile) and
    reports them as the current case's findings: cross-case evidence contamination.
    Clearing guarantees each parse reflects only the evidence it was just given.
    """
    d = EXPORTS_DIR / name
    d.mkdir(parents=True, exist_ok=True)
    for old in d.glob("*.csv"):
        try:
            old.unlink()
        except OSError:
            pass
    return str(d)


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


# Cap on how many bytes of CSV evidence we fold into the audited raw output.
# Large enough to hold the actual artifact rows (so grounding can verify claims
# against real evidence), bounded so the audit log stays manageable.
_MAX_AUDIT_EVIDENCE_BYTES = 8 * 1024 * 1024


def _collect_evidence_text(data_dir: str | None) -> str:
    """Concatenate the CSV evidence an EZ tool just wrote, for the audit record.

    EZ Tools print only a banner/status to stdout and write the actual rows to a
    CSV file. Chain-of-custody and grounding both depend on the *data* — not the
    banner — so we fold the CSV bytes into the audited raw_output. Bounded by
    _MAX_AUDIT_EVIDENCE_BYTES.
    """
    if not data_dir:
        return ""
    p = Path(data_dir)
    if not p.exists():
        return ""
    parts: list[str] = []
    budget = _MAX_AUDIT_EVIDENCE_BYTES
    for csv_file in sorted(p.glob("*.csv")):
        if budget <= 0:
            parts.append("[evidence truncated for audit record]")
            break
        try:
            text = csv_file.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        if len(text) > budget:
            # Truncate within a single large CSV so the audit record stays bounded
            # while still carrying the column header + a large body of real rows.
            text = text[:budget] + "\n[evidence truncated for audit record]"
        parts.append(f"--- {csv_file.name} ---\n{text}")
        budget -= len(text)
    return "\n".join(parts)


# Rare, high-signal events (RDP, persistence, account mgmt, PowerShell, log clear,
# service install, explicit-credential logon). These are few and always worth keeping.
_RARE_EVENT_IDS = {
    "4648", "4697", "4698", "4699", "4700", "4701", "4702",
    "4720", "4726", "5860", "5861", "7040", "7045",
    "4103", "4104", "4778", "4779", "1149", "1102", "104",
}
# High-volume events worth sampling (logons, logoffs, priv logon, proc creation, svc state).
# 4672 (special-privilege logon) fires constantly for SYSTEM, so it belongs here, not in rare.
_VOLUME_EVENT_IDS = {"4624", "4625", "4634", "4647", "4672", "4688", "7034", "7035", "7036", "5857"}
_TIMELINE_EVENT_IDS = _RARE_EVENT_IDS | _VOLUME_EVENT_IDS


def _build_event_timeline(events: list[dict], limit: int = 400, rare_cap: int = 250) -> list[str]:
    """One line per security event, co-locating the event ID with its timestamp:

        "[event 4778] 2020-11-14 03:42:11 — Session reconnected — DOMAIN\\user"

    Pairing the ID and the date in one string lets a downstream timeline tie a specific
    incident date to a concrete Windows event (the form IR reports use). Rare high-signal
    events (RDP, persistence, PowerShell…) are ALL kept so the incident window is never
    crowded out by routine high-volume service-state noise; the remaining budget is filled
    with the most recent volume events. Output is chronological.
    """
    def _line(e: dict, eid: str) -> tuple[str, str]:
        ts = str(e.get("timestamp", "")).strip()
        desc = (e.get("map_description") or "").strip() or str(e.get("channel", "")).strip()
        user = (e.get("user_name") or "").strip()
        s = f"[event {eid}] {ts} — {desc}"
        if user and user not in ("-", "N/A"):
            s += f" — {user}"
        return ts, s

    rare: list[tuple[str, str]] = []
    volume: list[tuple[str, str]] = []
    for e in events:
        eid = str(e.get("event_id", "")).strip()
        if eid in _RARE_EVENT_IDS:
            rare.append(_line(e, eid))
        elif eid in _VOLUME_EVENT_IDS:
            volume.append(_line(e, eid))

    chosen = rare[-rare_cap:] + volume[-max(0, limit - min(len(rare), rare_cap)):]
    chosen.sort(key=lambda x: x[0])  # chronological by embedded timestamp
    return [s for _, s in chosen]


def _run(cmd: list[str], tool_name: str, data_dir: str | None = None) -> tuple[str, str]:
    """Run an EZ tool. If ``data_dir`` is given, the CSV evidence written there is
    folded into the audited raw_output so chain-of-custody (SHA-256) and the
    grounding corpus reflect the actual artifact rows, not just the stdout banner.
    """
    try:
        guard_command(cmd)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
        evidence = _collect_evidence_text(data_dir)
        raw_output = result.stdout
        if evidence:
            raw_output = f"{result.stdout}\n=== CSV EVIDENCE ===\n{evidence}"
        log_tool_execution(tool_name, cmd, raw_output, error=result.stderr)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        # EZ tools write the CSV incrementally; a timeout still leaves real evidence
        # on disk. Fold whatever was written so chain-of-custody and grounding keep
        # the partial rows instead of an empty record.
        msg = f"'{tool_name}' timed out after {MAX_TOOL_TIMEOUT}s (partial evidence captured)"
        evidence = _collect_evidence_text(data_dir)
        log_tool_execution(tool_name, cmd, evidence, error=msg)
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
    # RECmd ABORTS on a dirty hive ("Registry hive is dirty ... Aborting!!") when it
    # cannot find matching .LOG1/.LOG2 transaction logs in the same dir. Live-acquired
    # hives (NTUSER.DAT, SYSTEM, UsrClass.dat) are almost always dirty and ship TxR
    # (.blf / .regtrans-ms) logs rather than the .LOG files RECmd replays, so it bails
    # and the tool silently returns 0 rows. --nl tells RECmd to skip transaction-log
    # loading and parse the hive as-is ("Continuing anyways..."). Always pass it so a
    # dirty hive never turns into an empty (and misleading) result.
    extra = ["--nl"] if name.lower() == "recmd" else []
    exe = EZ_TOOLS_DIR / f"{name}.exe"
    # Only exec the native .exe on Windows — on Linux those PE launchers can't run.
    if os.name == "nt" and exe.exists():
        return [str(exe)] + extra
    # Case-insensitive .dll match — Linux globs are case-sensitive, so e.g.
    # "SbECmd.dll" would miss the on-disk "SBECmd.dll" and fall through to an error.
    want = f"{name}.dll".lower()
    hits = [p for p in EZ_TOOLS_DIR.glob("**/*.dll") if p.name.lower() == want]
    if hits:
        return ["dotnet", str(hits[0])] + extra
    if exe.exists():
        return [str(exe)] + extra
    # Fall back to a top-level dll path; _run() reports a clear error if missing.
    return ["dotnet", str(EZ_TOOLS_DIR / f"{name}.dll")] + extra


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


# RECmd `--csv` only emits a CSV in BATCH (--bn) mode. A single-key dump (--kn) goes
# to STDOUT as an indented key/subkey/value tree, so a CSV-only reader sees 0 rows
# even when the key is full of data. This regex pulls the subkey records out of that
# stdout tree so --kn tools (USBSTOR, network interfaces, RecentDocs) still yield
# structured entries.
_RECMD_SUBKEY_RE = __import__("re").compile(
    r"Name:\s*(?P<name>.+?)\s*\(Last write:\s*(?P<lastwrite>[^)]*)\)"
)


def _recmd_subkeys_from_stdout(stdout: str, max_rows: int = 200) -> list[dict]:
    """Extract subkey records (name + last-write time) from a RECmd --kn stdout dump."""
    out: list[dict] = []
    for m in _RECMD_SUBKEY_RE.finditer(stdout or ""):
        name = m.group("name").strip()
        if not name:
            continue
        out.append({"name": name, "last_write": m.group("lastwrite").strip()})
        if len(out) >= max_rows:
            break
    return out


def _offline_controlset(key: str) -> str:
    """Offline SYSTEM hives have no ``CurrentControlSet`` symlink — only ControlSet001/2.
    Rewrite the key so RECmd can resolve it against an acquired hive.
    """
    return key.replace("CurrentControlSet", "ControlSet001", 1)


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
        output_dir = _fresh_outdir("evtx")
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
        _run(cmd, "parse_event_logs", data_dir=output_dir)
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
            "incident_event_timeline": _build_event_timeline(events),
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
        output_dir = _fresh_outdir("shimcache")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("AppCompatCacheParser.exe") + ["-f", system_hive_path, "--csv", output_dir]
        _run(cmd, "parse_shimcache", data_dir=output_dir)
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
        output_dir = _fresh_outdir("amcache")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("AmcacheParser.exe") + ["-f", amcache_path, "--csv", output_dir]
        _run(cmd, "parse_amcache", data_dir=output_dir)
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
        output_dir = _fresh_outdir("prefetch")
        cmd = _ez("PECmd.exe") + ["-d", prefetch_dir, "--csv", output_dir]
        _run(cmd, "parse_prefetch", data_dir=output_dir)
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
        output_dir = _fresh_outdir("mft")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("MFTECmd.exe") + ["-f", mft_path, "--csv", output_dir]
        _run(cmd, "parse_mft", data_dir=output_dir)
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
        output_dir = _fresh_outdir("lnk")
        cmd = _ez("LECmd.exe") + ["-d", lnk_dir, "--csv", output_dir]
        _run(cmd, "parse_lnk_files", data_dir=output_dir)
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
        output_dir = _fresh_outdir("jumplists")
        cmd = _ez("JLECmd.exe") + ["-d", jumplist_dir, "--csv", output_dir]
        _run(cmd, "parse_jump_lists", data_dir=output_dir)
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
        output_dir = _fresh_outdir("registry")
        cmd = _ez("RECmd.exe") + ["-f", hive_path, "--csv", output_dir]
        if search_pattern:
            cmd += ["--sk", search_pattern]

        _run(cmd, "parse_registry_hive", data_dir=output_dir)
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
        output_dir = _fresh_outdir("recycle_bin")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("RBCmd.exe") + ["-d", recycle_bin_path, "--csv", output_dir]
        _run(cmd, "parse_recycle_bin", data_dir=output_dir)
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
        Critical where cloud sync services are suspected exfiltration channels.

        Args:
            srum_path: Absolute path to SRUDB.dat extracted from the evidence volume.
        """
        output_dir = _fresh_outdir("srum")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("SrumECmd.exe") + ["-f", srum_path, "--csv", output_dir]
        _run(cmd, "parse_srum", data_dir=output_dir)
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
        output_dir = _fresh_outdir("usn_journal")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("MFTECmd.exe") + ["-f", usn_path, "--csv", output_dir]
        _run(cmd, "parse_usn_journal", data_dir=output_dir)
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
        output_dir = _fresh_outdir("userassist")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        # RECmd ships its batch files under RECmd/BatchExamples/, and the UserAssist
        # one is named BatchExampleUserAssist.reb — not BatchExamples/UserAssist.reb.
        # Glob for it so a layout change can't silently break the parse (RECmd errors
        # "batch file does not exist" and returns 0 rows otherwise).
        _ua = (list(EZ_TOOLS_DIR.glob("**/BatchExample*UserAssist*.reb"))
               or list(EZ_TOOLS_DIR.glob("**/UserAssist.reb")))
        batch_file = str(_ua[0]) if _ua else str(
            EZ_TOOLS_DIR / "RECmd" / "BatchExamples" / "BatchExampleUserAssist.reb")
        cmd = _ez("RECmd.exe") + ["-f", ntuser_path, "--bn", batch_file, "--csv", output_dir]
        _run(cmd, "parse_userassist", data_dir=output_dir)
        audit_id = get_last_audit_id()
        increment_tool_counter()

        entries = _read_csv_dir(output_dir)
        useful = []
        for row in entries:
            # The UserAssist batch DECODES each entry: ValueName holds the raw ROT13
            # value, but the human-readable program path lands in ValueData, the last
            # run time in ValueData2 ("Last executed: ..."), and the run count in
            # ValueData3 ("Run count: N"). Reading ValueName (the old behaviour) yields
            # ROT13 gibberish like "HRZR_PGYFRFFVBA"; prefer the decoded ValueData.
            path = (row.get("ValueData") or "").strip()
            if not path or path.upper().startswith("UEME_"):
                # ValueData empty or a session/control counter — fall back to the ROT13
                # ValueName, decoded, so nothing is silently dropped.
                raw = row.get("ValueName", "") or ""
                try:
                    path = __import__("codecs").decode(raw, "rot_13")
                except Exception:
                    path = raw
            count = (row.get("ValueData3") or "").replace("Run count:", "").strip()
            last_run = (row.get("ValueData2") or "").replace("Last executed:", "").strip() \
                or row.get("LastWriteTimestamp", "")
            if path and not path.upper().startswith("UEME_"):
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
        output_dir = _fresh_outdir("recentdocs")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("RECmd.exe") + [ "-f", ntuser_path,
            "--kn", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            "--csv", output_dir,
        ]
        stdout, _ = _run(cmd, "parse_recentdocs", data_dir=output_dir)
        audit_id = get_last_audit_id()
        increment_tool_counter()

        # --kn dumps to stdout (no CSV); fall back to parsing the subkey tree.
        entries = _read_csv_dir(output_dir) or _recmd_subkeys_from_stdout(stdout)
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
        output_dir = _fresh_outdir("network_history")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("RECmd.exe") + [ "-f", system_hive_path,
            "--kn", _offline_controlset("CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"),
            "--csv", output_dir,
        ]
        stdout, _ = _run(cmd, "parse_network_history", data_dir=output_dir)
        audit_id = get_last_audit_id()
        increment_tool_counter()

        # --kn dumps to stdout (no CSV); fall back to parsing the subkey tree.
        entries = _read_csv_dir(output_dir) or _recmd_subkeys_from_stdout(stdout)
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
        output_dir = _fresh_outdir("usb_history")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = _ez("RECmd.exe") + [ "-f", system_hive_path,
            "--kn", _offline_controlset("CurrentControlSet\\Enum\\USBSTOR"),
            "--csv", output_dir,
        ]
        stdout, _ = _run(cmd, "parse_usb_history", data_dir=output_dir)
        audit_id = get_last_audit_id()
        increment_tool_counter()

        # --kn dumps to stdout (no CSV); the USBSTOR subkey names ARE the device
        # identifiers (Disk&Ven_..&Prod_..&Rev_..), so parse them from the tree.
        entries = _read_csv_dir(output_dir) or _recmd_subkeys_from_stdout(stdout)
        data = {
            "total_usb_devices": len(entries),
            "entries": entries[:100],
            "note": "Cross-reference connection timestamps with logon events (4624) "
                    "to identify which user account was active during USB insertion.",
        }
        return wrap_response("parse_usb_history", data, audit_id)
