"""
Cloud storage artifact forensics — Dropbox, OneDrive, Google Drive, Slack, Teams.

These tools parse offline artifacts left by cloud sync clients on the local filesystem.
Critical for exfiltration investigation: cloud clients are stealth exfil channels
because transfers look like normal sync activity (T1567.002).

Tools:
  parse_dropbox_logs      — Dropbox sync_history.db + config
  parse_onedrive_logs     — OneDrive SyncDiagnostics.log + ODL binary logs
  parse_google_drive_logs — Google Drive for Desktop activity
  parse_slack_artifacts   — Slack desktop cache/message index
  parse_teams_artifacts   — Microsoft Teams IndexedDB and logs
  parse_icloud_logs       — iCloud for Windows sync logs
"""
import json
import re
import sqlite3
import struct
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.parsers.cloud_parser import classify_sync_events, build_cloud_summary
from mcp_server.parsers.rag_enrichment import enrich_findings, build_rag_summary


def _query_sqlite(db_path: str, query: str, params: tuple = ()) -> list[dict]:
    uri = f"file:{db_path}?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        return [{"error": str(e)}]


def register_cloud_artifact_tools(mcp, rag=None):

    @mcp.tool()
    def parse_dropbox_logs(dropbox_dir: str) -> str:
        """
        Parse Dropbox client forensic artifacts.

        Examines: sync_history.db (file sync events with timestamps), config.dbx
        (account configuration, linked email), filecache.dbx (cached file metadata),
        and instance1/instance2 log directories.

        Dropbox artifacts prove which files were synced and WHEN — critical for
        T1567.002 (Exfiltration to Cloud Storage) attribution.

        Args:
            dropbox_dir: Path to Dropbox appdata directory.
                         Typically: Users/<user>/AppData/Local/Dropbox/
        """
        increment_tool_counter()
        db_path = Path(dropbox_dir)
        if not db_path.exists():
            return json.dumps({"error": f"Dropbox directory not found: {dropbox_dir}"})

        log_tool_execution("parse_dropbox_logs", [dropbox_dir], "Dropbox artifact parse")
        audit_id = get_last_audit_id()

        results: dict = {"dropbox_dir": dropbox_dir}

        # sync_history.db — most valuable artifact
        sync_dbs = list(db_path.rglob("sync_history.db"))
        sync_events: list[dict] = []
        for sdb in sync_dbs[:3]:
            rows = _query_sqlite(
                str(sdb),
                "SELECT * FROM sync_history ORDER BY server_mtime DESC LIMIT 500",
            )
            if rows and "error" not in rows[0]:
                sync_events.extend([dict(r) for r in rows])
                results["sync_history_db"] = str(sdb)

        # filecache.dbx (SQLite with different extension)
        filecache_dbs = list(db_path.rglob("filecache.dbx"))
        file_entries: list[dict] = []
        for fdb in filecache_dbs[:2]:
            rows = _query_sqlite(str(fdb), "SELECT * FROM file_journal ORDER BY server_mtime DESC LIMIT 500")
            if rows and "error" not in rows[0]:
                file_entries.extend(rows)

        # config.dbx for account info
        config_dbs = list(db_path.rglob("config.dbx"))
        config: dict = {}
        for cdb in config_dbs[:1]:
            rows = _query_sqlite(str(cdb), "SELECT key, value FROM config")
            if rows and "error" not in rows[0]:
                config = {r.get("key", ""): str(r.get("value", ""))[:200] for r in rows}

        # Parse text log files for upload indicators
        upload_indicators: list[str] = []
        for log_file in list(db_path.rglob("*.log"))[:20]:
            try:
                text = log_file.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    if any(kw in line.lower() for kw in ["upload", "sync", "added", "modified"]):
                        upload_indicators.append(f"{log_file.name}: {line[:200]}")
                        if len(upload_indicators) >= 100:
                            break
            except Exception:
                pass

        # Middleware parser: classify sync events for exfiltration risk
        _, suspicious_syncs = classify_sync_events(sync_events)
        cloud_summary = build_cloud_summary("Dropbox", sync_events, suspicious_syncs)
        enrich_findings(rag, suspicious_syncs,
                        lambda e: f"Dropbox cloud exfiltration sync event {e.get('filename', '')} {e.get('threat_flags', [])}")

        results.update({
            "sync_event_count": len(sync_events),
            "recent_sync_events": sync_events[:100],
            "file_cache_entries": file_entries[:100],
            "account_config": {k: v for k, v in config.items() if "email" in k.lower() or "account" in k.lower() or "user" in k.lower()},
            "upload_log_indicators": upload_indicators[:50],
            "exfiltration_analysis": cloud_summary,
            "rag_context": build_rag_summary(rag, "Dropbox cloud exfiltration T1567.002"),
            "tool_calls_used": get_tool_count(),
        })
        return wrap_response("parse_dropbox_logs", results, audit_id)

    @mcp.tool()
    def parse_onedrive_logs(onedrive_dir: str) -> str:
        """
        Parse Microsoft OneDrive client forensic artifacts.

        Examines: SyncDiagnostics.log (sync events), ODL (OneDrive Log) binary
        log files, and the SQLite database files in the OneDrive data directory.

        ODL logs record every file uploaded/downloaded with timestamps and
        file names — they persist after browser history is cleared.

        Args:
            onedrive_dir: Path to OneDrive local data directory.
                          Typically: Users/<user>/AppData/Local/Microsoft/OneDrive/
        """
        increment_tool_counter()
        od_path = Path(onedrive_dir)
        if not od_path.exists():
            return json.dumps({"error": f"OneDrive directory not found: {onedrive_dir}"})

        log_tool_execution("parse_onedrive_logs", [onedrive_dir], "OneDrive artifact parse")
        audit_id = get_last_audit_id()

        results: dict = {"onedrive_dir": onedrive_dir}
        sync_events: list[dict] = []
        odl_entries: list[str] = []

        # SyncDiagnostics.log — human-readable
        diag_logs = list(od_path.rglob("SyncDiagnostics.log"))
        for dl in diag_logs[:3]:
            try:
                text = dl.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    if any(kw in line for kw in ["Upload", "Download", "Sync", "Added", "Moved", "Deleted"]):
                        sync_events.append({"source": dl.name, "line": line[:300]})
            except Exception:
                pass
        results["sync_events"] = sync_events[:200]

        # ODL binary logs — extract printable strings containing file paths
        odl_files = sorted(od_path.rglob("*.odl"), key=lambda f: f.stat().st_mtime if f.exists() else 0, reverse=True)
        for odl in odl_files[:20]:
            try:
                raw = odl.read_bytes()
                for m in re.finditer(rb"[A-Za-z0-9_\-\\/:. ]{10,200}", raw):
                    s = m.group().decode("utf-8", errors="replace").strip()
                    if any(ext in s for ext in [".docx", ".xlsx", ".pdf", ".pptx", ".zip", ".exe", ":\\"]):
                        odl_entries.append(f"{odl.name}: {s}")
            except Exception:
                pass
        results["odl_file_references"] = odl_entries[:200]
        results["odl_file_count"] = len(odl_files)

        # SQLite databases
        sqlite_dbs = list(od_path.rglob("*.db"))
        db_schemas: list[dict] = []
        for sdb in sqlite_dbs[:5]:
            rows = _query_sqlite(str(sdb), "SELECT name FROM sqlite_master WHERE type='table'")
            if rows and "error" not in rows[0]:
                db_schemas.append({"db": sdb.name, "tables": [r.get("name") for r in rows]})
        results["sqlite_databases"] = db_schemas

        _, suspicious_syncs = classify_sync_events(sync_events)
        results["exfiltration_analysis"] = build_cloud_summary("OneDrive", sync_events, suspicious_syncs)
        enrich_findings(rag, suspicious_syncs,
                        lambda e: f"OneDrive exfiltration sync event {e.get('line', '')} {e.get('threat_flags', [])}")
        results["rag_context"] = build_rag_summary(rag, "OneDrive cloud exfiltration T1567.002")
        results["tool_calls_used"] = get_tool_count()
        return wrap_response("parse_onedrive_logs", results, audit_id)

    @mcp.tool()
    def parse_google_drive_logs(gdrive_dir: str) -> str:
        """
        Parse Google Drive for Desktop forensic artifacts.

        Examines: sync_log.log / cloud_graph.db (file sync metadata),
        snapshot.db (file listing at last sync), and metadata databases.

        Args:
            gdrive_dir: Path to Google Drive appdata directory.
                        Typically: Users/<user>/AppData/Local/Google/DriveFS/
                        or Users/<user>/AppData/Local/Google/Drive/
        """
        increment_tool_counter()
        gd_path = Path(gdrive_dir)
        if not gd_path.exists():
            return json.dumps({"error": f"Google Drive directory not found: {gdrive_dir}"})

        log_tool_execution("parse_google_drive_logs", [gdrive_dir], "Google Drive artifact parse")
        audit_id = get_last_audit_id()

        results: dict = {"gdrive_dir": gdrive_dir}
        sync_events: list[str] = []

        # Parse log files
        for log_file in sorted(gd_path.rglob("*.log"), key=lambda f: f.stat().st_mtime if f.exists() else 0, reverse=True)[:10]:
            try:
                text = log_file.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    if any(kw in line.lower() for kw in ["upload", "sync", "error", "quota", "shared"]):
                        sync_events.append(f"{log_file.name}: {line[:300]}")
                        if len(sync_events) >= 200:
                            break
            except Exception:
                pass
        results["sync_log_events"] = sync_events[:200]

        # cloud_graph.db — file metadata
        cloud_dbs = list(gd_path.rglob("cloud_graph.db")) + list(gd_path.rglob("snapshot.db"))
        db_entries: list[dict] = []
        for cdb in cloud_dbs[:3]:
            tables = _query_sqlite(str(cdb), "SELECT name FROM sqlite_master WHERE type='table'")
            for tbl in tables[:5]:
                t = tbl.get("name", "")
                rows = _query_sqlite(str(cdb), f"SELECT * FROM \"{t}\" LIMIT 100")
                if rows and "error" not in rows[0]:
                    db_entries.append({"db": cdb.name, "table": t, "sample_rows": rows[:10]})

        sync_event_dicts = [{"line": e} for e in sync_events]
        _, suspicious_syncs = classify_sync_events(sync_event_dicts)
        results["exfiltration_analysis"] = build_cloud_summary("Google Drive", sync_event_dicts, suspicious_syncs)
        enrich_findings(rag, suspicious_syncs,
                        lambda e: f"Google Drive exfiltration {e.get('line', '')} {e.get('threat_flags', [])}")
        results["rag_context"] = build_rag_summary(rag, "Google Drive cloud exfiltration T1567.002")
        results["database_entries"] = db_entries[:20]
        results["tool_calls_used"] = get_tool_count()
        return wrap_response("parse_google_drive_logs", results, audit_id)

    @mcp.tool()
    def parse_slack_artifacts(slack_dir: str) -> str:
        """
        Parse Slack desktop client forensic artifacts.

        Slack stores message cache, workspace data, and file transfer logs in
        LevelDB/IndexedDB databases under AppData. These artifacts can reveal
        communication patterns and file sharing activity.

        Args:
            slack_dir: Path to Slack appdata directory.
                       Typically: Users/<user>/AppData/Roaming/Slack/
        """
        increment_tool_counter()
        slack_path = Path(slack_dir)
        if not slack_path.exists():
            return json.dumps({"error": f"Slack directory not found: {slack_dir}"})

        log_tool_execution("parse_slack_artifacts", [slack_dir], "Slack artifact parse")
        audit_id = get_last_audit_id()

        results: dict = {"slack_dir": slack_dir}

        # Workspace list from storage
        workspaces: list[str] = []
        for p in slack_path.rglob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and "team" in str(data).lower():
                    workspaces.append(str(p.relative_to(slack_path)))
            except Exception:
                pass

        # Extract strings from LevelDB files (message cache)
        cached_messages: list[str] = []
        for ldb in sorted(slack_path.rglob("*.ldb"), key=lambda f: f.stat().st_mtime if f.exists() else 0, reverse=True)[:20]:
            try:
                raw = ldb.read_bytes()
                for m in re.finditer(rb'"text":"([^"]{10,300})"', raw):
                    cached_messages.append(m.group(1).decode("utf-8", errors="replace"))
            except Exception:
                pass

        # Download logs
        downloads: list[str] = []
        for log_file in list(slack_path.rglob("*.log"))[:10]:
            try:
                text = log_file.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    if "download" in line.lower() or "file" in line.lower():
                        downloads.append(line[:200])
            except Exception:
                pass

        results.update({
            "workspace_config_files": workspaces[:20],
            "cached_message_count": len(cached_messages),
            "cached_messages_sample": cached_messages[:50],
            "download_log_entries": downloads[:50],
            "rag_context": build_rag_summary(rag, "Slack desktop artifacts insider threat data exfiltration"),
            "tool_calls_used": get_tool_count(),
        })
        return wrap_response("parse_slack_artifacts", results, audit_id)

    @mcp.tool()
    def parse_teams_artifacts(teams_dir: str) -> str:
        """
        Parse Microsoft Teams desktop client forensic artifacts.

        Teams stores chat history, meeting records, and file transfer logs
        in IndexedDB (LevelDB format) and JSON logs under AppData.

        Args:
            teams_dir: Path to Teams appdata directory.
                       Typically: Users/<user>/AppData/Roaming/Microsoft/Teams/
        """
        increment_tool_counter()
        teams_path = Path(teams_dir)
        if not teams_path.exists():
            return json.dumps({"error": f"Teams directory not found: {teams_dir}"})

        log_tool_execution("parse_teams_artifacts", [teams_dir], "Teams artifact parse")
        audit_id = get_last_audit_id()

        results: dict = {"teams_dir": teams_dir}
        account_info: list[dict] = []
        chats: list[str] = []
        file_transfers: list[str] = []

        # accounts.json
        for acc_file in teams_path.rglob("accounts.json"):
            try:
                data = json.loads(Path(acc_file).read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for a in data:
                        account_info.append({
                            "username": a.get("username", a.get("upn", "")),
                            "display_name": a.get("displayName", ""),
                        })
                elif isinstance(data, dict):
                    account_info.append(data)
            except Exception:
                pass

        # Extract from LevelDB (IndexedDB) files
        for ldb in sorted(teams_path.rglob("*.ldb"), key=lambda f: f.stat().st_mtime if f.exists() else 0, reverse=True)[:20]:
            try:
                raw = ldb.read_bytes()
                # Chat messages
                for m in re.finditer(rb'"content":"([^"]{5,300})"', raw):
                    chats.append(m.group(1).decode("utf-8", errors="replace"))
                # File references
                for m in re.finditer(rb'"fileName":"([^"]{3,200})"', raw):
                    file_transfers.append(m.group(1).decode("utf-8", errors="replace"))
            except Exception:
                pass

        # Parse JSON logs
        log_entries: list[str] = []
        for log_file in sorted(teams_path.rglob("*.json"))[:30]:
            try:
                text = log_file.read_text(encoding="utf-8", errors="replace")
                if "messageType" in text or "fileUpload" in text:
                    log_entries.append(str(log_file.relative_to(teams_path)))
            except Exception:
                pass

        ft_dicts = [{"filename": f} for f in file_transfers]
        _, suspicious_ft = classify_sync_events(ft_dicts)
        enrich_findings(rag, suspicious_ft,
                        lambda e: f"Microsoft Teams file transfer exfiltration {e.get('filename', '')} {e.get('threat_flags', [])}")

        results.update({
            "accounts": account_info[:10],
            "cached_chat_count": len(chats),
            "chats_sample": chats[:50],
            "file_transfer_count": len(file_transfers),
            "file_transfers": list(dict.fromkeys(file_transfers))[:100],
            "suspicious_file_transfers": suspicious_ft[:30],
            "relevant_log_files": log_entries[:20],
            "rag_context": build_rag_summary(rag, "Microsoft Teams file sharing exfiltration T1567.002"),
            "tool_calls_used": get_tool_count(),
        })
        return wrap_response("parse_teams_artifacts", results, audit_id)

    @mcp.tool()
    def parse_icloud_logs(icloud_dir: str) -> str:
        """
        Parse iCloud for Windows client forensic artifacts.

        iCloud for Windows is a common exfiltration vector for Apple ecosystem
        users — files placed in iCloud Drive sync automatically to all Apple devices.

        Args:
            icloud_dir: Path to iCloud appdata directory.
                        Typically: Users/<user>/AppData/Local/Apple Inc/iCloud/
                        Or check: Users/<user>/iCloudDrive/ for local sync folder.
        """
        increment_tool_counter()
        icloud_path = Path(icloud_dir)
        if not icloud_path.exists():
            return json.dumps({"error": f"iCloud directory not found: {icloud_dir}"})

        log_tool_execution("parse_icloud_logs", [icloud_dir], "iCloud artifact parse")
        audit_id = get_last_audit_id()

        results: dict = {"icloud_dir": icloud_dir}
        log_entries: list[str] = []
        synced_files: list[dict] = []

        # Parse log files
        for log_file in sorted(icloud_path.rglob("*.log"), key=lambda f: f.stat().st_mtime if f.exists() else 0, reverse=True)[:10]:
            try:
                text = log_file.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    if any(kw in line.lower() for kw in ["upload", "sync", "download", "error"]):
                        log_entries.append(f"{log_file.name}: {line[:300]}")
            except Exception:
                pass

        # Inventory files in iCloud Drive local folder
        for p in icloud_path.rglob("*"):
            if p.is_file() and p.suffix.lower() not in {".log", ".db", ".plist"}:
                try:
                    synced_files.append({
                        "filename": p.name,
                        "size_bytes": p.stat().st_size,
                        "relative_path": str(p.relative_to(icloud_path)),
                    })
                except Exception:
                    pass

        results.update({
            "log_entries": log_entries[:100],
            "synced_file_count": len(synced_files),
            "synced_files_sample": synced_files[:100],
            "tool_calls_used": get_tool_count(),
        })
        return wrap_response("parse_icloud_logs", results, audit_id)
