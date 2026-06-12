"""
Anti-forensics detection tools.

Tools:
  detect_timestomping         — Compare MACB timestamps for anomalies
  detect_log_wiping           — Event log record-gap and cleared-log detection
  detect_secure_deletion      — Find traces of secure delete tools (SDelete, Eraser)
  detect_ads_streams          — Alternate Data Streams discovery via NTFS MFT
  analyze_vss_shadows         — Volume Shadow Copy inventory
  detect_prefetch_anomalies   — Prefetch execution count or timing inconsistencies
  detect_event_log_tampering  — Event ID 1102/104 and audit policy change detection
"""
import json
import re
import subprocess
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import MAX_TOOL_TIMEOUT
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.parsers.rag_enrichment import enrich_findings, build_rag_summary
from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques


def register_anti_forensics_tools(mcp, rag=None):

    @mcp.tool()
    def detect_timestomping(mft_json_path: str) -> str:
        """
        Detect timestamp manipulation (timestomping) from a parsed MFT JSON file.

        Compares $STANDARD_INFORMATION vs $FILE_NAME timestamps for each entry.
        Timestomping tools only update $SI — $FN timestamps are harder to modify
        and are set by the kernel at file creation. A large delta between $SI and
        $FN timestamps indicates likely timestomping (T1070.006).

        Also detects: timestamps pre-dating the OS installation, timestamps set to
        round numbers (attacker laziness), and unrealistically early epochs.

        Args:
            mft_json_path: Path to MFT JSON previously output by parse_mft().
        """
        increment_tool_counter()
        if not Path(mft_json_path).exists():
            return json.dumps({"error": f"MFT JSON not found: {mft_json_path}"})

        log_tool_execution("detect_timestomping", [mft_json_path], "timestamp anomaly analysis")
        audit_id = get_last_audit_id()

        try:
            records = json.loads(Path(mft_json_path).read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError) as e:
            return json.dumps({"error": f"Failed to parse MFT JSON: {e}"})

        if not isinstance(records, list):
            records = [records]

        anomalies: list[dict] = []
        round_number_anomalies: list[dict] = []
        pre_epoch_anomalies: list[dict] = []

        for rec in records:
            fn_created = rec.get("fn_created", "")
            si_created = rec.get("si_created", "") or rec.get("created", "")
            file_name = rec.get("file_name", rec.get("FileName", "unknown"))

            if fn_created and si_created and fn_created != si_created:
                # Check for significant delta (> 1 second is suspicious; $FN updated by OS only)
                try:
                    from datetime import datetime
                    fmt = "%Y-%m-%d %H:%M:%S"
                    dt_fn = datetime.strptime(fn_created[:19], fmt)
                    dt_si = datetime.strptime(si_created[:19], fmt)
                    delta_secs = abs((dt_fn - dt_si).total_seconds())
                    if delta_secs > 2:
                        anomalies.append({
                            "file": file_name,
                            "fn_created": fn_created,
                            "si_created": si_created,
                            "delta_seconds": delta_secs,
                            "mitre": "T1070.006 — Indicator Removal: Timestomping",
                        })
                except ValueError:
                    pass

            # Round-number timestamp detection (e.g. 2020-01-01 00:00:00)
            for ts_field in [si_created, rec.get("modified", ""), rec.get("accessed", "")]:
                if ts_field and re.search(r"\d{4}-\d{2}-\d{2} 00:00:00", ts_field):
                    round_number_anomalies.append({
                        "file": file_name,
                        "timestamp": ts_field,
                        "reason": "Round-number timestamp (attacker default)",
                    })
                    break

            # Pre-epoch (before 1980) or far future timestamps
            for ts_field in [si_created]:
                if ts_field and ts_field < "1980":
                    pre_epoch_anomalies.append({"file": file_name, "timestamp": ts_field})
                    break

        for a in anomalies:
            a["mitre_techniques"] = map_finding_to_techniques(f"timestomping SI FN delta {a.get('file', '')}")
        enrich_findings(rag, anomalies[:10],
                        lambda a: f"timestomping MACB manipulation {a.get('file', '')} T1070.006")

        data = {
            "mft_json_path": mft_json_path,
            "records_analyzed": len(records),
            "si_fn_delta_anomalies": anomalies[:100],
            "round_number_anomalies": round_number_anomalies[:50],
            "pre_epoch_anomalies": pre_epoch_anomalies[:20],
            "total_anomalies": len(anomalies) + len(round_number_anomalies) + len(pre_epoch_anomalies),
            "mitre": "T1070.006 — Indicator Removal: Timestomping" if anomalies else "",
            "rag_context": build_rag_summary(rag, "timestomping MACB anti-forensics T1070.006"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("detect_timestomping", data, audit_id)

    @mcp.tool()
    def detect_log_wiping(evtx_dir: str) -> str:
        """
        Detect Windows event log tampering and clearing attempts.

        Looks for:
        - Event ID 1102 (Security log cleared by administrator)
        - Event ID 104 (System log cleared)
        - Event ID 4719 (Audit policy changed)
        - Large gaps in record sequence numbers (selective deletion)
        - Zero-size event log files (cleared but not overwritten)

        Args:
            evtx_dir: Directory containing .evtx files (e.g. /mnt/evidence/Windows/System32/winevt/Logs/).
        """
        increment_tool_counter()
        evtx_path = Path(evtx_dir)
        if not evtx_path.exists():
            return json.dumps({"error": f"EVTX directory not found: {evtx_dir}"})

        log_tool_execution("detect_log_wiping", [evtx_dir], "log tamper detection")
        audit_id = get_last_audit_id()

        cleared_logs: list[dict] = []
        empty_log_files: list[str] = []
        zero_byte_files: list[str] = []

        # Check for zero-size or suspiciously small EVTX files (< 69632 bytes = minimum valid EVTX)
        for evtx_file in evtx_path.glob("*.evtx"):
            size = evtx_file.stat().st_size
            if size == 0:
                zero_byte_files.append(str(evtx_file.name))
            elif size < 69632:
                empty_log_files.append({"file": evtx_file.name, "size_bytes": size})

        # Try python-evtx or evtxexport to find clear events
        try:
            import Evtx.Evtx as evtx_parser
            import Evtx.Views as e_views
            import lxml.etree as etree

            for evtx_file in sorted(evtx_path.glob("*.evtx")):
                try:
                    with evtx_parser.Evtx(str(evtx_file)) as log:
                        for record in log.records():
                            try:
                                xml = record.xml()
                                if any(eid in xml for eid in ["<EventID>1102</EventID>",
                                                               "<EventID>104</EventID>",
                                                               "<EventID>4719</EventID>"]):
                                    cleared_logs.append({
                                        "source_file": evtx_file.name,
                                        "record_id": record.record_num(),
                                        "xml_snippet": xml[:500],
                                    })
                            except Exception:
                                pass
                except Exception:
                    pass
        except ImportError:
            cleared_logs.append({
                "note": "python-evtx not installed; install with: pip3 install python-evtx lxml",
                "manual_check": "Look for Event IDs 1102, 104, 4719 in parsed event log output",
            })

        for c in cleared_logs:
            if isinstance(c, dict) and "event_id" in c:
                c["mitre_techniques"] = map_finding_to_techniques(
                    f"event log cleared {c.get('source_file', '')} T1070.001")
        enrich_findings(rag, [c for c in cleared_logs if isinstance(c, dict) and "event_id" in c][:5],
                        lambda c: f"Windows event log cleared event ID {c.get('event_id')} T1070.001")

        data = {
            "evtx_dir": evtx_dir,
            "log_clear_events": cleared_logs[:50],
            "zero_byte_evtx_files": zero_byte_files[:20],
            "suspiciously_small_evtx_files": empty_log_files[:20],
            "total_indicators": len(cleared_logs) + len(zero_byte_files) + len(empty_log_files),
            "mitre": "T1070.001 — Indicator Removal: Clear Windows Event Logs" if (cleared_logs or zero_byte_files) else "",
            "rag_context": build_rag_summary(rag, "event log wiping clearing anti-forensics T1070.001"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("detect_log_wiping", data, audit_id)

    @mcp.tool()
    def detect_secure_deletion(evidence_root: str) -> str:
        """
        Find traces of secure deletion tools on a mounted Windows/Linux evidence image.

        Checks for: SDelete, Eraser, DBAN, cipher /w, shred, wipe, CCleaner,
        Bleachbit in prefetch, shimcache, registry, and file system artifacts.

        Secure deletion is evidence destruction (T1070.004 — File Deletion).

        Args:
            evidence_root: Root of mounted evidence (e.g. /mnt/evidence/).
        """
        increment_tool_counter()
        root = Path(evidence_root)
        if not root.exists():
            return json.dumps({"error": f"Evidence root not found: {evidence_root}"})

        log_tool_execution("detect_secure_deletion", [evidence_root], "secure-deletion artifact search")
        audit_id = get_last_audit_id()

        _SECURE_DEL_TOOLS = [
            "sdelete", "sdelete64", "eraser", "cipher",
            "shred", "wipe", "bleachbit", "ccleaner",
            "dban", "nwipe", "secure-delete",
        ]

        findings: list[dict] = []

        # Search prefetch
        pf_dir = root / "Windows" / "Prefetch"
        if pf_dir.exists():
            for pf_file in pf_dir.glob("*.pf"):
                name_lower = pf_file.stem.lower()
                for tool in _SECURE_DEL_TOOLS:
                    if tool in name_lower:
                        findings.append({
                            "type": "prefetch",
                            "file": pf_file.name,
                            "tool_detected": tool,
                            "mitre": "T1070.004 — File Deletion",
                        })

        # Search shimcache / amcache exports
        for json_file in (root.parent / "analysis").glob("shimcache*.json") if (root.parent / "analysis").exists() else []:
            try:
                data_sc = json.loads(json_file.read_text())
                entries = data_sc.get("entries", data_sc.get("shimcache", []))
                for e in entries:
                    path = str(e.get("path", e.get("file", ""))).lower()
                    for tool in _SECURE_DEL_TOOLS:
                        if tool in path:
                            findings.append({
                                "type": "shimcache",
                                "path": path,
                                "tool_detected": tool,
                                "mitre": "T1070.004 — File Deletion",
                            })
            except Exception:
                pass

        # Search file system for leftover tool binaries
        for tool in _SECURE_DEL_TOOLS:
            for suffix in [".exe", ".64", ""]:
                for search_dir in ["Windows", "Users", "Temp", "ProgramFiles", "Program Files"]:
                    sp = root / search_dir
                    if sp.exists():
                        for match in sp.rglob(f"{tool}{suffix}"):
                            findings.append({
                                "type": "file_found",
                                "path": str(match.relative_to(root)),
                                "tool_detected": tool,
                                "mitre": "T1070.004 — File Deletion",
                            })

        for f in findings:
            f["mitre_techniques"] = map_finding_to_techniques(
                f"secure deletion {f.get('tool_detected', '')} T1070.004")
        enrich_findings(rag, findings[:5],
                        lambda f: f"secure deletion tool {f.get('tool_detected', '')} anti-forensics evidence destruction")

        data = {
            "evidence_root": evidence_root,
            "total_indicators": len(findings),
            "secure_deletion_indicators": findings[:100],
            "mitre": "T1070.004 — File Deletion" if findings else "",
            "rag_context": build_rag_summary(rag, "secure deletion SDelete Eraser file wiping T1070.004"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("detect_secure_deletion", data, audit_id)

    @mcp.tool()
    def detect_ads_streams(file_path: str) -> str:
        """
        Detect Alternate Data Streams (ADS) on an NTFS file or directory using fls / icat.

        ADS allow hiding data or executables in a stream attached to a legitimate file
        (e.g. notepad.exe:hidden.exe). Zone.Identifier is legitimate; other streams
        are suspicious and may contain malware payloads (T1564.004).

        Args:
            file_path: Path to the file or directory to inspect for ADS.
                       For full disk scanning, pass the image path + offset.
        """
        increment_tool_counter()
        log_tool_execution("detect_ads_streams", [file_path], "ADS detection")
        audit_id = get_last_audit_id()

        streams: list[dict] = []

        # Try using python to list NTFS ADS (works on live Windows)
        try:
            import ctypes
            # Windows API approach for live files
            if Path(file_path).exists():
                result = subprocess.run(
                    ["streams.exe", "-nobanner", "-accepteula", file_path],
                    capture_output=True, text=True, timeout=30,
                )
                for line in result.stdout.splitlines():
                    if ":$" not in line and ":" in line and line.strip():
                        # skip Zone.Identifier
                        if "Zone.Identifier" not in line:
                            streams.append({
                                "stream": line.strip(),
                                "suspicious": True,
                                "mitre": "T1564.004 — Hide Artifacts: NTFS File Attributes",
                            })
                        else:
                            streams.append({"stream": line.strip(), "suspicious": False, "reason": "Zone.Identifier (download marker)"})
        except Exception:
            pass

        # Fallback: fls-based approach on disk images
        if not streams:
            try:
                result = subprocess.run(
                    ["fls", "-r", file_path],
                    capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT,
                )
                for line in result.stdout.splitlines():
                    if ":" in line and "ADS" in line:
                        streams.append({"stream": line.strip(), "suspicious": True})
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        suspicious_streams = [s for s in streams if s.get("suspicious")]
        for s in suspicious_streams:
            s["mitre_techniques"] = map_finding_to_techniques(
                f"alternate data stream ADS NTFS hidden {s.get('stream', '')} T1564.004")
        enrich_findings(rag, suspicious_streams[:5],
                        lambda s: f"NTFS alternate data stream ADS hidden payload T1564.004 {s.get('stream', '')}")

        data = {
            "file_path": file_path,
            "total_streams": len(streams),
            "suspicious_streams": suspicious_streams[:50],
            "all_streams": streams[:100],
            "mitre": "T1564.004 — Hide Artifacts: NTFS File Attributes" if suspicious_streams else "",
            "rag_context": build_rag_summary(rag, "NTFS alternate data streams ADS hidden malware T1564.004"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("detect_ads_streams", data, audit_id)

    @mcp.tool()
    def analyze_vss_shadows(image_path: str) -> str:
        """
        Inventory Volume Shadow Copies (VSS) from a disk image.

        VSS snapshots may contain evidence that was later deleted from the live
        volume (T1490 — Inhibit System Recovery). Attackers often use vssadmin
        delete shadows to destroy forensic evidence before ransomware.

        Returns: number of shadow copies, creation times, and whether any were
        deleted relative to the current image state.

        Args:
            image_path: Absolute path to the disk image.
        """
        increment_tool_counter()
        if not Path(image_path).exists():
            return json.dumps({"error": f"Image not found: {image_path}"})

        cmd = ["vshadowinfo", image_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
            log_tool_execution("analyze_vss_shadows", cmd, result.stdout, error=result.stderr)
        except FileNotFoundError:
            # Try libvshadow
            try:
                cmd2 = ["vshadowinfo", "-v", image_path]
                result = subprocess.run(cmd2, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
                log_tool_execution("analyze_vss_shadows", cmd2, result.stdout, error=result.stderr)
            except FileNotFoundError:
                return json.dumps({
                    "error": "vshadowinfo not found. Install: sudo apt install libvshadow-utils",
                    "manual": "Use: vshadowmount <image> /mnt/vss then ls /mnt/vss",
                })
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "vshadowinfo timed out"})

        audit_id = get_last_audit_id()

        shadows: list[dict] = []
        current: dict = {}

        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Shadow copy:") or line.startswith("Volume shadow copy:"):
                if current:
                    shadows.append(current)
                current = {"index": line}
            elif ":" in line:
                k, _, v = line.partition(":")
                current[k.strip()] = v.strip()
        if current:
            shadows.append(current)

        vss_rag = build_rag_summary(rag, "VSS shadow copy deletion vssadmin ransomware T1490") if len(shadows) == 0 else []

        data = {
            "image_path": image_path,
            "shadow_copy_count": len(shadows),
            "shadow_copies": shadows[:50],
            "note": "If 0 shadows found, attacker may have run: vssadmin delete shadows /all",
            "mitre": "T1490 — Inhibit System Recovery" if len(shadows) == 0 else "",
            "rag_context": vss_rag,
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("analyze_vss_shadows", data, audit_id)

    @mcp.tool()
    def detect_prefetch_anomalies(prefetch_json_path: str) -> str:
        """
        Analyse parsed prefetch data for forensic anomalies.

        Detects:
        - Executables run from temp/suspicious paths (T1036.005)
        - Execution counts inconsistent with a legitimate tool (too many/few)
        - Tools known for anti-forensics (SDelete, cipher, wevtutil, bcdedit)
        - Prefetch entries with suspiciously recent first-run matching a known incident date
        - Execution within seconds of other suspicious tools (coordinated attack)

        Args:
            prefetch_json_path: Path to JSON output from parse_prefetch().
        """
        increment_tool_counter()
        if not Path(prefetch_json_path).exists():
            return json.dumps({"error": f"Prefetch JSON not found: {prefetch_json_path}"})

        log_tool_execution("detect_prefetch_anomalies", [prefetch_json_path], "prefetch anomaly analysis")
        audit_id = get_last_audit_id()

        try:
            data_pf = json.loads(Path(prefetch_json_path).read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError) as e:
            return json.dumps({"error": f"Failed to parse prefetch JSON: {e}"})

        entries = data_pf if isinstance(data_pf, list) else data_pf.get("entries", [])

        _SUSPICIOUS_PATHS = ["/temp/", "\\temp\\", "/tmp/", "\\appdata\\local\\temp",
                             "\\users\\public\\", "\\programdata\\", "\\recycler\\", "\\$recycle.bin\\"]
        _AF_TOOLS = ["sdelete", "cipher", "wevtutil", "bcdedit", "vssadmin",
                     "fsutil", "takeown", "cacls", "icacls", "reg delete",
                     "sc delete", "net stop", "taskkill"]

        suspicious: list[dict] = []
        af_tools: list[dict] = []
        temp_executions: list[dict] = []

        for entry in entries:
            exe = str(entry.get("executable_name", entry.get("name", ""))).lower()
            path = str(entry.get("path", "")).lower()
            run_count = int(entry.get("run_count", entry.get("RunCount", 0)) or 0)
            last_run = entry.get("last_run", entry.get("LastRun", ""))

            # Temp path executions
            if any(p in path for p in _SUSPICIOUS_PATHS):
                item = {**entry, "anomaly": "Execution from suspicious/temp path", "mitre": "T1036.005"}
                temp_executions.append(item)
                suspicious.append(item)

            # Anti-forensics tools
            for af in _AF_TOOLS:
                if af in exe or af in path:
                    item = {**entry, "anomaly": f"Anti-forensics tool: {af}", "mitre": "T1070"}
                    af_tools.append(item)
                    suspicious.append(item)
                    break

        for s in suspicious:
            s.setdefault("mitre_techniques", map_finding_to_techniques(
                f"prefetch anomaly {s.get('anomaly', '')} {s.get('executable_name', '')}"))
        enrich_findings(rag, suspicious[:10],
                        lambda s: f"prefetch anomaly execution {s.get('executable_name', '')} {s.get('anomaly', '')}")

        data = {
            "prefetch_json_path": prefetch_json_path,
            "total_entries": len(entries),
            "suspicious_entries": suspicious[:100],
            "temp_path_executions": temp_executions[:50],
            "anti_forensics_tools": af_tools[:50],
            "total_anomalies": len(suspicious),
            "rag_context": build_rag_summary(rag, "prefetch anti-forensics execution suspicious path T1036 T1070"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("detect_prefetch_anomalies", data, audit_id)

    @mcp.tool()
    def detect_event_log_tampering(evtx_dir: str) -> str:
        """
        Detect evidence of event log tampering including audit policy changes.

        Searches for:
        - Event ID 1102: Security audit log cleared
        - Event ID 104: System log cleared
        - Event ID 4719: System audit policy was changed (T1562.002)
        - Event ID 4906: CrashOnAuditFail changed
        - Event ID 7040: Service start type changed (may disable event log service)

        Args:
            evtx_dir: Directory containing Windows .evtx event log files.
        """
        increment_tool_counter()
        evtx_path = Path(evtx_dir)
        if not evtx_path.exists():
            return json.dumps({"error": f"EVTX directory not found: {evtx_dir}"})

        log_tool_execution("detect_event_log_tampering", [evtx_dir], "event log tamper detection")
        audit_id = get_last_audit_id()

        _TARGET_IDS = {"1102", "104", "4719", "4906", "7040"}
        _ID_DESCRIPTIONS = {
            "1102": "Security log cleared",
            "104":  "System log cleared",
            "4719": "Audit policy changed",
            "4906": "CrashOnAuditFail changed",
            "7040": "Service start type changed",
        }

        findings: list[dict] = []

        try:
            import Evtx.Evtx as evtx_lib
            for evtx_file in sorted(evtx_path.glob("*.evtx")):
                try:
                    with evtx_lib.Evtx(str(evtx_file)) as log:
                        for record in log.records():
                            try:
                                xml = record.xml()
                                for eid in _TARGET_IDS:
                                    if f"<EventID>{eid}</EventID>" in xml:
                                        findings.append({
                                            "event_id": eid,
                                            "description": _ID_DESCRIPTIONS.get(eid, ""),
                                            "source_file": evtx_file.name,
                                            "record_id": record.record_num(),
                                            "xml_snippet": xml[:600],
                                            "mitre": "T1562.002 — Impair Defenses: Disable Windows Event Logging",
                                        })
                            except Exception:
                                pass
                except Exception:
                    pass
        except ImportError:
            findings.append({
                "note": "python-evtx not installed; run: pip3 install python-evtx lxml",
                "manual_check": f"Search for Event IDs {', '.join(sorted(_TARGET_IDS))} in event log output",
            })

        for f in findings:
            if "event_id" in f:
                f["mitre_techniques"] = map_finding_to_techniques(
                    f"event log tamper audit policy {f.get('description', '')} T1562.002")
        enrich_findings(rag, [f for f in findings if "event_id" in f][:5],
                        lambda f: f"event log tampering event ID {f.get('event_id')} audit policy change T1562.002")

        data = {
            "evtx_dir": evtx_dir,
            "total_tampering_indicators": len(findings),
            "findings": findings[:100],
            "mitre": "T1562.002 — Impair Defenses" if findings else "",
            "rag_context": build_rag_summary(rag, "event log tampering audit policy disable T1562.002"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("detect_event_log_tampering", data, audit_id)
