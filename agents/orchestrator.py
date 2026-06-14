"""
LangGraph multi-agent forensic orchestrator.

Fan-out architecture: memory, disk, network, and browser agents run in sequence,
results are synthesized, then a final report is generated.
Supports all 18 DeepSIFT tool categories via the underlying MCP parsers.
"""
from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import TypedDict, Annotated
import operator

logger = logging.getLogger(__name__)


class ForensicState(TypedDict):
    image_path: str
    disk_image_path: str
    evidence_mount_path: str
    browser_profile_dir: str
    email_export_dir: str
    case_dir: str
    memory_findings: dict
    disk_findings: dict
    network_findings: dict
    browser_findings: dict
    synthesis: dict
    final_report: dict
    iterations: int
    errors: Annotated[list[str], operator.add]
    status: str


MAX_ITERATIONS = 10


class ForensicOrchestrator:
    def __init__(self, rag=None):
        self.rag = rag
        self.graph = self._build_graph()

    def _build_graph(self):
        from langgraph.graph import StateGraph, END

        wf = StateGraph(ForensicState)

        wf.add_node("memory_agent", self._memory_agent)
        wf.add_node("disk_agent", self._disk_agent)
        wf.add_node("network_agent", self._network_agent)
        wf.add_node("browser_agent", self._browser_agent)
        wf.add_node("synthesis_agent", self._synthesis_agent)
        wf.add_node("report_agent", self._report_agent)

        wf.set_entry_point("memory_agent")
        wf.add_edge("memory_agent", "disk_agent")
        wf.add_edge("disk_agent", "network_agent")
        wf.add_edge("network_agent", "browser_agent")
        wf.add_edge("browser_agent", "synthesis_agent")
        wf.add_edge("synthesis_agent", "report_agent")
        wf.add_edge("report_agent", END)

        return wf.compile()

    # ── Specialist agents ─────────────────────────────────────────────────

    def _memory_agent(self, state: ForensicState) -> dict:
        """Memory forensics: process list, injected code, command lines."""
        logger.info("[memory_agent] Starting memory analysis")
        findings: dict = {}

        try:
            from mcp_server.config import VOLATILITY_CMD
            from mcp_server.parsers.pslist_parser import parse_pslist, analyze_processes
            from mcp_server.parsers.malfind_parser import parse_malfind
            from mcp_server.parsers.mitre_auto_map import map_process_anomalies, map_injection, map_cmdline
            from mcp_server.tools.volatility import _parse_cmdline
            import subprocess

            image = state["image_path"]

            # --- Process list ---
            result = subprocess.run(
                VOLATILITY_CMD + ["-f", image, "windows.pslist"],
                capture_output=True, text=True, timeout=300,
            )
            processes = analyze_processes(parse_pslist(result.stdout))
            suspicious_procs = [p for p in processes if p["suspicious"]]
            for proc in suspicious_procs:
                proc["mitre_techniques"] = map_process_anomalies(proc.get("anomalies", []))
                if self.rag:
                    proc["threat_intel"] = self.rag.query(
                        f"suspicious process {proc['name']} anomalies: {proc.get('anomalies', [])}", n_results=2
                    )
            findings["processes"] = processes
            findings["suspicious_processes"] = suspicious_procs

            # --- Injected code (malfind) ---
            result = subprocess.run(
                VOLATILITY_CMD + ["-f", image, "windows.malfind"],
                capture_output=True, text=True, timeout=300,
            )
            injections = parse_malfind(result.stdout)
            high_risk = [i for i in injections if i.get("risk_level") == "high"]
            for inj in injections:
                inj["mitre_techniques"] = map_injection(
                    inj.get("injection_type", ""), inj.get("protection", "")
                )
            findings["injections"] = injections
            findings["high_risk_injections"] = high_risk

            # --- Command lines (parsed — no raw text stored) ---
            result = subprocess.run(
                VOLATILITY_CMD + ["-f", image, "windows.cmdline"],
                capture_output=True, text=True, timeout=300,
            )
            cmdlines = _parse_cmdline(result.stdout)
            suspicious_cmds = [c for c in cmdlines if c.get("suspicious")]
            for cmd in suspicious_cmds:
                cmd["mitre_techniques"] = map_cmdline(cmd.get("cmdline", ""))
            findings["suspicious_cmdlines"] = suspicious_cmds
            findings["all_cmdlines"] = cmdlines

            logger.info(
                f"[memory_agent] Done: {len(processes)} processes, "
                f"{len(suspicious_procs)} suspicious, "
                f"{len(high_risk)} high-risk injections, "
                f"{len(suspicious_cmds)} suspicious cmdlines"
            )

        except Exception as e:
            logger.error(f"[memory_agent] Error: {e}")
            findings["error"] = str(e)

        return {
            "memory_findings": findings,
            "iterations": state["iterations"] + 1,
        }

    def _disk_agent(self, state: ForensicState) -> dict:
        """Disk forensics: event logs, prefetch, shimcache, LNK files."""
        disk_image = state.get("disk_image_path", "")
        evidence_mount = state.get("evidence_mount_path", "")
        findings: dict = {}

        if not disk_image and not evidence_mount:
            logger.info("[disk_agent] No disk image/mount provided — skipping disk analysis")
            findings["note"] = (
                "No disk image provided. Disk analysis skipped. "
                "Pass --disk-image or --evidence-mount to enable disk artifact analysis."
            )
            return {"disk_findings": findings}

        logger.info(f"[disk_agent] Starting disk analysis on {disk_image or evidence_mount}")
        mount = evidence_mount or disk_image

        try:
            from mcp_server.config import EZ_TOOLS_DIR, EXPORTS_DIR
            import subprocess
            import csv as _csv

            def _ez(tool: str) -> list:
                # SIFT (Linux): EZ Tools ship as .NET DLLs run via dotnet, not
                # Windows .exe. Resolve <Tool>.dll anywhere under EZ_TOOLS_DIR
                # (some, e.g. EvtxECmd, live in a subdir) and invoke via dotnet.
                name = tool[:-4] if tool.lower().endswith(".exe") else tool
                # Case-insensitive match: Linux globs are case-sensitive, so e.g.
                # "SbECmd.dll" would miss the on-disk "SBECmd.dll".
                want = f"{name}.dll".lower()
                hits = [p for p in EZ_TOOLS_DIR.glob("**/*.dll") if p.name.lower() == want]
                dll = str(hits[0]) if hits else str(EZ_TOOLS_DIR / f"{name}.dll")
                return ["dotnet", dll]

            def _ez_csv(cmd: list, out_subdir: str) -> list[dict]:
                out = str(EXPORTS_DIR / out_subdir)
                Path(out).mkdir(parents=True, exist_ok=True)
                # Clear any CSVs from a prior run — otherwise this call re-reads
                # stale output (which can balloon to multiple GB and appear to hang).
                for _old in Path(out).glob("*.csv"):
                    try:
                        _old.unlink()
                    except Exception:
                        pass
                try:
                    subprocess.run(cmd + ["--csv", out], capture_output=True,
                                   text=True, timeout=900)
                except Exception:
                    return []
                rows = []
                for f in Path(out).glob("*.csv"):
                    try:
                        with open(f, encoding="utf-8-sig") as fh:
                            rows.extend(list(_csv.DictReader(fh)))
                    except Exception:
                        continue
                return rows

            # Event logs (resolve winevt/Logs case-insensitively for Linux mounts)
            _winevt = Path(mount) / "Windows/System32/winevt"
            evtx_dir = ""
            for _cand in ("Logs", "logs"):
                if (_winevt / _cand).exists():
                    evtx_dir = str(_winevt / _cand)
                    break
            if evtx_dir:
                DEFAULT_IDS = "4624,4625,4648,4672,4697,4698,4703,7045,4103,4104,5861,1149,4778"
                # Parsing every channel + all rotated Security archives can mean
                # millions of records and many minutes. Curate a high-value set:
                # the live security/system/RDP/PowerShell channels, plus only the
                # most-recent rotated Security archives (closest to capture — they
                # cover the days just before it, where an incident lives). Bounded,
                # no hard-coded dates, and an order of magnitude faster.
                logs = Path(evtx_dir)
                wanted = []
                for pat in ("Security.evtx", "System.evtx",
                            "Microsoft-Windows-TerminalServices-*Operational.evtx",
                            "Microsoft-Windows-PowerShell*Operational.evtx",
                            "Microsoft-Windows-WinRM*Operational.evtx",
                            "Microsoft-Windows-TaskScheduler*Operational.evtx"):
                    wanted.extend(sorted(logs.glob(pat)))
                archives = sorted(logs.glob("Archive-Security-*.evtx"),
                                  key=lambda p: p.stat().st_mtime, reverse=True)[:20]
                wanted.extend(archives)
                # Stage selected files (symlinks — evidence stays read-only) and run
                # EvtxECmd over just that set.
                staged = str(EXPORTS_DIR / "disk_evtx_src")
                Path(staged).mkdir(parents=True, exist_ok=True)
                for f in wanted:
                    link = Path(staged) / f.name
                    try:
                        if not link.exists():
                            link.symlink_to(f)
                    except Exception:
                        pass
                logger.info(f"[disk_agent] Event logs: parsing {len(wanted)} curated "
                            f"evtx file(s) (live channels + {len(archives)} recent archives)")
                rows = _ez_csv(
                    _ez("EvtxECmd.exe") + ["-d", staged, "--inc", DEFAULT_IDS],
                    "disk_evtx"
                )
                events = [{
                    "timestamp": r.get("TimeCreated", ""),
                    "event_id": r.get("EventId", ""),
                    "channel": r.get("Channel", ""),
                    "user": r.get("UserName", ""),
                    "description": r.get("MapDescription", ""),
                    "payload": r.get("PayloadData1", "")[:300],
                } for r in rows]
                events.sort(key=lambda x: x.get("timestamp", ""))
                findings["event_log_count"] = len(events)
                # Keep ALL high-signal security events (failed/explicit/RDP logons,
                # service & task installs, PowerShell, WMI) regardless of volume —
                # these are rare and pinpoint the incident window. Successful logons
                # (4624) are noisy, so sample them evenly across the whole timeline
                # so every day (incl. the incident date) is represented rather than
                # only keeping the earliest events.
                HIGH_SIGNAL = {"4625", "4648", "4697", "4698", "4703", "7045",
                               "4103", "4104", "5861", "1149", "4778"}
                # Date-stratified retention: cap events PER DAY so no day (incl. the
                # incident date) is crowded out by a high-volume day. High-signal
                # events (failed/explicit/RDP logons, service/task installs) are kept
                # ahead of routine 4624/4672 within each day's budget.
                from collections import defaultdict
                per_day: dict = defaultdict(list)
                for e in events:
                    per_day[str(e.get("timestamp", ""))[:10]].append(e)
                PER_DAY_CAP = 120
                kept = []
                for day, evs in per_day.items():
                    evs.sort(key=lambda x: (str(x.get("event_id")) not in HIGH_SIGNAL,
                                            x.get("timestamp", "")))
                    kept.extend(evs[:PER_DAY_CAP])
                kept.sort(key=lambda x: x.get("timestamp", ""))
                findings["event_logs"] = kept[:6000]
                findings["high_signal_event_count"] = sum(
                    1 for e in events if str(e.get("event_id")) in HIGH_SIGNAL)
                logger.info(
                    f"[disk_agent] Event logs: {len(events)} total across "
                    f"{len(per_day)} day(s), kept {len(findings['event_logs'])} "
                    f"(<= {PER_DAY_CAP}/day)"
                )

            # Prefetch
            pf_dir = str(Path(mount) / "Windows/Prefetch")
            if Path(pf_dir).exists():
                rows = _ez_csv(_ez("PECmd.exe") + ["-d", pf_dir], "disk_prefetch")
                findings["prefetch"] = [{
                    "executable": r.get("ExecutableName", ""),
                    "run_count": r.get("RunCount", ""),
                    "last_run": r.get("LastRun", ""),
                } for r in rows]
                logger.info(f"[disk_agent] Prefetch: {len(findings['prefetch'])} entries")

            # Shimcache
            system_hive = str(Path(mount) / "Windows/System32/config/SYSTEM")
            if Path(system_hive).exists():
                rows = _ez_csv(
                    _ez("AppCompatCacheParser.exe") + ["-f", system_hive],
                    "disk_shimcache"
                )
                findings["shimcache"] = [{
                    "path": r.get("Path", ""),
                    "last_modified": r.get("LastModifiedTimeUTC", ""),
                    "executed": r.get("Executed", ""),
                } for r in rows]
                logger.info(f"[disk_agent] Shimcache: {len(findings['shimcache'])} entries")

            # LNK files — target the per-user Recent folders (recently accessed
            # files) instead of recursing all of \Users (which traverses huge
            # AppData trees and times out with no useful gain).
            users_root = Path(mount) / "Users"
            recent_dirs = []
            if users_root.exists():
                for udir in users_root.iterdir():
                    rec = udir / "AppData/Roaming/Microsoft/Windows/Recent"
                    if rec.exists():
                        recent_dirs.append(str(rec))
            lnk_files = []
            for rec in recent_dirs:
                rows = _ez_csv(_ez("LECmd.exe") + ["-d", rec], "disk_lnk")
                lnk_files.extend({
                    "source": r.get("SourceFile", ""),
                    "target": r.get("LocalPath", ""),
                    "accessed": r.get("TargetAccessed", ""),
                } for r in rows)
            if recent_dirs:
                findings["lnk_files"] = lnk_files
                logger.info(
                    f"[disk_agent] LNK files: {len(lnk_files)} entries "
                    f"from {len(recent_dirs)} Recent folder(s)"
                )

        except Exception as e:
            logger.error(f"[disk_agent] Error: {e}")
            findings["error"] = str(e)

        return {"disk_findings": findings}

    def _network_agent(self, state: ForensicState) -> dict:
        """Network forensics: connections + MITRE mapping."""
        logger.info("[network_agent] Starting network analysis")
        findings: dict = {}

        try:
            from mcp_server.config import VOLATILITY_CMD
            from mcp_server.parsers.netscan_parser import parse_netscan, get_external_ips
            from mcp_server.parsers.mitre_auto_map import map_network_connection
            import subprocess

            image = state["image_path"]
            result = subprocess.run(
                VOLATILITY_CMD + ["-f", image, "windows.netscan"],
                capture_output=True, text=True, timeout=300,
            )
            connections = parse_netscan(result.stdout)
            external_ips = get_external_ips(connections)
            suspicious = [c for c in connections if c.get("suspicious")]
            for c in suspicious:
                c["mitre_techniques"] = map_network_connection(c.get("ioc_flags", []))
            findings["connections"] = connections
            findings["external_ips"] = external_ips
            findings["suspicious_connections"] = suspicious

            logger.info(
                f"[network_agent] Done: {len(connections)} connections, "
                f"{len(external_ips)} external IPs, {len(suspicious)} suspicious"
            )

        except Exception as e:
            logger.error(f"[network_agent] Error: {e}")
            findings["error"] = str(e)

        return {"network_findings": findings}

    def _browser_agent(self, state: ForensicState) -> dict:
        """Browser & cloud-storage artifact analysis across ALL installed browsers
        and ALL profiles (Chrome/Edge/Brave + Firefox). A multi-user incident may
        touch a non-default profile, so analysing only the first profile (the old
        behaviour) misses incident-window browsing entirely."""
        findings: dict = {}
        mount = state.get("evidence_mount_path", "") or state.get("browser_profile_dir", "")
        if not mount:
            logger.info("[browser_agent] No evidence mount — skipping browser analysis")
            findings["note"] = "No evidence_mount_path in state."
            return {"browser_findings": findings}

        try:
            from mcp_server.parsers.browser_parser import (
                classify_chrome_rows, classify_downloads, build_browser_summary,
            )
            from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques

            histories, ff_places = self._discover_browser_histories(mount)
            all_rows: list[dict] = []
            all_downloads: list[dict] = []

            for label, db in histories:        # Chromium: Chrome/Edge/Brave profiles
                v, d = self._read_chromium_history(db, label)
                all_rows.extend(v)
                all_downloads.extend(d)
            for label, db in ff_places:         # Firefox profiles
                all_rows.extend(self._read_firefox_history(db, label))

            classified, suspicious_urls = classify_chrome_rows(all_rows)
            for u in suspicious_urls:
                u["mitre_techniques"] = map_finding_to_techniques(
                    f"browser URL {u.get('url', '')} {','.join(u.get('threat_flags', []))}"
                )
            _, suspicious_dl = classify_downloads(all_downloads)

            # Sort by recency so the report's window slice shows incident activity.
            classified.sort(key=lambda r: r.get("last_visit", ""), reverse=True)
            findings["chrome_history"] = classified[:600]
            findings["suspicious_urls"] = suspicious_urls
            findings["downloads"] = all_downloads[:200]
            findings["suspicious_downloads"] = suspicious_dl
            findings["browser_summary"] = build_browser_summary(classified, suspicious_urls)
            findings["profiles_analyzed"] = [lbl for lbl, _ in histories] + [lbl for lbl, _ in ff_places]
            logger.info(
                f"[browser_agent] {len(histories)+len(ff_places)} profile(s): "
                f"{len(classified)} URLs, {len(suspicious_urls)} cloud/exfil/suspicious, "
                f"{len(all_downloads)} downloads"
            )

            if self.rag and suspicious_urls:
                from mcp_server.parsers.rag_enrichment import enrich_findings
                enrich_findings(
                    self.rag, suspicious_urls[:8],
                    lambda u: f"browser exfiltration cloud URL {u.get('url', '')} "
                              f"{','.join(u.get('threat_flags', []))}",
                )
        except Exception as e:
            logger.error(f"[browser_agent] Error: {e}")
            findings["error"] = str(e)

        return {"browser_findings": findings}

    # ── Browser helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _discover_browser_histories(mount: str):
        """Return (chromium_histories, firefox_places) as lists of (label, db_path)
        covering every profile of every installed browser under the evidence mount."""
        users = Path(mount) / "Users"
        chromium, firefox = [], []
        if not users.exists():
            return chromium, firefox
        chromium_roots = [
            ("Chrome", "AppData/Local/Google/Chrome/User Data"),
            ("Edge", "AppData/Local/Microsoft/Edge/User Data"),
            ("Brave", "AppData/Local/BraveSoftware/Brave-Browser/User Data"),
        ]
        try:
            user_dirs = [u for u in users.iterdir() if u.is_dir()]
        except Exception:
            return chromium, firefox
        for udir in user_dirs:
            for bname, rel in chromium_roots:
                ud = udir / rel
                if not ud.exists():
                    continue
                for prof in ud.iterdir():
                    hist = prof / "History"
                    if hist.exists():
                        chromium.append((f"{udir.name}/{bname}/{prof.name}", str(hist)))
            ffroot = udir / "AppData/Roaming/Mozilla/Firefox/Profiles"
            if ffroot.exists():
                for prof in ffroot.iterdir():
                    pl = prof / "places.sqlite"
                    if pl.exists():
                        firefox.append((f"{udir.name}/Firefox/{prof.name}", str(pl)))
        return chromium, firefox

    @staticmethod
    def _webkit_to_utc(ts) -> str:
        from datetime import datetime, timedelta, timezone
        try:
            ts = int(ts)
            if ts <= 0:
                return ""
            return (datetime(1601, 1, 1, tzinfo=timezone.utc)
                    + timedelta(microseconds=ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return ""

    @classmethod
    def _read_chromium_history(cls, db: str, label: str):
        import sqlite3, shutil, tempfile
        visits, downloads = [], []
        tmp = tempfile.mktemp(suffix=".db")
        try:
            shutil.copy2(db, tmp)
            conn = sqlite3.connect(tmp)
            for r in conn.execute(
                "SELECT url,title,visit_count,last_visit_time FROM urls WHERE last_visit_time>0"
            ).fetchall():
                visits.append({"url": r[0], "title": r[1], "visit_count": r[2],
                               "last_visit": cls._webkit_to_utc(r[3]), "profile": label})
            try:
                for r in conn.execute(
                    "SELECT target_path,tab_url,total_bytes,start_time FROM downloads"
                ).fetchall():
                    downloads.append({"target_path": r[0], "url": r[1], "bytes": r[2],
                                      "start": cls._webkit_to_utc(r[3]), "profile": label})
            except Exception:
                pass
            conn.close()
        except Exception:
            pass
        finally:
            Path(tmp).unlink(missing_ok=True)
        return visits, downloads

    @staticmethod
    def _read_firefox_history(db: str, label: str):
        import sqlite3, shutil, tempfile
        from datetime import datetime, timezone
        visits = []
        tmp = tempfile.mktemp(suffix=".sqlite")
        try:
            shutil.copy2(db, tmp)
            conn = sqlite3.connect(tmp)
            for r in conn.execute(
                "SELECT url,title,visit_count,last_visit_date FROM moz_places "
                "WHERE last_visit_date IS NOT NULL"
            ).fetchall():
                try:
                    lv = datetime.fromtimestamp(r[3] / 1_000_000, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    lv = ""
                visits.append({"url": r[0], "title": r[1], "visit_count": r[2],
                               "last_visit": lv, "profile": label})
            conn.close()
        except Exception:
            pass
        finally:
            Path(tmp).unlink(missing_ok=True)
        return visits

    def _synthesis_agent(self, state: ForensicState) -> dict:
        """Cross-correlates memory, disk, network, and browser findings. Aggregates MITRE techniques."""
        logger.info("[synthesis_agent] Correlating findings")
        memory = state.get("memory_findings", {})
        disk = state.get("disk_findings", {})
        network = state.get("network_findings", {})
        browser = state.get("browser_findings", {})

        suspicious_procs = {
            p["pid"]: p["name"]
            for p in memory.get("suspicious_processes", [])
        }
        suspicious_conns = [
            c for c in network.get("suspicious_connections", [])
            if c.get("pid") in suspicious_procs
        ]

        # Aggregate MITRE technique IDs from all sources
        mitre_tids: set[str] = set()
        for proc in memory.get("suspicious_processes", []):
            for t in proc.get("mitre_techniques", []):
                mitre_tids.add(t["technique_id"])
        for inj in memory.get("high_risk_injections", []):
            for t in inj.get("mitre_techniques", []):
                mitre_tids.add(t["technique_id"])
        for cmd in memory.get("suspicious_cmdlines", []):
            for t in cmd.get("mitre_techniques", []):
                mitre_tids.add(t["technique_id"])
        for conn in network.get("suspicious_connections", []):
            for t in conn.get("mitre_techniques", []):
                mitre_tids.add(t["technique_id"])
        for url in browser.get("suspicious_urls", []):
            for t in url.get("mitre_techniques", []):
                mitre_tids.add(t["technique_id"])

        synthesis = {
            "correlated_suspicious_processes": list(suspicious_procs.values()),
            "processes_with_network_activity": [
                {
                    "pid": c["pid"],
                    "process": suspicious_procs.get(c["pid"], "unknown"),
                    "foreign_addr": c["foreign_addr"],
                    "foreign_port": c["foreign_port"],
                    "state": c["state"],
                }
                for c in suspicious_conns
            ],
            "high_risk_injections": memory.get("high_risk_injections", []),
            "external_ips": network.get("external_ips", []),
            "suspicious_browser_urls": browser.get("suspicious_urls", []),
            "browser_downloads": browser.get("downloads", []),
            "mitre_techniques": sorted(mitre_tids),
            "total_suspicious_processes": len(suspicious_procs),
            "total_suspicious_connections": len(suspicious_conns),
        }

        if self.rag and synthesis["external_ips"]:
            for ip in synthesis["external_ips"][:5]:
                context = self.rag.query(f"malicious IP {ip} C2 command and control")
                synthesis.setdefault("threat_intel", {})[ip] = context

        return {"synthesis": synthesis}

    def _report_agent(self, state: ForensicState) -> dict:
        """Generates the final structured report and saves it to case_dir/findings.json."""
        logger.info("[report_agent] Generating final report")
        synthesis = state.get("synthesis", {})
        memory = state.get("memory_findings", {})
        disk = state.get("disk_findings", {})
        browser = state.get("browser_findings", {})

        # Build timeline from disk event logs. Prefer high-signal (non-4624)
        # events and sample EVENLY across the whole period so every day — incl.
        # the incident date — is represented, not just the earliest burst.
        evts = disk.get("event_logs", [])
        hs = [e for e in evts if str(e.get("event_id")) != "4624"]
        src = hs if hs else evts
        step = max(1, len(src) // 200)
        timeline_src = src[::step][:200]
        timeline = []
        for evt in timeline_src:
            if evt.get("timestamp"):
                timeline.append(f"{evt['timestamp']} [Event {evt.get('event_id', '?')}] {evt.get('description', '')}")

        # Disk/browser exfiltration & access evidence (the artifacts a memory-only
        # analysis structurally cannot see).
        files_accessed = [
            f"{l.get('target', '')} (accessed {l.get('accessed', '')})"
            for l in disk.get("lnk_files", []) if l.get("target")
        ][:100]
        browser_activity = [
            f"{v.get('last_visit', '')} {v.get('url', '')}"
            for v in browser.get("chrome_history", []) if v.get("url")
        ][:200]
        suspicious_browser_urls = synthesis.get("suspicious_browser_urls", [])
        cloud_services_used = sorted({
            u.get("url", "") for u in suspicious_browser_urls
            if "CLOUD_EXFIL_DOMAIN" in u.get("threat_flags", [])
        })
        downloads = [
            f"{d.get('start', '')} {d.get('target_path', '')} <- {d.get('url', '')}"
            for d in browser.get("downloads", []) if d.get("target_path")
        ][:100]

        # Confidence heuristic
        n_suspicious = synthesis.get("total_suspicious_processes", 0)
        n_inject = len(synthesis.get("high_risk_injections", []))
        n_conns = synthesis.get("total_suspicious_connections", 0)
        if n_suspicious >= 2 or n_inject >= 1:
            confidence = "high"
        elif n_suspicious >= 1 or n_conns >= 1:
            confidence = "medium"
        else:
            confidence = "low"

        report = {
            "image_path": state.get("image_path", ""),
            "summary": self._build_summary(synthesis, memory),
            "suspicious_processes": [
                f"{p['name']} (PID {p['pid']})"
                for p in memory.get("suspicious_processes", [])
            ],
            "network_iocs": synthesis.get("external_ips", []),
            "suspicious_browser_urls": synthesis.get("suspicious_browser_urls", []),
            "mitre_techniques": synthesis.get("mitre_techniques", []),
            "timeline": timeline,
            "confidence": confidence,
            "high_risk_injections": len(synthesis.get("high_risk_injections", [])),
            "processes_with_c2": synthesis.get("processes_with_network_activity", []),
            "files_accessed": files_accessed,
            "browser_activity": browser_activity,
            "cloud_services_used": cloud_services_used,
            "downloads": downloads,
            "event_log_count": disk.get("event_log_count", 0),
            "iterations_used": state.get("iterations", 0),
            "status": "complete",
        }

        # Save to case_dir/findings.json (no double-nesting)
        case_dir = Path(state.get("case_dir", "."))
        case_dir.mkdir(parents=True, exist_ok=True)
        with open(case_dir / "findings.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"[report_agent] Report saved to {case_dir / 'findings.json'}")
        return {"final_report": report, "status": "complete"}

    def _build_summary(self, synthesis: dict, memory: dict) -> str:
        n_procs = synthesis.get("total_suspicious_processes", 0)
        n_conns = synthesis.get("total_suspicious_connections", 0)
        n_inject = len(synthesis.get("high_risk_injections", []))
        ips = synthesis.get("external_ips", [])
        mitre = synthesis.get("mitre_techniques", [])
        browser_urls = synthesis.get("suspicious_browser_urls", [])

        parts = []
        if n_procs:
            parts.append(f"{n_procs} suspicious process(es) detected")
        if n_inject:
            parts.append(f"{n_inject} high-risk memory injection(s) found")
        if n_conns:
            parts.append(f"{n_conns} suspicious network connection(s) observed")
        if ips:
            parts.append(f"External IPs contacted: {', '.join(ips[:5])}")
        if browser_urls:
            parts.append(f"{len(browser_urls)} suspicious browser URL(s) identified")
        if mitre:
            parts.append(f"ATT&CK techniques: {', '.join(mitre[:5])}")
        if not parts:
            parts.append("No high-confidence indicators identified — manual review recommended")

        return ". ".join(parts) + "."

    # ── Public interface ───────────────────────────────────────────────────

    @staticmethod
    def _discover_browser_profile(evidence_mount: str) -> str:
        """Find a Chromium-family 'User Data' dir (Chrome/Edge) under the mount.

        Returns the first profile directory that actually contains a History DB,
        or "" if none found. Case-insensitive to suit NTFS-on-Linux mounts.
        """
        users = Path(evidence_mount) / "Users"
        if not users.exists():
            return ""
        rels = [
            "AppData/Local/Google/Chrome/User Data",
            "AppData/Local/Microsoft/Edge/User Data",
            "AppData/Local/BraveSoftware/Brave-Browser/User Data",
        ]
        try:
            user_dirs = [u for u in users.iterdir() if u.is_dir()]
        except Exception:
            return ""
        for udir in user_dirs:
            for rel in rels:
                ud = udir / rel
                if ud.exists() and (ud / "Default" / "History").exists():
                    return str(ud)
        return ""

    def investigate(
        self,
        image_path: str,
        case_dir: str = "./analysis",
        disk_image_path: str = "",
        evidence_mount_path: str = "",
        browser_profile_dir: str = "",
        email_export_dir: str = "",
    ) -> dict:
        """
        Run full multi-agent investigation.

        Args:
            image_path:          Path to memory image (.raw, .vmem, .mem).
            case_dir:            Directory for output files.
            disk_image_path:     Optional path to disk image (.E01, .dd) for disk analysis.
            evidence_mount_path: Optional path to mounted evidence volume for EZ Tools.
            browser_profile_dir: Optional path to browser profile directory for artifact analysis.
            email_export_dir:    Optional path to exported email directory (.pst/.ost/.eml).

        Returns:
            findings dict with summary, suspicious_processes, network_iocs,
            mitre_techniques, timeline, confidence — same schema as finish_analysis.
        """
        # Auto-discover a browser profile on the evidence mount when one was not
        # supplied. The Nov-13-style incident evidence (browsing, cloud usage,
        # downloads) lives on disk, so this lets the browser_agent run from a
        # plain --evidence-mount with no extra flags.
        if not browser_profile_dir and evidence_mount_path:
            browser_profile_dir = self._discover_browser_profile(evidence_mount_path)
            if browser_profile_dir:
                logger.info(f"[orchestrator] Auto-discovered browser profile: {browser_profile_dir}")

        initial: ForensicState = {
            "image_path": image_path,
            "disk_image_path": disk_image_path,
            "evidence_mount_path": evidence_mount_path,
            "browser_profile_dir": browser_profile_dir,
            "email_export_dir": email_export_dir,
            "case_dir": case_dir,
            "memory_findings": {},
            "disk_findings": {},
            "network_findings": {},
            "browser_findings": {},
            "synthesis": {},
            "final_report": {},
            "iterations": 0,
            "errors": [],
            "status": "running",
        }
        final_state = self.graph.invoke(initial)
        return final_state.get("final_report", {})


if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Run DeepSIFT multi-agent investigation")
    parser.add_argument("--image", required=True, help="Path to forensic memory image")
    parser.add_argument("--case-dir", default="./analysis", help="Output directory for findings")
    parser.add_argument("--disk-image", default="", help="Optional path to disk image")
    parser.add_argument("--evidence-mount", default="", help="Optional path to mounted evidence volume")
    parser.add_argument("--browser-dir", default="", help="Optional path to browser profile directory")
    parser.add_argument("--email-dir", default="", help="Optional path to email export directory")
    args = parser.parse_args()

    orchestrator = ForensicOrchestrator()
    report = orchestrator.investigate(
        args.image, args.case_dir,
        disk_image_path=args.disk_image,
        evidence_mount_path=args.evidence_mount,
        browser_profile_dir=args.browser_dir,
        email_export_dir=args.email_dir,
    )
    print(json.dumps(report, indent=2, default=str))
