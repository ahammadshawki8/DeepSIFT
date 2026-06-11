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

            def _ez(tool: str) -> str:
                return str(EZ_TOOLS_DIR / tool)

            def _ez_csv(cmd: list, out_subdir: str) -> list[dict]:
                out = str(EXPORTS_DIR / out_subdir)
                Path(out).mkdir(parents=True, exist_ok=True)
                try:
                    subprocess.run(cmd + ["--csv", out], capture_output=True,
                                   text=True, timeout=300)
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

            # Event logs
            evtx_dir = str(Path(mount) / "Windows/System32/winevt/logs")
            if Path(evtx_dir).exists():
                DEFAULT_IDS = "4624,4625,4648,4672,4697,4698,4703,7045,4103,4104,5861,1149,4778"
                rows = _ez_csv(
                    [_ez("EvtxECmd.exe"), "-d", evtx_dir, "--inc", DEFAULT_IDS],
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
                findings["event_logs"] = events[:500]
                findings["event_log_count"] = len(events)
                logger.info(f"[disk_agent] Event logs: {len(events)} events")

            # Prefetch
            pf_dir = str(Path(mount) / "Windows/Prefetch")
            if Path(pf_dir).exists():
                rows = _ez_csv([_ez("PECmd.exe"), "-d", pf_dir], "disk_prefetch")
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
                    [_ez("AppCompatCacheParser.exe"), "-f", system_hive],
                    "disk_shimcache"
                )
                findings["shimcache"] = [{
                    "path": r.get("Path", ""),
                    "last_modified": r.get("LastModifiedTimeUTC", ""),
                    "executed": r.get("Executed", ""),
                } for r in rows]
                logger.info(f"[disk_agent] Shimcache: {len(findings['shimcache'])} entries")

            # LNK files
            lnk_dir = str(Path(mount) / "Users")
            if Path(lnk_dir).exists():
                rows = _ez_csv([_ez("LECmd.exe"), "-d", lnk_dir, "--all"], "disk_lnk")
                findings["lnk_files"] = [{
                    "source": r.get("SourceFile", ""),
                    "target": r.get("LocalPath", ""),
                    "accessed": r.get("TargetAccessed", ""),
                } for r in rows]
                logger.info(f"[disk_agent] LNK files: {len(findings['lnk_files'])} entries")

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
        """Browser and cloud storage artifact analysis."""
        browser_dir = state.get("browser_profile_dir", "")
        findings: dict = {}

        if not browser_dir:
            logger.info("[browser_agent] No browser profile dir provided — skipping")
            findings["note"] = "No browser_profile_dir in state — pass it to enable browser analysis."
            return {"browser_findings": findings}

        logger.info(f"[browser_agent] Analyzing browser artifacts in {browser_dir}")

        try:
            from mcp_server.parsers.browser_parser import classify_chrome_rows, classify_downloads
            from mcp_server.parsers.cloud_parser import build_cloud_summary
            from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques
            import sqlite3

            # Chrome history
            history_db = Path(browser_dir) / "Default/History"
            if history_db.exists():
                try:
                    import shutil, tempfile
                    tmp = tempfile.mktemp(suffix=".db")
                    shutil.copy2(str(history_db), tmp)
                    with sqlite3.connect(tmp) as conn:
                        rows = conn.execute(
                            "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500"
                        ).fetchall()
                    Path(tmp).unlink(missing_ok=True)
                    url_rows = [{"url": r[0], "title": r[1], "visit_count": r[2]} for r in rows]
                    classified = classify_chrome_rows(url_rows)
                    findings["chrome_history"] = classified
                    suspicious_urls = [u for u in classified if u.get("risk") in ("HIGH", "MEDIUM")]
                    for u in suspicious_urls:
                        u["mitre_techniques"] = map_finding_to_techniques(
                            f"browser URL {u.get('url', '')} {u.get('risk_reason', '')}"
                        )
                    findings["suspicious_urls"] = suspicious_urls
                    logger.info(f"[browser_agent] Chrome: {len(classified)} URLs, {len(suspicious_urls)} suspicious")
                except Exception as e:
                    findings["chrome_error"] = str(e)

            # Downloads
            if history_db.exists():
                try:
                    import shutil, tempfile
                    tmp = tempfile.mktemp(suffix=".db")
                    shutil.copy2(str(history_db), tmp)
                    with sqlite3.connect(tmp) as conn:
                        dl_rows = conn.execute(
                            "SELECT target_path, referrer, tab_url, total_bytes, state FROM downloads LIMIT 200"
                        ).fetchall()
                    Path(tmp).unlink(missing_ok=True)
                    downloads = [{"target": r[0], "referrer": r[1], "url": r[2], "bytes": r[3]} for r in dl_rows]
                    findings["downloads"] = classify_downloads(downloads)
                except Exception as e:
                    findings["download_error"] = str(e)

            if self.rag and findings.get("suspicious_urls"):
                from mcp_server.parsers.rag_enrichment import enrich_findings
                enrich_findings(
                    self.rag,
                    findings["suspicious_urls"][:5],
                    lambda u: f"browser C2 exfiltration URL {u.get('url', '')} {u.get('risk_reason', '')}"
                )

        except Exception as e:
            logger.error(f"[browser_agent] Error: {e}")
            findings["error"] = str(e)

        return {"browser_findings": findings}

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

        # Build timeline from disk event logs if available
        timeline = []
        for evt in disk.get("event_logs", [])[:50]:
            if evt.get("timestamp"):
                timeline.append(f"{evt['timestamp']} [Event {evt.get('event_id', '?')}] {evt.get('description', '')}")

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
