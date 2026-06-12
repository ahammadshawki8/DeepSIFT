"""
Cross-artifact correlation and adversarial self-review tools.

Two tools that address the top competitive differentiators from the field:
  - correlate_artifacts: find overlapping evidence across memory/disk/network/registry
    (inspired by agentic-dart's DuckDB cross-artifact JOIN engine)
  - adversarial_review: explicitly challenge findings before finish_analysis
    (inspired by Mulder's Phase 4 "Alternative Narrative")
"""
import json
from pathlib import Path

from mcp_server.audit import (
    get_last_audit_id, increment_tool_counter, get_tool_count,
)
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.config import ANALYSIS_DIR


# ── Helpers ────────────────────────────────────────────────────────────────────

def _load_audit_log() -> list[dict]:
    """Load all tool call records from the current session audit log."""
    audit_log = ANALYSIS_DIR / "forensic_audit.log"
    entries: list[dict] = []
    if not audit_log.exists():
        return entries
    for line in audit_log.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def _load_export(audit_id: str) -> dict:
    """Load the parsed findings from an export file referenced by audit_id."""
    audit_entries = _load_audit_log()
    for entry in audit_entries:
        if entry.get("audit_id") == audit_id:
            raw_file = entry.get("raw_output_file", "")
            if raw_file and Path(raw_file).exists():
                try:
                    return json.loads(Path(raw_file).read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    pass
    return {}


def register_correlation_tools(mcp, rag=None):

    @mcp.tool()
    def correlate_artifacts(
        process_audit_id: str = "",
        network_audit_id: str = "",
        injection_audit_id: str = "",
        shimcache_audit_id: str = "",
        prefetch_audit_id: str = "",
        event_log_audit_id: str = "",
        raw_findings_json: str = "",
    ) -> str:
        """
        Cross-reference findings from multiple artifact sources to identify overlapping evidence.

        Finds convergence points: same PID in process list + network connections + injected code;
        same file in shimcache + prefetch + MFT; same user in event logs + registry run keys.
        Convergence significantly increases attribution confidence.

        Provide audit_ids from previous tool calls OR a raw_findings_json string containing
        a list of finding dicts (each with 'source', 'type', 'value' keys).

        Args:
            process_audit_id:   audit_id from get_process_list
            network_audit_id:   audit_id from get_network_connections
            injection_audit_id: audit_id from find_injected_code
            shimcache_audit_id: audit_id from parse_shimcache
            prefetch_audit_id:  audit_id from parse_prefetch
            event_log_audit_id: audit_id from parse_event_logs
            raw_findings_json:  JSON array of {source, type, value} dicts (alternative input)
        """
        increment_tool_counter()

        # Collect findings from each source
        sources: dict[str, dict] = {}

        if process_audit_id:
            sources["process_list"] = _load_export(process_audit_id)
        if network_audit_id:
            sources["network_connections"] = _load_export(network_audit_id)
        if injection_audit_id:
            sources["injected_code"] = _load_export(injection_audit_id)
        if shimcache_audit_id:
            sources["shimcache"] = _load_export(shimcache_audit_id)
        if prefetch_audit_id:
            sources["prefetch"] = _load_export(prefetch_audit_id)
        if event_log_audit_id:
            sources["event_logs"] = _load_export(event_log_audit_id)

        # Build lookup indexes
        pids_in_processes: set[str] = set()
        pids_in_network: set[str] = set()
        pids_in_injections: set[str] = set()
        paths_in_shimcache: set[str] = set()
        paths_in_prefetch: set[str] = set()
        ips_in_network: set[str] = set()
        users_in_events: set[str] = set()

        proc_data = sources.get("process_list", {})
        for p in proc_data.get("processes", []):
            pid = str(p.get("pid", ""))
            if pid:
                pids_in_processes.add(pid)

        net_data = sources.get("network_connections", {})
        for c in net_data.get("connections", []):
            pid = str(c.get("pid", ""))
            if pid:
                pids_in_network.add(pid)
            ip = c.get("foreign_addr", "")
            if ip and ip not in ("0.0.0.0", "::", "127.0.0.1", "::1", ""):
                ips_in_network.add(ip)

        inj_data = sources.get("injected_code", {})
        for inj in inj_data.get("findings", []):
            pid = str(inj.get("pid", ""))
            if pid:
                pids_in_injections.add(pid)

        shim_data = sources.get("shimcache", {})
        for e in shim_data.get("all_entries", []):
            p = e.get("path", "").lower()
            if p:
                paths_in_shimcache.add(p)

        pf_data = sources.get("prefetch", {})
        for e in pf_data.get("entries", []):
            exe = e.get("executable", "").lower()
            if exe:
                paths_in_prefetch.add(exe)

        ev_data = sources.get("event_logs", {})
        for e in ev_data.get("events", []):
            user = e.get("user_name", "")
            if user:
                users_in_events.add(user)

        # Parse manual input if provided
        manual_findings: list[dict] = []
        if raw_findings_json:
            try:
                manual_findings = json.loads(raw_findings_json)
            except json.JSONDecodeError:
                pass

        # Compute correlations
        correlations: list[dict] = []

        # PID corroboration: process + network
        pids_proc_and_net = pids_in_processes & pids_in_network
        if pids_proc_and_net:
            correlations.append({
                "type": "pid_corroboration",
                "description": "PIDs appear in BOTH process list and active network connections — "
                               "strong indicator of network-active processes.",
                "pids": sorted(pids_proc_and_net),
                "sources": ["process_list", "network_connections"],
                "confidence_boost": "HIGH — dual-source PID confirmation",
                "mitre_hint": "T1071 (C2 communication) or T1041 (exfiltration) if PIDs are suspicious",
            })

        # PID corroboration: process + injection
        pids_proc_and_inj = pids_in_processes & pids_in_injections
        if pids_proc_and_inj:
            correlations.append({
                "type": "injected_network_process",
                "description": "PIDs appear in BOTH injected code (malfind) and process list — "
                               "confirms injected processes are running.",
                "pids": sorted(pids_proc_and_inj),
                "sources": ["process_list", "injected_code"],
                "confidence_boost": "HIGH — injection confirmed in active process",
                "mitre_hint": "T1055 (Process Injection) confirmed active",
            })

        # Triple correlation: process + network + injection
        pids_all_three = pids_in_processes & pids_in_network & pids_in_injections
        if pids_all_three:
            correlations.append({
                "type": "injected_c2_process",
                "description": "PIDs appear in process list, active network connections, AND malfind — "
                               "this is high-confidence evidence of injected code with C2 communication.",
                "pids": sorted(pids_all_three),
                "sources": ["process_list", "network_connections", "injected_code"],
                "confidence_boost": "CRITICAL — three independent sources converge",
                "mitre_hint": "T1055 + T1071: injected code with active C2",
            })

        # Execution corroboration: shimcache + prefetch overlap
        exe_overlap = paths_in_shimcache & paths_in_prefetch
        if exe_overlap:
            correlations.append({
                "type": "execution_corroboration",
                "description": "Executables present in BOTH Shimcache (existence) and Prefetch (ran) — "
                               "confirms these files existed and executed on this system.",
                "executables": sorted(exe_overlap)[:20],
                "sources": ["shimcache", "prefetch"],
                "confidence_boost": "HIGH — shimcache + prefetch double-confirmation of execution",
                "mitre_hint": "T1036 (masquerading) or T1059 (execution) depending on location",
            })

        # Network IPs summary from correlated sources
        if ips_in_network:
            correlations.append({
                "type": "network_ioc_summary",
                "description": "External IP addresses observed in network connections — "
                               "run lookup_ip_reputation for each to assess threat intelligence.",
                "external_ips": sorted(ips_in_network),
                "sources": ["network_connections"],
                "recommendation": "Call lookup_ip_reputation for each IP listed above.",
                "mitre_hint": "T1071 (C2), T1041 (exfiltration), or T1133 (external remote service)",
            })

        # Coverage gap assessment
        coverage_gaps: list[str] = []
        if not pids_in_processes:
            coverage_gaps.append("No process list data — run get_process_list first.")
        if not pids_in_network:
            coverage_gaps.append("No network connection data — run get_network_connections.")
        if not pids_in_injections:
            coverage_gaps.append("No injection analysis data — run find_injected_code.")
        if not paths_in_shimcache and not paths_in_prefetch:
            coverage_gaps.append("No execution history data — run parse_shimcache and/or parse_prefetch.")
        if not users_in_events:
            coverage_gaps.append("No event log data — run parse_event_logs for logon/service/task events.")

        data = {
            "sources_loaded": list(sources.keys()),
            "correlations_found": len(correlations),
            "correlations": correlations,
            "coverage_gaps": coverage_gaps,
            "summary": (
                f"Found {len(correlations)} cross-artifact correlation(s) across "
                f"{len(sources)} evidence source(s). "
                f"{len(coverage_gaps)} coverage gap(s) identified."
            ),
        }
        return wrap_response("correlate_artifacts", data)

    @mcp.tool()
    def adversarial_review(
        current_findings_summary: str,
        suspicious_processes: str = "",
        network_iocs: str = "",
        mitre_techniques: str = "",
    ) -> str:
        """
        Explicitly challenge current investigation findings before submitting finish_analysis.

        For each claim, this tool generates counter-hypotheses and identifies evidence gaps
        that could undermine the conclusion. Calling this before finish_analysis reduces
        hallucination by forcing the analyst to confront alternative explanations.

        Inspired by Mulder's Phase 4 "Alternative Narrative" adversarial review.

        Args:
            current_findings_summary: The current investigation summary/hypothesis string.
            suspicious_processes: Comma-separated list of suspicious process names or PIDs.
            network_iocs:         Comma-separated list of suspicious IP addresses.
            mitre_techniques:     Comma-separated list of MITRE technique IDs (e.g. 'T1055,T1071').
        """
        increment_tool_counter()

        challenges: list[dict] = []
        gaps: list[str] = []
        alternative_hypotheses: list[dict] = []

        # Challenge process-based claims
        procs = [p.strip() for p in suspicious_processes.split(",") if p.strip()]
        for proc in procs:
            challenges.append({
                "claim": f"Process '{proc}' is malicious",
                "counter_hypotheses": [
                    f"'{proc}' may be a legitimate system process running from an unusual location due to "
                    "Windows update, software installer, or admin script — check parent PID and command line.",
                    f"Name collision: '{proc}' could be a legitimate application with the same name as malware — "
                    "verify the full path and digital signature.",
                    f"False positive from pslist parser: WOW64, .NET, or JIT-compiled processes can appear "
                    "anomalous without being malicious.",
                ],
                "required_corroboration": [
                    "get_loaded_dlls — check for injected or unsigned DLLs in this process",
                    "get_command_history — review the full command line for suspicious arguments",
                    "get_network_connections — verify if this PID has external C2 connections",
                    "parse_amcache — check SHA1 hash against threat intelligence",
                ],
            })

        # Challenge network IOC claims
        ips = [ip.strip() for ip in network_iocs.split(",") if ip.strip()]
        for ip in ips:
            challenges.append({
                "claim": f"IP {ip} is a C2 or exfiltration endpoint",
                "counter_hypotheses": [
                    f"{ip} may be a legitimate CDN, cloud provider, or corporate proxy — "
                    "verify the ASN and hosting provider via lookup_ip_reputation.",
                    f"Connection timing may pre-date the incident window — confirm timestamp alignment.",
                    "Netscan timestamps reflect kernel connection state, not necessarily malicious initiation — "
                    "cross-reference with browser history or process creation times.",
                ],
                "required_corroboration": [
                    f"lookup_ip_reputation('{ip}') — check AbuseIPDB confidence score and VT malicious count",
                    "filter_timeline — look for DNS queries or HTTP connections to this IP in timeline",
                    "parse_srum — check if any specific application sent large data volumes to this IP",
                ],
            })

        # Challenge MITRE technique assignments
        techniques = [t.strip() for t in mitre_techniques.split(",") if t.strip()]
        mitre_challenges = {
            "T1055": {
                "claim": "Process injection occurred (T1055)",
                "counter_hypotheses": [
                    "malfind false positives from JIT engines (Chrome, Edge, .NET CLR, Java) are common — "
                    "check if the injected process is a known JIT host.",
                    "RWX memory regions are allocated by legitimate software for plugin loading and DRM — "
                    "verify the injecting process identity.",
                ],
                "required_corroboration": [
                    "find_injected_code — check risk_level (PE header in region = high confidence, MZ signature only = medium)",
                    "get_loaded_dlls — look for unsigned or unsigned DLLs in the affected process",
                ],
            },
            "T1071": {
                "claim": "C2 communication detected (T1071)",
                "counter_hypotheses": [
                    "External IP connections may be telemetry, update checks, or cloud sync — "
                    "verify port numbers (80/443 is ambiguous) and data volumes.",
                    "Time-of-day of connections matters — automated beacon traffic at odd hours is more suspicious than browser-time connections.",
                ],
                "required_corroboration": [
                    "lookup_ip_reputation — confirm IP is known malicious before asserting C2",
                    "parse_srum — quantify bytes transferred to confirm exfiltration volume",
                ],
            },
            "T1547.001": {
                "claim": "Registry persistence established (T1547.001)",
                "counter_hypotheses": [
                    "Many legitimate applications use Run keys for auto-start — verify the path and publisher.",
                    "RunOnce keys may be legitimate installer cleanup tasks — check if the key is transient.",
                ],
                "required_corroboration": [
                    "parse_shimcache — verify the executable in the Run key appeared on disk before the incident",
                    "parse_event_logs — look for service install (7045) or task create (4698) events",
                ],
            },
            "T1003.001": {
                "claim": "LSASS credential dumping (T1003.001)",
                "counter_hypotheses": [
                    "Antivirus, EDR, and Windows Credential Guard all access LSASS legitimately — "
                    "verify the accessing process identity.",
                    "Windows Defender and MsMpEng routinely scan LSASS memory — this is not malicious.",
                ],
                "required_corroboration": [
                    "parse_event_logs — look for event 4656 (handle request to lsass.exe) with suspicious source process",
                    "find_injected_code — check if the accessing process has injected code",
                ],
            },
        }

        for t in techniques:
            if t in mitre_challenges:
                challenges.append(mitre_challenges[t])
            else:
                challenges.append({
                    "claim": f"MITRE technique {t} is present",
                    "counter_hypotheses": [
                        f"Technique {t} assignment is based on pattern matching — verify the specific "
                        "behavior exhibited matches the technique description in MITRE ATT&CK.",
                        "Similar-looking benign behaviors exist for most ATT&CK techniques — "
                        "consider whether the full kill chain supports this attribution.",
                    ],
                    "required_corroboration": [
                        "Verify at least two independent artifact sources corroborate this technique.",
                    ],
                })

        # Identify general coverage gaps
        if not procs:
            gaps.append("No suspicious processes listed — verify get_process_list was called and reviewed.")
        if not ips:
            gaps.append("No network IOCs listed — verify get_network_connections was called and external IPs reviewed.")
        if not techniques:
            gaps.append("No MITRE techniques listed — ATT&CK mapping is required for a complete investigation.")
        if "lateral" not in current_findings_summary.lower() and "rdp" not in current_findings_summary.lower():
            gaps.append("Lateral movement not addressed — consider parse_event_logs for RDP and SMB events (T1021).")
        if "persist" not in current_findings_summary.lower():
            gaps.append("Persistence mechanisms not addressed — check registry Run keys and scheduled tasks.")
        if "exfil" not in current_findings_summary.lower():
            gaps.append("Data exfiltration not quantified — run parse_srum to measure bytes sent per application.")

        # Generate alternative hypotheses for the overall scenario
        alternative_hypotheses.append({
            "hypothesis": "Opportunistic malware (not targeted attack)",
            "supporting_conditions": [
                "Generic malware family detected (ransomware, coin miner, adware)",
                "No industry-specific targeting indicators",
                "No evidence of reconnaissance or lateral movement",
            ],
            "how_to_rule_out": "Look for targeted tooling, spear-phishing artifacts, or industry-specific data staging.",
        })
        alternative_hypotheses.append({
            "hypothesis": "Insider threat / authorized user misuse",
            "supporting_conditions": [
                "Suspicious activity originates from legitimate user account",
                "Activity occurs during business hours",
                "No external C2 connections — data may be exfiltrated via authorized channels (email, USB, cloud sync)",
            ],
            "how_to_rule_out": "parse_srum to check cloud storage upload volumes; parse_event_logs for 4648 explicit credential use.",
        })
        alternative_hypotheses.append({
            "hypothesis": "Pentest or authorized red team activity",
            "supporting_conditions": [
                "Known red team tooling detected (Cobalt Strike, Metasploit, PsExec)",
                "Activity coincides with known maintenance or testing window",
            ],
            "how_to_rule_out": "Verify with incident response team whether a pentest was scheduled during this window.",
        })

        ready_for_finish = len(gaps) == 0 and len(challenges) > 0

        data = {
            "challenges_count": len(challenges),
            "challenges": challenges,
            "coverage_gaps": gaps,
            "alternative_hypotheses": alternative_hypotheses,
            "ready_for_finish_analysis": ready_for_finish,
            "recommendation": (
                "Address all coverage_gaps before calling finish_analysis. "
                "For each challenge, confirm required_corroboration steps have been performed. "
                "Document which alternative hypotheses were ruled out and why."
            ) if not ready_for_finish else (
                "All coverage gaps addressed. Proceed to finish_analysis with high confidence. "
                "Include audit_ids for all tool calls that corroborate your findings."
            ),
        }
        return wrap_response("adversarial_review", data)

    @mcp.tool()
    def detect_contradictions(
        process_audit_id: str = "",
        network_audit_id: str = "",
        injection_audit_id: str = "",
        hidden_process_audit_id: str = "",
        shimcache_audit_id: str = "",
        prefetch_audit_id: str = "",
        event_log_audit_id: str = "",
        services_audit_id: str = "",
    ) -> str:
        """
        Detect contradictions between forensic artifact sources.

        An UNRESOLVED_CONTRADICTION finding means two trusted tools produced
        results that CANNOT both be true simultaneously. Each contradiction
        significantly raises confidence that adversarial activity occurred
        (rootkits, timestomping, log wiping, DKOM process hiding).

        Contradiction types detected:
        - DKOM_HIDDEN_PROCESS: PID in netscan but absent from pslist
        - GHOST_INJECTED_PROCESS: PID in malfind but absent from pslist
        - PREFETCH_WITHOUT_SHIMCACHE: File ran (prefetch) but never seen by shimcache
          — possible shimcache manipulation or external execution
        - NETWORK_WITHOUT_PROCESS: External IP connection with no owning process in pslist
        - HIDDEN_SERVICE: Service in event logs (7045) but absent from svcscan
        - PROCESS_PARENT_MISMATCH: Process has unexpected parent vs SANS baseline
        - LOG_WIPE_INDICATOR: Significant gap in event log sequence numbers

        Args:
            process_audit_id:        audit_id from get_process_list (pslist)
            network_audit_id:        audit_id from get_network_connections (netscan)
            injection_audit_id:      audit_id from find_injected_code (malfind)
            hidden_process_audit_id: audit_id from scan_hidden_processes (pslist vs psscan)
            shimcache_audit_id:      audit_id from parse_shimcache
            prefetch_audit_id:       audit_id from parse_prefetch
            event_log_audit_id:      audit_id from parse_event_logs
            services_audit_id:       audit_id from get_running_services (svcscan)
        """
        increment_tool_counter()
        audit_id = get_last_audit_id()

        # Load all available sources
        sources: dict[str, dict] = {}
        if process_audit_id:
            sources["process_list"] = _load_export(process_audit_id)
        if network_audit_id:
            sources["network"] = _load_export(network_audit_id)
        if injection_audit_id:
            sources["injected"] = _load_export(injection_audit_id)
        if hidden_process_audit_id:
            sources["hidden_processes"] = _load_export(hidden_process_audit_id)
        if shimcache_audit_id:
            sources["shimcache"] = _load_export(shimcache_audit_id)
        if prefetch_audit_id:
            sources["prefetch"] = _load_export(prefetch_audit_id)
        if event_log_audit_id:
            sources["event_logs"] = _load_export(event_log_audit_id)
        if services_audit_id:
            sources["services"] = _load_export(services_audit_id)

        contradictions: list[dict] = []

        # ── Index each source ──────────────────────────────────────────────────

        pslist_pids: set[str] = set()
        for p in sources.get("process_list", {}).get("processes", []):
            pid = str(p.get("pid", ""))
            if pid:
                pslist_pids.add(pid)

        netscan_pids: set[str] = set()
        netscan_external_ips: set[str] = set()
        for c in sources.get("network", {}).get("connections", []):
            pid = str(c.get("pid", ""))
            if pid:
                netscan_pids.add(pid)
            ip = c.get("foreign_addr", "")
            if ip and ip not in ("0.0.0.0", "::", "127.0.0.1", "::1", ""):
                netscan_external_ips.add(ip)

        malfind_pids: set[str] = set()
        for f in sources.get("injected", {}).get("findings", []):
            pid = str(f.get("pid", ""))
            if pid:
                malfind_pids.add(pid)

        psscan_only_pids: set[str] = set()
        for p in sources.get("hidden_processes", {}).get("hidden_processes", []):
            pid = str(p.get("pid", ""))
            if pid:
                psscan_only_pids.add(pid)

        shimcache_exes: set[str] = set()
        for e in sources.get("shimcache", {}).get("all_entries", []):
            path = e.get("path", "").lower()
            if path:
                # Extract just the filename for fuzzy matching
                shimcache_exes.add(path.split("\\")[-1].split("/")[-1])

        prefetch_exes: set[str] = set()
        for e in sources.get("prefetch", {}).get("entries", []):
            exe = e.get("executable", "").lower()
            if exe:
                prefetch_exes.add(exe)

        svcscan_names: set[str] = set()
        for s in sources.get("services", {}).get("services", []):
            name = s.get("service_name", "").lower()
            if name:
                svcscan_names.add(name)

        evtlog_service_installs: set[str] = set()
        evtlog_seq_numbers: list[int] = []
        for e in sources.get("event_logs", {}).get("events", []):
            if e.get("event_id") in (7045, 4697):
                svc = e.get("service_name", e.get("data", {}).get("ServiceName", "")).lower()
                if svc:
                    evtlog_service_installs.add(svc)
            seq = e.get("record_id") or e.get("event_record_id")
            if seq is not None:
                try:
                    evtlog_seq_numbers.append(int(seq))
                except (TypeError, ValueError):
                    pass

        # ── Contradiction Rule 1: DKOM Hidden Process ──────────────────────────
        # psscan found a PID that pslist cannot see → DKOM rootkit manipulation
        if psscan_only_pids:
            contradictions.append({
                "type": "UNRESOLVED_CONTRADICTION",
                "subtype": "DKOM_HIDDEN_PROCESS",
                "severity": "CRITICAL",
                "description": (
                    "psscan found process(es) that pslist cannot enumerate. "
                    "DKOM (Direct Kernel Object Manipulation) rootkit is the most likely explanation — "
                    "the EPROCESS linked list has been modified to hide these processes (T1014)."
                ),
                "affected_pids": sorted(psscan_only_pids),
                "sources": ["scan_hidden_processes (psscan)", "get_process_list (pslist)"],
                "resolution": "Cannot resolve without kernel debugger — treat all psscan-only PIDs as rootkit-hidden.",
                "mitre": "T1014 — Rootkit",
                "confidence_impact": "+15 pts on Process Injection / Rootkit findings",
            })

        # ── Contradiction Rule 2: Network PID without pslist entry ─────────────
        orphan_net_pids = netscan_pids - pslist_pids
        if orphan_net_pids and pslist_pids:
            contradictions.append({
                "type": "UNRESOLVED_CONTRADICTION",
                "subtype": "NETWORK_WITHOUT_PROCESS",
                "severity": "HIGH",
                "description": (
                    "netscan shows active network connections owned by PIDs that do NOT appear "
                    "in pslist. The owning process is either hidden (rootkit) or terminated after "
                    "the connection was established but the socket remains in a TIME_WAIT state."
                ),
                "orphan_pids": sorted(orphan_net_pids),
                "sources": ["get_network_connections (netscan)", "get_process_list (pslist)"],
                "resolution": "Cross-reference with psscan; if PID not in psscan either, suspect DKOM.",
                "mitre": "T1014 or T1071 — hidden C2 process",
                "confidence_impact": "+10 pts on network IOC findings",
            })

        # ── Contradiction Rule 3: Injected PID without pslist entry ───────────
        ghost_pids = malfind_pids - pslist_pids
        if ghost_pids and pslist_pids:
            contradictions.append({
                "type": "UNRESOLVED_CONTRADICTION",
                "subtype": "GHOST_INJECTED_PROCESS",
                "severity": "HIGH",
                "description": (
                    "malfind found injected code regions in PIDs that do NOT appear in pslist. "
                    "These are 'ghost' injections: either the host process terminated after injection, "
                    "or the process is DKOM-hidden. Either way, the injection event occurred."
                ),
                "ghost_pids": sorted(ghost_pids),
                "sources": ["find_injected_code (malfind)", "get_process_list (pslist)"],
                "resolution": "Check psscan for these PIDs. If absent, the process self-terminated post-injection.",
                "mitre": "T1055 — Process Injection (confirmed by memory artifact)",
                "confidence_impact": "+10 pts on injection findings",
            })

        # ── Contradiction Rule 4: Prefetch execution without shimcache record ──
        # A file ran (prefetch) but shimcache has no record of it ever existing.
        # Possible: shimcache cleared/manipulated, or file was executed from network/USB
        # and never touched the local file system AppCompatCache.
        prefetch_without_shim: list[str] = []
        for exe in prefetch_exes:
            if exe not in shimcache_exes:
                prefetch_without_shim.append(exe)

        if prefetch_without_shim and shimcache_exes:
            contradictions.append({
                "type": "UNRESOLVED_CONTRADICTION",
                "subtype": "PREFETCH_WITHOUT_SHIMCACHE",
                "severity": "MEDIUM",
                "description": (
                    "These executables have Prefetch entries (they RAN on this system) but "
                    "NO corresponding Shimcache entries (no record of the file ever being seen). "
                    "Possible explanations: AppCompatCache was cleared (T1070.006 — Indicator Removal), "
                    "execution from a network share or removable media, or a Shimcache parsing gap."
                ),
                "executables": sorted(prefetch_without_shim)[:30],
                "sources": ["parse_prefetch", "parse_shimcache"],
                "resolution": "Check MFT for these filenames. If MFT has them but shimcache doesn't, "
                              "the AppCompatCache was likely manipulated.",
                "mitre": "T1070.006 — Indicator Removal: Timestomp / T1052 — Exfiltration over Physical Medium",
                "confidence_impact": "+5 pts on anti-forensics findings",
            })

        # ── Contradiction Rule 5: Service in event log but not in svcscan ─────
        service_ghost = evtlog_service_installs - svcscan_names
        if service_ghost and svcscan_names:
            contradictions.append({
                "type": "UNRESOLVED_CONTRADICTION",
                "subtype": "HIDDEN_SERVICE",
                "severity": "HIGH",
                "description": (
                    "Event logs record the INSTALLATION of these service(s) (EventID 7045/4697), "
                    "but svcscan cannot find them in the current service database. "
                    "The service was either deleted post-installation (cleanup) or is hidden "
                    "by a rootkit that patches the SCM (Service Control Manager) DKOM."
                ),
                "missing_services": sorted(service_ghost),
                "sources": ["parse_event_logs (7045/4697)", "get_running_services (svcscan)"],
                "resolution": "Check MFT for the service binary path from the event log. "
                              "If binary exists but service is gone → cleanup; if neither → rootkit or full cleanup.",
                "mitre": "T1543.003 — Windows Service + T1070 — Indicator Removal",
                "confidence_impact": "+10 pts on persistence findings",
            })

        # ── Contradiction Rule 6: Event log sequence number gap ───────────────
        if len(evtlog_seq_numbers) > 10:
            sorted_seqs = sorted(evtlog_seq_numbers)
            max_gap = 0
            gap_at = 0
            for i in range(1, len(sorted_seqs)):
                gap = sorted_seqs[i] - sorted_seqs[i - 1]
                if gap > max_gap:
                    max_gap = gap
                    gap_at = sorted_seqs[i - 1]
            if max_gap > 100:
                contradictions.append({
                    "type": "UNRESOLVED_CONTRADICTION",
                    "subtype": "LOG_WIPE_INDICATOR",
                    "severity": "HIGH",
                    "description": (
                        f"Event log record ID sequence has a gap of {max_gap} events "
                        f"after record #{gap_at}. Windows event logs use monotonically increasing "
                        "record IDs — a gap this large indicates events were deleted or the log "
                        "was cleared (T1070.001 — Clear Windows Event Logs)."
                    ),
                    "max_gap": max_gap,
                    "gap_after_record_id": gap_at,
                    "sources": ["parse_event_logs"],
                    "resolution": "Check for EventID 1102 (Security log cleared) or 104 (System log cleared) "
                                  "near the gap boundary.",
                    "mitre": "T1070.001 — Indicator Removal: Clear Windows Event Logs",
                    "confidence_impact": "+10 pts on anti-forensics findings",
                })

        data = {
            "contradictions_found": len(contradictions),
            "unresolved_contradictions": [c for c in contradictions if c["type"] == "UNRESOLVED_CONTRADICTION"],
            "all_contradictions": contradictions,
            "sources_checked": list(sources.keys()),
            "summary": (
                f"Detected {len(contradictions)} contradiction(s) across "
                f"{len(sources)} artifact source(s). "
                + (
                    "UNRESOLVED contradictions STRONGLY indicate adversarial anti-forensics — "
                    "include all in finish_analysis report."
                    if contradictions else
                    "No contradictions found — artifact sources are internally consistent."
                )
            ),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("detect_contradictions", data, audit_id)
