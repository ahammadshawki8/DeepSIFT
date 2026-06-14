"""
Volatility 3 MCP tool wrappers.
One function = one typed MCP tool. No generic run_volatility() shell escape.

Every response includes:
  audit_id        — chain-of-custody reference to forensic_audit.log
  caveats         — known false-positive sources for this tool
  advisories      — what NOT to conclude without corroboration
  corroboration   — recommended follow-up tool calls
"""
import json
import subprocess
from pathlib import Path

from mcp_server.config import VOLATILITY_CMD, MAX_TOOL_TIMEOUT, MAX_ITERATIONS
from mcp_server.audit import (
    log_tool_execution, get_last_audit_id,
    increment_tool_counter, get_tool_count, reset_tool_counter, guard_command,
)
from mcp_server.parsers.pslist_parser import parse_pslist, analyze_processes
from mcp_server.parsers.netscan_parser import parse_netscan, get_external_ips
from mcp_server.parsers.malfind_parser import parse_malfind
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.parsers.mitre_auto_map import (
    map_process_anomalies, map_injection, map_network_connection, map_cmdline,
)
from mcp_server.parsers.grounding_verifier import GroundingVerifier
from mcp_server.parsers.confidence_scorer import calculate_confidence_score


def _run(cmd: list[str], tool_name: str) -> tuple[str, str]:
    """Run a subprocess, audit-log result, return (stdout, stderr)."""
    try:
        guard_command(cmd)
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT,
        )
        log_tool_execution(tool_name, cmd, result.stdout, error=result.stderr)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        msg = f"Tool '{tool_name}' timed out after {MAX_TOOL_TIMEOUT}s"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg
    except FileNotFoundError:
        msg = f"Tool not found: {cmd[0]}. Is Volatility 3 installed on this SIFT system?"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg


def _check_iteration_limit() -> dict | None:
    """Return a warning dict if we're at or past MAX_ITERATIONS, else None."""
    count = get_tool_count()
    if count >= MAX_ITERATIONS:
        return {
            "warning": f"MAX_ITERATIONS ({MAX_ITERATIONS}) reached — call finish_analysis immediately.",
            "tool_calls_used": count,
        }
    return None


def _enrich_with_rag(findings: list, query: str, rag) -> list[dict]:
    """Optionally append RAG threat intel context to each suspicious finding."""
    if rag is None:
        return findings
    try:
        context = rag.query(query)
        return [{"findings": findings, "threat_intel_context": context}]
    except Exception:
        return findings


def register_volatility_tools(mcp, rag=None):
    """Register all Volatility 3 tools with the FastMCP instance."""

    @mcp.tool()
    def get_process_list(image_path: str, max_rows: int = 500) -> str:
        """
        Lists all running processes extracted from a memory image.

        ALWAYS call this first in any memory investigation. Returns structured JSON
        with pid, ppid, name, threads, create_time, suspicious flag, anomaly details,
        MITRE technique IDs, and an audit_id for chain-of-custody.

        The suspicious flag is set by Python comparing against the SANS Hunt Evil
        known-normal Windows process baseline — not by LLM inference.

        Args:
            image_path: Absolute path to the memory image file (.raw, .vmem, .mem).
            max_rows:   Maximum number of processes to return (default 500).
        """
        limit = _check_iteration_limit()
        if limit:
            return json.dumps(limit)

        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.pslist"]
        stdout, stderr = _run(cmd, "get_process_list")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        processes = analyze_processes(parse_pslist(stdout))
        suspicious = [p for p in processes if p["suspicious"]]

        for proc in suspicious:
            proc["mitre_techniques"] = map_process_anomalies(proc.get("anomalies", []))
            if rag:
                query = f"suspicious process {proc['name']} anomalies: {proc['anomalies']}"
                proc["threat_intel"] = rag.query(query, n_results=2)

        data = {
            "total_processes": len(processes),
            "suspicious_count": len(suspicious),
            "tool_calls_used": get_tool_count(),
            "tool_calls_remaining": max(0, MAX_ITERATIONS - get_tool_count()),
            "processes": processes[:max_rows],
            "investigation_note": (
                "Focus on processes marked suspicious=true. "
                "Run scan_hidden_processes to detect DKOM-hidden processes. "
                "Run get_loaded_dlls on suspicious PIDs."
            ),
        }
        return wrap_response("get_process_list", data, audit_id)

    @mcp.tool()
    def find_injected_code(image_path: str) -> str:
        """
        Finds processes with injected malicious code using memory region analysis.

        Python classifies each finding as shellcode, reflective_dll_injection,
        process_hollowing_candidate, or suspicious_exec_region based on memory
        protection flags and PE header presence.

        Args:
            image_path: Absolute path to the memory image file.
        """
        limit = _check_iteration_limit()
        if limit:
            return json.dumps(limit)

        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.malfind"]
        stdout, stderr = _run(cmd, "find_injected_code")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        findings = parse_malfind(stdout)
        high_risk = [f for f in findings if f.get("risk_level") == "high"]

        for f in findings:
            f["mitre_techniques"] = map_injection(
                f.get("injection_type", ""), f.get("protection", "")
            )
            if rag and f.get("risk_level") == "high":
                query = f"memory injection {f['injection_type']} in process {f['process']}"
                f["threat_intel"] = rag.query(query, n_results=2)

        data = {
            "total_findings": len(findings),
            "high_risk_count": len(high_risk),
            "tool_calls_used": get_tool_count(),
            "findings": findings,
        }
        return wrap_response("find_injected_code", data, audit_id)

    @mcp.tool()
    def get_network_connections(image_path: str, max_rows: int = 500) -> str:
        """
        Lists all active and recently closed network connections from memory.

        External IPs are flagged automatically. Returns protocol, local/foreign
        addresses, state, owning PID and process name, and MITRE technique IDs.

        Args:
            image_path: Absolute path to the memory image file.
            max_rows:   Maximum connections to return (default 500).
        """
        limit = _check_iteration_limit()
        if limit:
            return json.dumps(limit)

        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.netscan"]
        stdout, stderr = _run(cmd, "get_network_connections")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        connections = parse_netscan(stdout)
        suspicious = [c for c in connections if c.get("suspicious")]
        external_ips = get_external_ips(connections)

        for c in suspicious:
            c["mitre_techniques"] = map_network_connection(c.get("ioc_flags", []))

        data = {
            "total_connections": len(connections),
            "suspicious_count": len(suspicious),
            "external_ips": external_ips,
            "tool_calls_used": get_tool_count(),
            "connections": connections[:max_rows],
            "investigation_note": (
                f"Found {len(external_ips)} external IP(s). "
                "Run lookup_ip_reputation on each external IP. "
                "Cross-reference PIDs with suspicious processes."
            ),
        }
        return wrap_response("get_network_connections", data, audit_id)

    @mcp.tool()
    def get_loaded_dlls(image_path: str, pid: int) -> str:
        """
        Lists all DLLs loaded by a specific process.

        Unsigned DLLs in unusual paths (AppData, Temp, %USERPROFILE%) are flagged.

        Args:
            image_path: Absolute path to the memory image file.
            pid: Process ID from get_process_list output.
        """
        limit = _check_iteration_limit()
        if limit:
            return json.dumps(limit)

        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.dlllist", "--pid", str(pid)]
        stdout, stderr = _run(cmd, "get_loaded_dlls")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        dlls = _parse_dlllist(stdout, pid)
        suspicious_dlls = [d for d in dlls if d.get("suspicious")]

        data = {
            "pid": pid,
            "total_dlls": len(dlls),
            "suspicious_count": len(suspicious_dlls),
            "tool_calls_used": get_tool_count(),
            "dlls": dlls,
        }
        return wrap_response("get_loaded_dlls", data, audit_id)

    @mcp.tool()
    def get_command_history(image_path: str) -> str:
        """
        Extracts command line arguments for all processes from memory.

        Suspicious patterns (base64, -EncodedCommand, certutil, credential tools)
        are flagged automatically with MITRE technique IDs.

        Args:
            image_path: Absolute path to the memory image file.
        """
        limit = _check_iteration_limit()
        if limit:
            return json.dumps(limit)

        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.cmdline"]
        stdout, stderr = _run(cmd, "get_command_history")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        cmdlines = _parse_cmdline(stdout)
        suspicious = [c for c in cmdlines if c.get("suspicious")]

        for c in suspicious:
            c["mitre_techniques"] = map_cmdline(c.get("cmdline", ""))
            if rag:
                query = f"suspicious command line: {c['cmdline'][:200]}"
                c["threat_intel"] = rag.query(query, n_results=2)

        data = {
            "total_processes": len(cmdlines),
            "suspicious_count": len(suspicious),
            "tool_calls_used": get_tool_count(),
            "cmdlines": cmdlines,
        }
        return wrap_response("get_command_history", data, audit_id)

    @mcp.tool()
    def get_registry_hives(image_path: str) -> str:
        """
        Lists registry hives loaded in memory.

        Args:
            image_path: Absolute path to the memory image file.
        """
        limit = _check_iteration_limit()
        if limit:
            return json.dumps(limit)

        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.registry.hivelist"]
        stdout, stderr = _run(cmd, "get_registry_hives")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        hives = _parse_hivelist(stdout)
        data = {"hives": hives, "total": len(hives), "tool_calls_used": get_tool_count()}
        return wrap_response("get_registry_hives", data, audit_id)

    @mcp.tool()
    def get_registry_key(image_path: str, hive_offset: str, key: str) -> str:
        """
        Reads a specific registry key and its values from memory.

        Args:
            image_path:   Absolute path to the memory image file.
            hive_offset:  Hex offset from get_registry_hives (e.g. '0xffff...')
            key:          Registry key path relative to hive root.
        """
        limit = _check_iteration_limit()
        if limit:
            return json.dumps(limit)

        cmd = VOLATILITY_CMD + [
            "-f", image_path,
            "windows.registry.printkey",
            "--offset", hive_offset,
            "--key", key,
        ]
        stdout, stderr = _run(cmd, "get_registry_key")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        values = _parse_printkey(stdout)
        data = {
            "hive_offset": hive_offset,
            "key": key,
            "values": values,
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_registry_key", data, audit_id)

    @mcp.tool()
    def get_handles(image_path: str, pid: int) -> str:
        """
        Lists open handles (files, registry keys, mutexes) for a process.

        Args:
            image_path: Absolute path to the memory image file.
            pid:        Process ID from get_process_list output.
        """
        limit = _check_iteration_limit()
        if limit:
            return json.dumps(limit)

        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.handles", "--pid", str(pid)]
        stdout, stderr = _run(cmd, "get_handles")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        handles = _parse_handles(stdout)
        data = {
            "pid": pid,
            "total_handles": len(handles),
            "tool_calls_used": get_tool_count(),
            "handles": handles,
        }
        return json.dumps(data, default=str)

    @mcp.tool()
    def scan_hidden_processes(image_path: str) -> str:
        """
        Detects DKOM-hidden processes by diffing pslist (linked-list) vs psscan (pool scan).

        Processes in psscan but absent from pslist are rootkit-hidden (T1014).
        Python computes the diff automatically — no manual comparison needed.

        Args:
            image_path: Absolute path to the memory image file.
        """
        limit = _check_iteration_limit()
        if limit:
            return json.dumps(limit)

        pslist_out, _ = _run(
            VOLATILITY_CMD + ["-f", image_path, "windows.pslist"], "scan_hidden_pslist"
        )
        psscan_out, _ = _run(
            VOLATILITY_CMD + ["-f", image_path, "windows.psscan"], "scan_hidden_psscan"
        )
        audit_id = get_last_audit_id()
        increment_tool_counter()

        pslist_procs = parse_pslist(pslist_out)
        psscan_procs = parse_pslist(psscan_out)

        pslist_pids = {p["pid"] for p in pslist_procs}
        psscan_pids = {p["pid"] for p in psscan_procs}

        hidden_pids = psscan_pids - pslist_pids
        ghost_pids  = pslist_pids - psscan_pids

        hidden = [p for p in psscan_procs if p["pid"] in hidden_pids]
        ghost  = [p for p in pslist_procs  if p["pid"] in ghost_pids]

        mitre = []
        if hidden:
            mitre = [{"technique_id": "T1014", "technique_name": "Rootkit",
                      "url": "https://attack.mitre.org/techniques/T1014"}]
            if rag:
                context = rag.query("DKOM hidden process rootkit technique T1014")
                for h in hidden:
                    h["threat_intel"] = context

        data = {
            "pslist_process_count": len(pslist_procs),
            "psscan_process_count": len(psscan_procs),
            "hidden_process_count": len(hidden),
            "ghost_process_count": len(ghost),
            "hidden_processes": hidden,
            "ghost_processes": ghost,
            "mitre_techniques": mitre,
            "tool_calls_used": get_tool_count(),
            "verdict": (
                "ROOTKIT ACTIVITY DETECTED — processes hidden from pslist walk"
                if hidden else
                "No DKOM-hidden processes detected. Discrepancies are likely recently exited processes."
            ),
        }
        return wrap_response("scan_hidden_processes", data, audit_id)

    @mcp.tool()
    def get_running_services(image_path: str) -> str:
        """
        Lists all Windows services from memory using Volatility svcscan.

        Services with binary paths in user-writable directories (AppData, Temp,
        ProgramData) are flagged as suspicious and mapped to T1543.003.

        Args:
            image_path: Absolute path to the memory image file.
        """
        limit = _check_iteration_limit()
        if limit:
            return json.dumps(limit)

        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.svcscan"]
        stdout, stderr = _run(cmd, "get_running_services")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        services = _parse_svcscan(stdout)
        suspicious = [s for s in services if s.get("suspicious")]

        for s in suspicious:
            s["mitre_techniques"] = [
                {"technique_id": "T1543.003",
                 "technique_name": "Create or Modify System Process: Windows Service",
                 "url": "https://attack.mitre.org/techniques/T1543/003"}
            ]
            if rag:
                query = f"malicious service binary path {s.get('binary_path', '')}"
                s["threat_intel"] = rag.query(query, n_results=2)

        data = {
            "total_services": len(services),
            "suspicious_count": len(suspicious),
            "running_count": sum(1 for s in services if s.get("state") == "SERVICE_RUNNING"),
            "suspicious_services": suspicious,
            "all_services": services[:200],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_running_services", data, audit_id)

    @mcp.tool()
    def verify_findings(
        proposed_findings_json: str,
        audit_ids: list,
    ) -> str:
        """
        Verify proposed findings against raw tool outputs BEFORE submitting finish_analysis.

        Every claim (process names, IP addresses, MITRE techniques, file paths) is checked
        against the bytes returned by the cited tool calls. Claims that cannot be traced to
        raw evidence are flagged UNVERIFIED.

        Call this BEFORE finish_analysis. If grounding_score < 100%, review and correct
        the UNVERIFIED claims. Only call finish_analysis after achieving a clean grounding.

        Args:
            proposed_findings_json: JSON string of your planned findings dict.
                                    Must include: suspicious_processes, network_iocs,
                                    mitre_techniques, observation, interpretation.
            audit_ids:              List of audit_id strings from tool calls this session.
        """
        from mcp_server.config import ANALYSIS_DIR
        increment_tool_counter()

        if not audit_ids:
            return json.dumps({
                "error": "audit_ids required — provide audit_ids from tool calls this session."
            })

        # Accept the argument however the client/agent shaped it. FastMCP may hand
        # us a dict already, or a JSON string, or — when the agent over-escapes —
        # a JSON string that itself decodes to ANOTHER JSON string (double-encoded).
        # Decode up to a couple of layers until we reach a dict, so a quoting quirk
        # never surfaces as a server-side 'str has no attribute get' crash.
        findings = proposed_findings_json
        for _ in range(3):
            if isinstance(findings, dict):
                break
            if isinstance(findings, str):
                try:
                    findings = json.loads(findings)
                except (json.JSONDecodeError, ValueError) as e:
                    return json.dumps({"error": f"Invalid JSON in proposed_findings_json: {e}"})
            else:
                break
        if not isinstance(findings, dict):
            return json.dumps({
                "error": "proposed_findings_json must be a JSON OBJECT (dict) with keys like "
                         "suspicious_processes, network_iocs, mitre_techniques, observation, "
                         f"interpretation — got {type(findings).__name__}. Pass the object once, "
                         "not a quoted/escaped string of it.",
            })

        verifier = GroundingVerifier(ANALYSIS_DIR)
        result = verifier.verify(findings, audit_ids)

        # Confidence score preview
        confidence_preview = calculate_confidence_score(
            audit_ids=audit_ids,
            findings=findings,
            audit_log_path=ANALYSIS_DIR / "forensic_audit.log",
            grounding_score=result["grounding_score"],
        )

        return json.dumps({
            "grounding_verification": result,
            "confidence_preview": confidence_preview,
            "next_step": (
                "Grounding PASSED — proceed to finish_analysis."
                if result["verdict"] == "PASS"
                else f"Grounding FAILED — {result['unverified_count']} unverified claim(s). "
                     "Review unverified_claims and correct before finish_analysis."
            ),
        }, default=str)

    @mcp.tool()
    def finish_analysis(
        observation: str,
        interpretation: str,
        suspicious_processes: list,
        network_iocs: list,
        mitre_techniques: list,
        timeline: list,
        confidence: str,
        audit_ids: list,
    ) -> str:
        """
        Call this when you have sufficient evidence to write a final report.

        Separates factual observation from analytical interpretation to reduce
        hallucination. Requires audit_ids — every claim must cite a tool call.

        Automatically runs grounding verification and quantified confidence scoring.
        The report will not be saved if grounding_score is 0 (all claims unverifiable).

        Args:
            observation:           FACTUAL summary of raw tool outputs (what the tools showed).
                                   No interpretation. No speculation. Facts only.
            interpretation:        ANALYTICAL summary of what the observations MEAN for the
                                   investigation. Attribution, timeline reconstruction, impact.
            suspicious_processes:  List of suspicious process names with PIDs.
            network_iocs:          List of suspicious IPs, domains, or ports.
            mitre_techniques:      List of MITRE ATT&CK technique IDs observed.
            timeline:              Chronological list of events with timestamps.
            confidence:            'high', 'medium', or 'low' (qualitative label preserved
                                   alongside the numeric confidence score).
            audit_ids:             List of audit_id strings from the tool calls that
                                   support these findings. Cite every tool you relied on.
        """
        from mcp_server.config import ANALYSIS_DIR

        tool_count = get_tool_count()
        reset_tool_counter()

        if not audit_ids:
            return json.dumps({
                "error": "audit_ids is required — list the audit_id values from the tool calls "
                         "that produced the evidence for these findings. Every claim must be traceable.",
            })

        # ── Grounding verification ─────────────────────────────────────────────
        findings_draft = {
            "observation": observation,
            "interpretation": interpretation,
            "suspicious_processes": suspicious_processes,
            "network_iocs": network_iocs,
            "mitre_techniques": mitre_techniques,
        }
        verifier = GroundingVerifier(ANALYSIS_DIR)
        grounding = verifier.verify(findings_draft, audit_ids)

        # Hard block: if 0 claims verified and there are claims to verify, reject
        if (grounding["total_claims_checked"] > 0 and
                grounding["verified_count"] == 0):
            return json.dumps({
                "error": "GROUNDING FAILED — zero claims could be traced to raw evidence. "
                         "Every suspicious_processes / network_iocs / mitre_techniques entry "
                         "must appear verbatim in a cited tool's raw output. "
                         "Run verify_findings first to identify unverifiable claims.",
                "grounding": grounding,
            })

        # ── Quantified confidence scoring ──────────────────────────────────────
        confidence_score = calculate_confidence_score(
            audit_ids=audit_ids,
            findings=findings_draft,
            audit_log_path=ANALYSIS_DIR / "forensic_audit.log",
            grounding_score=grounding["grounding_score"],
        )

        # Fold in the autonomy ledger (hypotheses + self-corrections) if the agent
        # recorded any via record_hypothesis/update_hypothesis — this is the captured
        # evidence of senior-analyst reasoning when Claude Code itself is the agent.
        try:
            from mcp_server.tools.investigation_state import load_hypotheses, hypothesis_summary
            _hyps = load_hypotheses()
        except Exception:
            _hyps = []

        findings = {
            "observation": observation,
            "interpretation": interpretation,
            "summary": f"{observation} {interpretation}",
            "suspicious_processes": suspicious_processes,
            "network_iocs": network_iocs,
            "mitre_techniques": mitre_techniques,
            "timeline": timeline,
            "confidence_qualitative": confidence,
            "confidence_score": confidence_score,
            "grounding": grounding,
            "hypotheses": _hyps,
            "hypothesis_summary": hypothesis_summary(_hyps) if _hyps else {},
            "audit_ids": audit_ids,
            "tool_calls_used": tool_count,
            "status": "complete",
        }
        out = ANALYSIS_DIR / "findings.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

        return json.dumps({
            "status": "findings_saved",
            "path": str(out),
            "tool_calls_used": tool_count,
            "confidence_score": confidence_score["total_score"],
            "confidence_tier": confidence_score["tier"],
            "grounding_score": grounding["grounding_score"],
            "grounding_verdict": grounding["verdict"],
            "findings": findings,
        })


# ── Internal parsers ───────────────────────────────────────────────────────────

_SUSPICIOUS_SVC_PATHS = [
    "\\appdata\\", "\\temp\\", "\\tmp\\", "\\users\\public\\",
    "\\programdata\\", "\\recycle", "\\windows\\temp\\",
    "\\downloads\\", "\\desktop\\",
]


def _parse_svcscan(raw: str) -> list[dict]:
    """
    Parse Volatility 3 windows.svcscan output (TAB-delimited).
    Columns: Offset  Order  PID  Start  State  Type  Name  DisplayName  BinaryPath
    """
    services = []
    header_found = False

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Volatility") or stripped.startswith("Progress"):
            continue
        if "Name" in stripped and "State" in stripped and ("BinaryPath" in stripped or "Binary" in stripped):
            header_found = True
            continue
        if not header_found:
            continue

        parts = stripped.split("\t")
        if len(parts) < 6:
            parts = stripped.split()
            if len(parts) < 6:
                continue

        try:
            pid_raw = parts[2] if len(parts) > 2 else "0"
            pid = int(pid_raw) if pid_raw.isdigit() else 0
            state = parts[4] if len(parts) > 4 else ""
            name = parts[6] if len(parts) > 6 else ""
            binary_path = parts[8].strip() if len(parts) > 8 else ""
        except (IndexError, ValueError):
            continue

        suspicious = bool(binary_path) and any(
            s in binary_path.lower() for s in _SUSPICIOUS_SVC_PATHS
        )
        services.append({
            "name": name, "state": state, "pid": pid,
            "binary_path": binary_path, "suspicious": suspicious,
        })

    return services


_SUSPICIOUS_DLL_PATHS = [
    "\\appdata\\", "\\temp\\", "\\tmp\\", "\\users\\public\\",
    "\\programdata\\", "\\recycle", "\\windows\\fonts\\",
]
_SUSPICIOUS_DLL_NAMES = ["inject", "hook", "patch", "crypt", "rat", "loader"]


def _parse_dlllist(raw: str, pid: int) -> list[dict]:
    dlls = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("Volatility") or line.startswith("PID") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        path = parts[-1] if parts[-1].startswith("\\") or ":\\" in parts[-1] else ""
        name = Path(path).name if path else parts[0]
        suspicious = (
            any(s in path.lower() for s in _SUSPICIOUS_DLL_PATHS) or
            any(s in name.lower() for s in _SUSPICIOUS_DLL_NAMES)
        )
        dlls.append({"name": name, "path": path, "base": parts[0], "suspicious": suspicious})
    return dlls


_SUSPICIOUS_CMD_PATTERNS = [
    "base64", "-encodedcommand", "-enc ", "-nop", "bypass",
    "iex(", "invoke-expression", "invoke-webrequest", "downloadstring",
    "certutil", "bitsadmin", "mshta", "wscript", "cscript",
    "regsvr32", "rundll32", "net user", "net localgroup",
    "procdump", "mimikatz", "sekurlsa", "lsadump",
]


def _parse_cmdline(raw: str) -> list[dict]:
    results = []
    for line in raw.splitlines():
        line_s = line.strip()
        if not line_s or line_s.startswith("Volatility") or line_s.startswith("Progress"):
            continue
        if line_s.startswith("PID") and "Process" in line_s:
            continue
        parts = line_s.split()
        if len(parts) >= 2 and parts[0].isdigit():
            current_pid = int(parts[0])
            current_name = parts[1]
            cmdline = " ".join(parts[2:]) if len(parts) > 2 else ""
            suspicious_flags = [p for p in _SUSPICIOUS_CMD_PATTERNS if p in cmdline.lower()]
            results.append({
                "pid": current_pid, "name": current_name, "cmdline": cmdline,
                "suspicious": len(suspicious_flags) > 0,
                "suspicious_patterns": suspicious_flags,
            })
    return results


def _parse_hivelist(raw: str) -> list[dict]:
    hives = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("Volatility") or line.startswith("Offset") or line.startswith("Progress"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            hives.append({"offset": parts[0], "name": " ".join(parts[1:])})
    return hives


def _parse_printkey(raw: str) -> list[dict]:
    values = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("Volatility") or line.startswith("Last"):
            continue
        if "REG_" in line:
            parts = line.split()
            val_type_idx = next((i for i, p in enumerate(parts) if p.startswith("REG_")), -1)
            if val_type_idx > 0:
                values.append({
                    "name": " ".join(parts[:val_type_idx - 1]),
                    "type": parts[val_type_idx],
                    "data": " ".join(parts[val_type_idx + 1:]),
                })
    return values


def _parse_handles(raw: str) -> list[dict]:
    handles = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("Volatility") or "HandleValue" in line or line.startswith("Progress"):
            continue
        parts = line.split()
        if len(parts) >= 5:
            handles.append({
                "pid": parts[0], "handle": parts[1], "access": parts[2],
                "type": parts[3], "name": " ".join(parts[4:]),
            })
    return handles
