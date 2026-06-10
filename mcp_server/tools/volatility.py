"""
Volatility 3 MCP tool wrappers.
Each function = one typed MCP tool. No generic run_volatility() — the agent
cannot call an invalid plugin because each plugin is its own function.
"""
from __future__ import annotations
import json
import subprocess
from pathlib import Path

from mcp_server.config import VOLATILITY_CMD, MAX_TOOL_TIMEOUT
from mcp_server.audit import log_tool_execution
from mcp_server.parsers.pslist_parser import parse_pslist, analyze_processes
from mcp_server.parsers.netscan_parser import parse_netscan, get_external_ips
from mcp_server.parsers.malfind_parser import parse_malfind


def _run(cmd: list[str], tool_name: str) -> tuple[str, str]:
    """Run a subprocess, return (stdout, stderr). Always saves to audit log."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_TOOL_TIMEOUT,
        )
        log_tool_execution(
            tool_name=tool_name,
            command=cmd,
            raw_output=result.stdout,
            error=result.stderr,
        )
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        msg = f"Tool '{tool_name}' timed out after {MAX_TOOL_TIMEOUT}s"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg
    except FileNotFoundError:
        msg = f"Tool not found: {cmd[0]}. Is Volatility 3 installed on this SIFT system?"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg


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
    def get_process_list(image_path: str) -> str:
        """
        Lists all running processes extracted from a memory image.

        Call this FIRST in any memory investigation. Returns structured JSON with
        pid, ppid, name, threads, create_time, suspicious flag, and anomaly details.
        The suspicious flag is set by Python comparing against the SANS Hunt Evil
        known-normal Windows process baseline — not by the LLM guessing.

        Args:
            image_path: Absolute path to the memory image file (.raw, .vmem, .mem).
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.pslist"]
        stdout, stderr = _run(cmd, "get_process_list")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        processes = parse_pslist(stdout)
        processes = analyze_processes(processes)

        suspicious = [p for p in processes if p["suspicious"]]

        if rag and suspicious:
            for proc in suspicious:
                query = f"suspicious process {proc['name']} anomalies: {proc['anomalies']}"
                proc["threat_intel"] = rag.query(query, n_results=2)

        return json.dumps({
            "total_processes": len(processes),
            "suspicious_count": len(suspicious),
            "processes": processes,
            "investigation_note": (
                "Focus on processes marked suspicious=true. "
                "Check their DLLs with get_loaded_dlls and network connections with get_network_connections."
            ),
        }, default=str)

    @mcp.tool()
    def find_injected_code(image_path: str) -> str:
        """
        Finds processes with injected malicious code using memory region analysis.

        Use after get_process_list reveals suspicious processes. Python classifies
        each finding as shellcode, reflective_dll_injection, process_hollowing_candidate,
        or suspicious_exec_region based on memory protection flags and PE header presence.

        Args:
            image_path: Absolute path to the memory image file.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.malfind"]
        stdout, stderr = _run(cmd, "find_injected_code")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        findings = parse_malfind(stdout)
        high_risk = [f for f in findings if f.get("risk_level") == "high"]

        if rag and high_risk:
            for f in high_risk:
                query = f"memory injection {f['injection_type']} in process {f['process']}"
                f["threat_intel"] = rag.query(query, n_results=2)

        return json.dumps({
            "total_findings": len(findings),
            "high_risk_count": len(high_risk),
            "findings": findings,
            "investigation_note": (
                "high risk_level findings are most likely malicious. "
                "Cross-reference process names with get_process_list results."
            ),
        }, default=str)

    @mcp.tool()
    def get_network_connections(image_path: str) -> str:
        """
        Lists all active and recently closed network connections from memory.

        Use to identify C2 communication or data exfiltration. Returns structured JSON
        with protocol, local/foreign addresses, state, owning PID and process name.
        External IPs are flagged automatically. Use lookup_ip_reputation for any
        flagged IPs.

        Args:
            image_path: Absolute path to the memory image file.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.netscan"]
        stdout, stderr = _run(cmd, "get_network_connections")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        connections = parse_netscan(stdout)
        suspicious = [c for c in connections if c.get("suspicious")]
        external_ips = get_external_ips(connections)

        return json.dumps({
            "total_connections": len(connections),
            "suspicious_count": len(suspicious),
            "external_ips": external_ips,
            "connections": connections,
            "investigation_note": (
                f"Found {len(external_ips)} external IP(s). "
                "Use lookup_ip_reputation on each external IP to check for C2 infrastructure."
            ),
        }, default=str)

    @mcp.tool()
    def get_loaded_dlls(image_path: str, pid: int) -> str:
        """
        Lists all DLLs loaded by a specific process.

        Use after get_process_list or find_injected_code identifies a suspicious process.
        Unsigned DLLs in unusual paths (AppData, Temp, %USERPROFILE%) are flagged.

        Args:
            image_path: Absolute path to the memory image file.
            pid: Process ID from get_process_list output.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.dlllist", "--pid", str(pid)]
        stdout, stderr = _run(cmd, "get_loaded_dlls")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        dlls = _parse_dlllist(stdout, pid)
        suspicious_dlls = [d for d in dlls if d.get("suspicious")]

        return json.dumps({
            "pid": pid,
            "total_dlls": len(dlls),
            "suspicious_count": len(suspicious_dlls),
            "dlls": dlls,
        }, default=str)

    @mcp.tool()
    def get_command_history(image_path: str) -> str:
        """
        Extracts command line arguments for all processes from memory.

        Use to find commands executed by an attacker: PowerShell one-liners,
        certutil downloads, encoded commands, lateral movement tools.
        Suspicious patterns (base64, -EncodedCommand, wget, curl to external IPs)
        are flagged automatically.

        Args:
            image_path: Absolute path to the memory image file.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.cmdline"]
        stdout, stderr = _run(cmd, "get_command_history")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        cmdlines = _parse_cmdline(stdout)
        suspicious = [c for c in cmdlines if c.get("suspicious")]

        if rag and suspicious:
            for c in suspicious:
                query = f"suspicious command line: {c['cmdline'][:200]}"
                c["threat_intel"] = rag.query(query, n_results=2)

        return json.dumps({
            "total_processes": len(cmdlines),
            "suspicious_count": len(suspicious),
            "cmdlines": cmdlines,
        }, default=str)

    @mcp.tool()
    def get_registry_hives(image_path: str) -> str:
        """
        Lists registry hives loaded in memory.

        Use to find persistence mechanisms, user activity, and loaded user profiles.
        Returns hive names and virtual offsets for follow-up registry key extraction.

        Args:
            image_path: Absolute path to the memory image file.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.registry.hivelist"]
        stdout, stderr = _run(cmd, "get_registry_hives")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        hives = _parse_hivelist(stdout)
        return json.dumps({"hives": hives, "total": len(hives)}, default=str)

    @mcp.tool()
    def get_registry_key(image_path: str, hive_offset: str, key: str) -> str:
        """
        Reads a specific registry key and its values from memory.

        Use hive_offset from get_registry_hives. Key paths use backslash separators.
        Common persistence keys to check:
          SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
          SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce
          SYSTEM\\CurrentControlSet\\Services

        Args:
            image_path: Absolute path to the memory image file.
            hive_offset: Hex offset from get_registry_hives (e.g. '0xffff...')
            key: Registry key path relative to hive root.
        """
        cmd = VOLATILITY_CMD + [
            "-f", image_path,
            "windows.registry.printkey",
            "--offset", hive_offset,
            "--key", key,
        ]
        stdout, stderr = _run(cmd, "get_registry_key")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        values = _parse_printkey(stdout)
        return json.dumps({
            "hive_offset": hive_offset,
            "key": key,
            "values": values,
        }, default=str)

    @mcp.tool()
    def get_handles(image_path: str, pid: int) -> str:
        """
        Lists open handles (files, registry keys, mutexes) for a process.

        Useful for finding mutex names used by malware families, open file handles
        to sensitive files, and named pipe connections.

        Args:
            image_path: Absolute path to the memory image file.
            pid: Process ID from get_process_list output.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.handles", "--pid", str(pid)]
        stdout, stderr = _run(cmd, "get_handles")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        handles = _parse_handles(stdout)
        return json.dumps({
            "pid": pid,
            "total_handles": len(handles),
            "handles": handles,
        }, default=str)

    @mcp.tool()
    def finish_analysis(
        summary: str,
        suspicious_processes: list,
        network_iocs: list,
        mitre_techniques: list,
        timeline: list,
        confidence: str,
    ) -> str:
        """
        Call this when you have sufficient evidence to write a final report.
        Do NOT keep investigating if you have identified the key findings.
        This saves the findings to analysis/findings.json.

        Args:
            summary: Plain English description of what happened and how.
            suspicious_processes: List of suspicious process names with PIDs (e.g. ['svchost.exe (PID 1234)']).
            network_iocs: List of suspicious IPs, domains, or ports found.
            mitre_techniques: List of MITRE ATT&CK technique IDs observed (e.g. ['T1055', 'T1059']).
            timeline: List of events in chronological order with timestamps.
            confidence: Your confidence in the findings — 'high', 'medium', or 'low'.
        """
        from mcp_server.config import ANALYSIS_DIR
        findings = {
            "summary": summary,
            "suspicious_processes": suspicious_processes,
            "network_iocs": network_iocs,
            "mitre_techniques": mitre_techniques,
            "timeline": timeline,
            "confidence": confidence,
        }
        out = ANALYSIS_DIR / "findings.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

        return json.dumps({
            "status": "findings_saved",
            "path": str(out),
            "findings": findings,
        })


# ── Internal parsers for tools not in their own parser module ──────────────

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
    current_pid = None
    current_name = None
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
                "pid": current_pid,
                "name": current_name,
                "cmdline": cmdline,
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
                "pid": parts[0],
                "handle": parts[1],
                "access": parts[2],
                "type": parts[3],
                "name": " ".join(parts[4:]),
            })
    return handles
