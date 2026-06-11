"""
Extended Volatility 3 tool wrappers — Priority 4 (tool count expansion).

10 additional Volatility 3 plugins covering:
  - Privilege escalation detection (get_privileges)
  - Malware mutex fingerprinting (get_mutexes)
  - Environment variable leakage (get_env_vars)
  - VAD-level memory anomalies (get_vad_info)
  - Unlinked/hidden DLL detection (get_ldrmodules)
  - SSDT hook detection (get_ssdt)
  - Kernel callback rootkits (get_callbacks)
  - File-based IOC hunting (get_filescan)
  - Process activity timeline (get_timeliner)
  - Device driver stack (get_devicetree)
"""
from __future__ import annotations
import json
import subprocess

from mcp_server.config import VOLATILITY_CMD, MAX_TOOL_TIMEOUT
from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.parsers.forensic_knowledge import wrap_response


_SUSPICIOUS_PRIV = {
    "SeDebugPrivilege",        # allows access to any process — used by credential dumpers
    "SeImpersonatePrivilege",  # token impersonation — used by many exploits
    "SeTcbPrivilege",          # act as OS — extreme privilege
    "SeLoadDriverPrivilege",   # load kernel drivers — rootkit installation
    "SeCreateTokenPrivilege",  # create auth tokens — token forgery
    "SeAssignPrimaryTokenPrivilege",
    "SeRestorePrivilege",      # write any file — used for DLL planting
    "SeTakeOwnershipPrivilege",
}

_KNOWN_BENIGN_MUTEXES = {
    "local\\", "global\\", "session\\", "_msctf_", "crypt32_",
    "wer_", "net_", "rpc_", "ole_", "shim_",
}


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
        msg = f"Volatility 3 not found: {cmd[0]}"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg


def register_volatility_extended_tools(mcp, rag=None):

    @mcp.tool()
    def get_privileges(image_path: str, pid: int = 0) -> str:
        """
        List process privileges from memory. SeDebugPrivilege and SeImpersonatePrivilege
        in non-system processes are strong indicators of privilege escalation or credential
        dumping tools (T1134, T1003).

        Args:
            image_path: Absolute path to the memory image.
            pid:        Filter to a specific PID (0 = all processes).
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.privileges.Privs"]
        if pid:
            cmd += ["--pid", str(pid)]
        stdout, stderr = _run(cmd, "get_privileges")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        privs: list[dict] = []
        suspicious: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility") or line.startswith("PID"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                priv_name = parts[2] if len(parts) > 2 else ""
                is_enabled = "Enabled" in line or "Present" in line
                is_suspicious = priv_name in _SUSPICIOUS_PRIV and is_enabled
                entry = {
                    "pid": parts[0] if parts[0].isdigit() else "",
                    "process": parts[1] if len(parts) > 1 else "",
                    "privilege": priv_name,
                    "enabled": is_enabled,
                    "suspicious": is_suspicious,
                }
                privs.append(entry)
                if is_suspicious:
                    suspicious.append(entry)

        data = {
            "total_privilege_entries": len(privs),
            "suspicious_privileges": suspicious,
            "tool_calls_used": get_tool_count(),
            "all_privileges": privs[:200],
        }
        return wrap_response("get_privileges", data, audit_id)

    @mcp.tool()
    def get_mutexes(image_path: str) -> str:
        """
        List mutex objects from memory. Malware families use distinctive mutex names
        as anti-reinfection markers — these serve as reliable IOCs (T1106, T1055).

        Known C2 mutex patterns: GUID-style, all-caps random strings,
        names matching YARA signatures (e.g. Cobalt Strike default mutexes).

        Args:
            image_path: Absolute path to the memory image.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.mutantscan.MutantScan"]
        stdout, stderr = _run(cmd, "get_mutexes")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        mutexes: list[dict] = []
        suspicious: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility") or line.startswith("Offset"):
                continue
            parts = line.split()
            name = parts[-1] if parts else ""
            is_benign = any(b in name.lower() for b in _KNOWN_BENIGN_MUTEXES)
            is_suspicious = (
                not is_benign and len(name) > 5
                and (name.upper() == name or  # all caps = suspicious
                     len(name) > 30 or          # very long = suspicious
                     name.startswith("{"))       # GUID = possible C2 mutex
            )
            entry = {"offset": parts[0] if parts else "", "name": name, "suspicious": is_suspicious}
            mutexes.append(entry)
            if is_suspicious:
                suspicious.append(entry)

        data = {
            "total_mutexes": len(mutexes),
            "suspicious_mutexes": suspicious[:50],
            "tool_calls_used": get_tool_count(),
            "all_mutexes": mutexes[:300],
        }
        return wrap_response("get_mutexes", data, audit_id)

    @mcp.tool()
    def get_env_vars(image_path: str, pid: int = 0) -> str:
        """
        Extract environment variables from process memory. Attackers sometimes
        pass C2 URLs, credentials, or staging directories via environment variables
        to avoid command-line forensics (T1564.002, T1059).

        Args:
            image_path: Absolute path to the memory image.
            pid:        Filter to a specific PID (0 = all processes).
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.envars.Envars"]
        if pid:
            cmd += ["--pid", str(pid)]
        stdout, stderr = _run(cmd, "get_env_vars")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        vars_list: list[dict] = []
        suspicious: list[dict] = []
        _SUSPICIOUS_VAR_KEYWORDS = [
            "password", "passwd", "secret", "token", "key", "api",
            "c2", "beacon", "payload", "stager", "http://", "https://",
        ]
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility") or line.startswith("PID"):
                continue
            parts = line.split(None, 3)
            if len(parts) >= 4:
                var_name = parts[2]
                var_val = parts[3]
                is_susp = any(k in var_name.lower() or k in var_val.lower()
                              for k in _SUSPICIOUS_VAR_KEYWORDS)
                entry = {
                    "pid": parts[0],
                    "process": parts[1],
                    "variable": var_name,
                    "value": var_val[:200],
                    "suspicious": is_susp,
                }
                vars_list.append(entry)
                if is_susp:
                    suspicious.append(entry)

        data = {
            "total_env_vars": len(vars_list),
            "suspicious_env_vars": suspicious[:30],
            "tool_calls_used": get_tool_count(),
            "all_env_vars": vars_list[:300],
        }
        return wrap_response("get_env_vars", data, audit_id)

    @mcp.tool()
    def get_vad_info(image_path: str, pid: int) -> str:
        """
        List Virtual Address Descriptor (VAD) regions for a process.

        VAD regions with PAGE_EXECUTE_READWRITE (RWX) that are NOT backed by
        a mapped file (Private=True) are prime injection candidates (T1055).
        This is the same data malfind uses, but with full region context.

        Args:
            image_path: Absolute path to the memory image.
            pid:        Process ID from get_process_list.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.vadinfo.VadInfo", "--pid", str(pid)]
        stdout, stderr = _run(cmd, "get_vad_info")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        regions: list[dict] = []
        suspicious: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility") or line.startswith("PID"):
                continue
            parts = line.split()
            if len(parts) >= 5:
                protection = parts[4] if len(parts) > 4 else ""
                filename = parts[-1] if len(parts) > 8 else ""
                is_file_backed = filename.startswith("\\") or "." in filename
                is_rwx = "EXECUTE_READWRITE" in protection or protection in ("PAGE_EXECUTE_READWRITE",)
                is_suspicious = is_rwx and not is_file_backed
                entry = {
                    "start": parts[1] if len(parts) > 1 else "",
                    "end": parts[2] if len(parts) > 2 else "",
                    "protection": protection,
                    "file_backed": is_file_backed,
                    "filename": filename,
                    "suspicious": is_suspicious,
                }
                regions.append(entry)
                if is_suspicious:
                    suspicious.append(entry)

        data = {
            "pid": pid,
            "total_vad_regions": len(regions),
            "suspicious_rwx_private_regions": suspicious[:30],
            "tool_calls_used": get_tool_count(),
            "all_regions": regions[:200],
        }
        return wrap_response("get_vad_info", data, audit_id)

    @mcp.tool()
    def get_ldrmodules(image_path: str, pid: int) -> str:
        """
        Compare three module lists for a process: InLoadOrder, InMemoryOrder,
        InInitializationOrder. A DLL present in memory but ABSENT from one or more
        lists is unlinked — classic rootkit/injected DLL indicator (T1055.001).

        Args:
            image_path: Absolute path to the memory image.
            pid:        Process ID from get_process_list.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.ldrmodules.LdrModules", "--pid", str(pid)]
        stdout, stderr = _run(cmd, "get_ldrmodules")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        modules: list[dict] = []
        unlinked: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility") or line.startswith("Pid"):
                continue
            parts = line.split()
            if len(parts) >= 6:
                load = parts[2].upper() == "TRUE"
                mem = parts[3].upper() == "TRUE"
                init = parts[4].upper() == "TRUE"
                path = parts[5] if len(parts) > 5 else ""
                is_unlinked = not (load and mem and init)
                entry = {
                    "base": parts[1] if len(parts) > 1 else "",
                    "in_load": load, "in_mem": mem, "in_init": init,
                    "path": path,
                    "unlinked": is_unlinked,
                }
                modules.append(entry)
                if is_unlinked:
                    unlinked.append(entry)

        data = {
            "pid": pid,
            "total_modules": len(modules),
            "unlinked_modules": unlinked[:30],
            "tool_calls_used": get_tool_count(),
            "all_modules": modules[:200],
        }
        return wrap_response("get_ldrmodules", data, audit_id)

    @mcp.tool()
    def get_ssdt(image_path: str) -> str:
        """
        Dump the System Service Descriptor Table (SSDT) to detect kernel hooks.

        Legitimate SSDT entries point to ntoskrnl.exe or win32k.sys.
        Entries pointing elsewhere indicate a kernel rootkit (T1014, T1547.006).

        Args:
            image_path: Absolute path to the memory image.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.ssdt.SSDT"]
        stdout, stderr = _run(cmd, "get_ssdt")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        entries: list[dict] = []
        hooked: list[dict] = []
        _LEGIT = ("ntoskrnl", "ntkrnlpa", "win32k", "nt!")
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility") or line.startswith("Index"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                module = parts[3] if len(parts) > 3 else ""
                is_hooked = not any(leg in module.lower() for leg in _LEGIT)
                entry = {
                    "index": parts[0],
                    "address": parts[1] if len(parts) > 1 else "",
                    "function": parts[2] if len(parts) > 2 else "",
                    "module": module,
                    "hooked": is_hooked,
                }
                entries.append(entry)
                if is_hooked:
                    hooked.append(entry)

        data = {
            "total_ssdt_entries": len(entries),
            "hooked_entries": hooked[:30],
            "tool_calls_used": get_tool_count(),
            "verdict": "KERNEL HOOKS DETECTED — possible rootkit" if hooked else "SSDT appears clean",
        }
        return wrap_response("get_ssdt", data, audit_id)

    @mcp.tool()
    def get_callbacks(image_path: str) -> str:
        """
        List kernel notification callbacks registered in memory.

        Legitimate callbacks: security software, antivirus. Unrecognised drivers
        registering callbacks (PsSetCreateProcessNotifyRoutine etc.) indicate
        a kernel-level rootkit or monitoring implant (T1014, T1547.006).

        Args:
            image_path: Absolute path to the memory image.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.callbacks.Callbacks"]
        stdout, stderr = _run(cmd, "get_callbacks")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        callbacks: list[dict] = []
        _LEGIT_DRIVERS = {
            "ntoskrnl", "hal", "win32k", "tcpip", "ndis", "fltmgr",
            "ksecdd", "cng", "wdfilter", "defender", "mpfilter",
            "classpnp", "disk", "acpi", "pci", "volmgr", "ntfs",
        }
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility") or line.startswith("Type"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                module = parts[-1].lower()
                is_suspicious = not any(leg in module for leg in _LEGIT_DRIVERS)
                callbacks.append({
                    "type": parts[0],
                    "callback": parts[1] if len(parts) > 1 else "",
                    "module": parts[-1],
                    "suspicious": is_suspicious,
                })

        suspicious = [c for c in callbacks if c.get("suspicious")]
        data = {
            "total_callbacks": len(callbacks),
            "suspicious_callbacks": suspicious[:30],
            "tool_calls_used": get_tool_count(),
            "all_callbacks": callbacks[:200],
        }
        return wrap_response("get_callbacks", data, audit_id)

    @mcp.tool()
    def get_filescan(image_path: str, pattern: str = "") -> str:
        """
        Scan memory pool tags for FILE_OBJECT structures to find all files
        that were open at the time of capture — including deleted files still
        referenced in memory (T1070, T1083).

        Args:
            image_path: Absolute path to the memory image.
            pattern:    Optional filename substring to filter results.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.filescan.FileScan"]
        stdout, stderr = _run(cmd, "get_filescan")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        files: list[dict] = []
        _SUSPICIOUS_PATHS = ("\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\public\\")
        _EXEC_EXTS = (".exe", ".dll", ".sys", ".ps1", ".bat", ".vbs", ".cmd")

        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility") or line.startswith("Offset"):
                continue
            parts = line.split(None, 2)
            if len(parts) >= 3:
                path = parts[2]
                if pattern and pattern.lower() not in path.lower():
                    continue
                is_susp = (
                    any(s in path.lower() for s in _SUSPICIOUS_PATHS) and
                    any(path.lower().endswith(e) for e in _EXEC_EXTS)
                )
                files.append({
                    "offset": parts[0],
                    "handles": parts[1],
                    "path": path,
                    "suspicious": is_susp,
                })

        suspicious = [f for f in files if f.get("suspicious")]
        data = {
            "total_file_objects": len(files),
            "suspicious_file_objects": suspicious[:50],
            "pattern_filter": pattern,
            "tool_calls_used": get_tool_count(),
            "all_files": files[:300],
        }
        return wrap_response("get_filescan", data, audit_id)

    @mcp.tool()
    def get_timeliner(image_path: str) -> str:
        """
        Extract a timeline of process creation, DLL load, and module events
        from memory. Reveals the exact sequence of activity without needing
        disk artifacts (T1083, T1055, T1059).

        Args:
            image_path: Absolute path to the memory image.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "timeliner.Timeliner"]
        stdout, stderr = _run(cmd, "get_timeliner")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        events: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility"):
                continue
            parts = line.split("|")
            if len(parts) >= 3:
                events.append({
                    "timestamp": parts[0].strip(),
                    "type": parts[1].strip(),
                    "description": parts[2].strip(),
                })

        events.sort(key=lambda e: e.get("timestamp", ""))
        data = {
            "total_timeline_events": len(events),
            "events": events[:200],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_timeliner", data, audit_id)

    @mcp.tool()
    def get_devicetree(image_path: str) -> str:
        """
        List the Windows I/O device driver stack from memory.

        Unrecognised drivers or drivers loaded from non-standard paths indicate
        kernel-mode rootkits or implants (T1014, T1547.006). Cross-reference
        driver paths with get_filescan to check if they still exist on disk.

        Args:
            image_path: Absolute path to the memory image.
        """
        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.devicetree.DeviceTree"]
        stdout, stderr = _run(cmd, "get_devicetree")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        drivers: list[dict] = []
        _LEGIT_PATHS = ("\\windows\\system32\\drivers\\", "\\windows\\system32\\")
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Volatility"):
                continue
            if "DRV" in line or "DEV" in line:
                parts = line.split()
                path = parts[-1] if parts else ""
                is_suspicious = bool(path) and not any(lp in path.lower() for lp in _LEGIT_PATHS)
                drivers.append({
                    "type": "driver",
                    "path": path,
                    "raw": line[:200],
                    "suspicious": is_suspicious,
                })

        suspicious = [d for d in drivers if d.get("suspicious")]
        data = {
            "total_driver_entries": len(drivers),
            "suspicious_drivers": suspicious[:30],
            "tool_calls_used": get_tool_count(),
            "all_drivers": drivers[:200],
        }
        return wrap_response("get_devicetree", data, audit_id)
