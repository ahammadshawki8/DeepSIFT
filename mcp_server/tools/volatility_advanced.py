"""
Advanced Volatility 3 plugins — credential extraction, kernel forensics, and more.

Tools:
  get_modules        — Loaded kernel modules list (rootkit detection)
  get_driverirp      — IRP major function handler table (hook detection)
  get_getsids        — SID per process (privilege escalation evidence)
  get_hashdump       — SAM password hashes from memory (T1003.002)
  get_lsadump        — LSA secrets from memory (T1003.004)
  get_cachedump      — Cached domain credential hashes (T1003.005)
  get_clipboard      — Clipboard contents at memory capture time
  get_atoms          — Atom table (malware mutex/window class fingerprinting)
  get_sessions       — Logon sessions (RDP, interactive, service)
  get_mft_memory     — MFT records parsed from memory (file system view)
  get_ads_memory     — Alternate Data Streams found in memory MFT scan
  dump_process       — Dump a process executable to disk for further analysis
"""
from __future__ import annotations
import json
import re
import subprocess
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import VOLATILITY_CMD, MAX_TOOL_TIMEOUT, EXPORTS_DIR
from mcp_server.parsers.forensic_knowledge import wrap_response


def _vol(image_path: str, plugin: str, extra: list[str] | None = None) -> tuple[str, str]:
    cmd = VOLATILITY_CMD + ["-f", image_path, plugin] + (extra or [])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
        log_tool_execution(plugin, cmd, r.stdout, error=r.stderr)
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return "", f"{plugin} timed out"
    except FileNotFoundError:
        return "", "Volatility not found"


def register_volatility_advanced_tools(mcp, rag=None):

    @mcp.tool()
    def get_modules(image_path: str) -> str:
        """
        List loaded kernel modules (drivers) from a Windows memory image.

        Kernel modules loaded at unusual base addresses, from temp paths, or with
        non-standard names are indicators of rootkit activity (T1014, T1547.006).
        Cross-reference with get_callbacks and get_driverirp.

        Args:
            image_path: Absolute path to the memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol(image_path, "windows.modules.Modules")
        audit_id = get_last_audit_id()

        modules: list[dict] = []
        suspicious: list[dict] = []
        _KNOWN_DIRS = {"\\windows\\system32\\", "\\windows\\syswow64\\",
                       "\\windows\\system32\\drivers\\", "\\program files\\"}

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("Offset"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            name = parts[1] if len(parts) > 1 else ""
            path = " ".join(parts[2:]) if len(parts) > 2 else ""
            entry = {"name": name, "path": path}
            modules.append(entry)
            if not any(d in path.lower() for d in _KNOWN_DIRS):
                entry["suspicious_reason"] = "Non-standard module path"
                suspicious.append(entry)

        data = {
            "image_path": image_path,
            "total_modules": len(modules),
            "suspicious_modules": suspicious[:30],
            "all_modules": modules[:200],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_modules", data, audit_id)

    @mcp.tool()
    def get_driverirp(image_path: str) -> str:
        """
        Enumerate IRP (I/O Request Packet) major function handlers for all drivers.

        Rootkits hook IRP handlers to intercept file I/O, network I/O, and process
        creation at the kernel level. Handlers pointing outside the owning driver's
        address range indicate a hook.

        Args:
            image_path: Absolute path to the memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol(image_path, "windows.driverirp.DriverIrp")
        audit_id = get_last_audit_id()

        hooked: list[dict] = []
        all_entries: list[dict] = []

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("Offset"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                entry = {"raw": line[:300]}
                if "HOOK" in line.upper() or "UNKNOWN" in line.upper():
                    entry["hooked"] = True
                    hooked.append(entry)
                all_entries.append(entry)

        data = {
            "image_path": image_path,
            "total_irp_entries": len(all_entries),
            "hooked_handlers": hooked[:50],
            "all_irp_entries": all_entries[:200],
            "forensic_note": "Handlers pointing outside the owning driver = IRP hook (T1014 Rootkit)",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_driverirp", data, audit_id)

    @mcp.tool()
    def get_getsids(image_path: str, pid: int = 0) -> str:
        """
        List Security Identifiers (SIDs) associated with each process.

        Processes running under unexpected SIDs indicate privilege escalation
        (T1134 — Access Token Manipulation). A user process under SYSTEM SID
        (S-1-5-18) is a high-confidence compromise indicator.

        Args:
            image_path: Absolute path to the memory image.
            pid:        Optional — limit to a specific PID (0 = all processes).
        """
        increment_tool_counter()
        extra = ["--pid", str(pid)] if pid else []
        stdout, stderr = _vol(image_path, "windows.getsids.GetSIDs", extra)
        audit_id = get_last_audit_id()

        entries: list[dict] = []
        suspicious: list[dict] = []
        _SYSTEM_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}
        _SUSPICIOUS_NAMES = {"system", "local service", "network service"}

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("PID"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                pid_val = parts[0]
                proc = parts[1] if len(parts) > 1 else ""
                sid = parts[2] if len(parts) > 2 else ""
                sid_name = " ".join(parts[3:]) if len(parts) > 3 else ""
                entry = {"pid": pid_val, "process": proc, "sid": sid, "sid_name": sid_name}
                entries.append(entry)
                # Flag non-system processes running as SYSTEM
                if sid in _SYSTEM_SIDS and proc.lower() not in {
                    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
                    "lsass.exe", "svchost.exe", "winlogon.exe", "spoolsv.exe",
                }:
                    entry["suspicious_reason"] = f"Unexpected process running under {sid} ({sid_name})"
                    suspicious.append(entry)

        data = {
            "image_path": image_path,
            "total_sid_entries": len(entries),
            "suspicious_sid_assignments": suspicious[:30],
            "all_entries": entries[:300],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_getsids", data, audit_id)

    @mcp.tool()
    def get_hashdump(image_path: str) -> str:
        """
        Extract local user account password hashes from memory (SAM + SYSTEM).

        Dumps NTLM hashes for all local accounts from the in-memory SAM database.
        Hashes can be cracked offline or used in pass-the-hash attacks (T1003.002).

        Returns: usernames and NTLM hash strings (NOT plaintext passwords).
        Submit hashes to lookup_hash_reputation for known-password check.

        Args:
            image_path: Absolute path to the memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol(image_path, "windows.hashdump.Hashdump")
        audit_id = get_last_audit_id()

        accounts: list[dict] = []
        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("User"):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                accounts.append({
                    "username": parts[0].strip(),
                    "uid": parts[1].strip(),
                    "lm_hash": parts[2].strip(),
                    "ntlm_hash": parts[3].strip(),
                    "empty_password": parts[3].strip() == "31d6cfe0d16ae931b73c59d7e0c089c0",
                })
            elif len(parts) >= 2:
                accounts.append({"username": parts[0].strip(), "raw": line[:100]})

        data = {
            "image_path": image_path,
            "account_count": len(accounts),
            "accounts": accounts,
            "mitre": "T1003.002 — OS Credential Dumping: Security Account Manager",
            "next_step": "Submit ntlm_hash values to lookup_hash_reputation for known-password identification.",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_hashdump", data, audit_id)

    @mcp.tool()
    def get_lsadump(image_path: str) -> str:
        """
        Extract LSA (Local Security Authority) secrets from memory.

        LSA secrets contain: service account passwords, auto-logon credentials,
        VPN passwords, cached domain credentials, and DPAPI master keys.
        These are stored encrypted in HKLM\\SECURITY\\Policy\\Secrets.

        Args:
            image_path: Absolute path to the memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol(image_path, "windows.lsadump.LsaDump")
        audit_id = get_last_audit_id()

        secrets: list[dict] = []
        current: dict = {}
        for line in stdout.splitlines():
            if not line or line.startswith("Volatility"):
                continue
            if line.startswith("Secret:"):
                if current:
                    secrets.append(current)
                current = {"secret_name": line.replace("Secret:", "").strip()}
            elif line.startswith("Value:"):
                current["value_preview"] = line.replace("Value:", "").strip()[:200]
            else:
                current[f"raw_{len(current)}"] = line[:200]
        if current:
            secrets.append(current)

        data = {
            "image_path": image_path,
            "secret_count": len(secrets),
            "lsa_secrets": secrets,
            "mitre": "T1003.004 — OS Credential Dumping: LSA Secrets",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_lsadump", data, audit_id)

    @mcp.tool()
    def get_cachedump(image_path: str) -> str:
        """
        Extract cached domain credential hashes (DCC2/MSCachev2) from memory.

        Windows caches the last N domain logon credentials so users can log in
        offline. These DCC2 hashes can be cracked offline to reveal domain
        passwords (T1003.005 — Cached Domain Credentials).

        Args:
            image_path: Absolute path to the memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol(image_path, "windows.cachedump.Cachedump")
        audit_id = get_last_audit_id()

        caches: list[dict] = []
        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("Username"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                caches.append({
                    "username": parts[0],
                    "domain_cached_hash": parts[1] if len(parts) > 1 else "",
                })

        data = {
            "image_path": image_path,
            "cached_credential_count": len(caches),
            "cached_credentials": caches,
            "mitre": "T1003.005 — OS Credential Dumping: Cached Domain Credentials",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_cachedump", data, audit_id)

    @mcp.tool()
    def get_clipboard(image_path: str) -> str:
        """
        Extract clipboard contents from a Windows memory image.

        The clipboard may contain: copied passwords, sensitive document fragments,
        credentials copied from a password manager, or attacker tool output.
        Clipboard is cleared on reboot but survives memory capture.

        Args:
            image_path: Absolute path to the memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol(image_path, "windows.clipboard.Clipboard")
        audit_id = get_last_audit_id()

        entries: list[dict] = []
        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("Session"):
                continue
            entries.append({"raw": line[:500]})

        # Flag potential passwords/credentials
        cred_indicators = [
            e for e in entries
            if any(kw in str(e).lower() for kw in [
                "password", "pass", "secret", "token", "key", "hash",
                "admin", "root", "sudo", "credential",
            ])
        ]

        data = {
            "image_path": image_path,
            "clipboard_entry_count": len(entries),
            "potential_credential_entries": cred_indicators[:20],
            "clipboard_contents": entries[:100],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_clipboard", data, audit_id)

    @mcp.tool()
    def get_atoms(image_path: str) -> str:
        """
        Enumerate the Windows atom table from a memory image.

        Atoms are global string identifiers used by Windows for window class names
        and clipboard formats. Malware families register distinctive atom names
        as mutex substitutes or for inter-process communication (T1055).

        Args:
            image_path: Absolute path to the memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol(image_path, "windows.atoms.Atoms")
        audit_id = get_last_audit_id()

        atoms: list[dict] = []
        suspicious: list[dict] = []

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("Session"):
                continue
            parts = line.split()
            name = parts[-1] if parts else ""
            entry = {"atom_id": parts[1] if len(parts) > 1 else "", "name": name}
            atoms.append(entry)
            # Flag: all-caps GUIDs, long random strings, known malware atom patterns
            if (
                re.match(r"^[A-Z0-9_]{10,}$", name) or
                re.match(r"^\{[0-9A-F-]{36}\}$", name) or
                len(name) > 40
            ):
                entry["suspicious_reason"] = "Unusual atom name pattern"
                suspicious.append(entry)

        data = {
            "image_path": image_path,
            "total_atoms": len(atoms),
            "suspicious_atoms": suspicious[:30],
            "all_atoms": atoms[:300],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_atoms", data, audit_id)

    @mcp.tool()
    def get_sessions(image_path: str) -> str:
        """
        Enumerate logon sessions from a Windows memory image.

        Sessions reveal: interactive console logons, RDP sessions, service logons,
        and network logons. Multiple simultaneous sessions indicate concurrent access,
        and unexpected session types (e.g. RemoteInteractive for a server) are suspicious.

        Args:
            image_path: Absolute path to the memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol(image_path, "windows.sessions.Sessions")
        audit_id = get_last_audit_id()

        sessions: list[dict] = []
        suspicious: list[dict] = []

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("Session"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                entry = {
                    "session_id": parts[0],
                    "process": parts[1] if len(parts) > 1 else "",
                    "username": parts[2] if len(parts) > 2 else "",
                    "raw": line[:300],
                }
                sessions.append(entry)
                if "rdp" in line.lower() or "RemoteInteractive" in line:
                    entry["rdp_session"] = True
                    suspicious.append(entry)

        data = {
            "image_path": image_path,
            "total_sessions": len(sessions),
            "rdp_or_remote_sessions": suspicious[:20],
            "all_sessions": sessions[:100],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_sessions", data, audit_id)

    @mcp.tool()
    def get_mft_memory(image_path: str) -> str:
        """
        Scan for MFT (Master File Table) records in memory using Volatility.

        MFT records found in memory can reveal recently accessed/deleted files
        even if on-disk MFT has been modified. Provides file system state at
        the time of memory capture.

        Args:
            image_path: Absolute path to the memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol(image_path, "windows.mftscan.MFTScan")
        audit_id = get_last_audit_id()

        entries: list[dict] = []
        suspicious: list[dict] = []

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("Offset"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                filename = " ".join(parts[3:])
                entry = {"offset": parts[0], "record_num": parts[1], "filename": filename}
                entries.append(entry)
                if any(kw in filename.lower() for kw in [
                    "temp", "appdata\\local\\temp", "recycle", ".exe", ".dll", ".ps1",
                ]):
                    suspicious.append(entry)

        data = {
            "image_path": image_path,
            "mft_records_found": len(entries),
            "suspicious_file_records": suspicious[:50],
            "all_records": entries[:200],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_mft_memory", data, audit_id)

    @mcp.tool()
    def get_ads_memory(image_path: str) -> str:
        """
        Scan for NTFS Alternate Data Streams (ADS) in memory MFT records.

        ADS allow data to be hidden in the metadata of legitimate files —
        a classic anti-forensics and steganography technique (T1564.004).
        ADS hiding is detected by comparing the data stream count per MFT record.

        Args:
            image_path: Absolute path to the memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol(image_path, "windows.mftscan.ADS")
        audit_id = get_last_audit_id()

        ads_entries: list[dict] = []

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("Offset"):
                continue
            ads_entries.append({"raw": line[:400]})

        data = {
            "image_path": image_path,
            "ads_count": len(ads_entries),
            "ads_entries": ads_entries[:100],
            "mitre": "T1564.004 — Hide Artifacts: NTFS File Attributes (ADS)",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_ads_memory", data, audit_id)

    @mcp.tool()
    def dump_process(image_path: str, pid: int, output_dir: str = "") -> str:
        """
        Dump a process executable from memory to disk for static analysis.

        The dumped .exe can then be analysed with get_pe_metadata, detect_packer,
        extract_strings, or scan_file_with_yara to identify the malware family.

        Args:
            image_path:  Absolute path to the memory image.
            pid:         PID of the process to dump.
            output_dir:  Directory to write the dump (default: exports/).
        """
        increment_tool_counter()
        out_dir = Path(output_dir) if output_dir else EXPORTS_DIR / "procdump"
        out_dir.mkdir(parents=True, exist_ok=True)

        stdout, stderr = _vol(
            image_path, "windows.dumpfiles.DumpFiles",
            ["--pid", str(pid), "-o", str(out_dir)],
        )
        audit_id = get_last_audit_id()

        # List what was dumped
        dumped_files = list(out_dir.glob(f"pid.{pid}.*"))
        if not dumped_files:
            dumped_files = list(out_dir.glob("*.dmp"))

        data = {
            "image_path": image_path,
            "pid": pid,
            "output_dir": str(out_dir),
            "dumped_files": [str(f) for f in dumped_files[:20]],
            "file_count": len(dumped_files),
            "stdout_preview": stdout[:500],
            "next_steps": [
                f"get_pe_metadata('{dumped_files[0]}')" if dumped_files else "No files dumped",
                f"detect_packer('{dumped_files[0]}')" if dumped_files else "",
                f"scan_file_with_yara('{dumped_files[0]}', 'rats')" if dumped_files else "",
            ],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("dump_process", data, audit_id)
