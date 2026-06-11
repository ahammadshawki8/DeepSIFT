"""
Linux forensics tools — Volatility Linux plugins + disk/log artifact analysis.

Tools:
  get_linux_processes    — linux.pslist + pstree
  get_linux_bash_history — linux.bash: bash history from memory
  get_linux_network      — linux.lsof + linux.netfilter
  get_linux_modules      — linux.check_modules: rootkit detection
  get_linux_syscall      — linux.check_syscall: syscall table hook detection
  get_linux_malfind      — linux.malfind: injected code detection
  get_linux_envars       — linux.envars: process environment variables
  get_linux_mounts       — linux.mount: mounted file systems
  parse_syslog           — Parse /var/log/syslog, auth.log, kern.log, secure
  parse_linux_crontab    — Cron persistence analysis (T1053.003)
"""
from __future__ import annotations
import json
import re
import subprocess
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import VOLATILITY_CMD, MAX_TOOL_TIMEOUT
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.parsers.linux_parser import (
    classify_linux_process, classify_bash_command, classify_syslog_entries
)
from mcp_server.parsers.rag_enrichment import enrich_findings, build_rag_summary
from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques


def _vol_linux(image_path: str, plugin: str, extra: list[str] | None = None) -> tuple[str, str]:
    cmd = VOLATILITY_CMD + ["-f", image_path, plugin] + (extra or [])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
        log_tool_execution(plugin, cmd, r.stdout, error=r.stderr)
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return "", f"{plugin} timed out"
    except FileNotFoundError:
        return "", "Volatility not found"


def register_linux_forensics_tools(mcp, rag=None):

    @mcp.tool()
    def get_linux_processes(image_path: str) -> str:
        """
        List running processes from a Linux memory image using linux.pslist.

        Returns process hierarchy, PID/PPID relationships, and flags suspicious
        processes: processes with no TTY doing network I/O, kernel threads running
        unexpected code, and processes with mismatched names.

        Args:
            image_path: Absolute path to the Linux memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol_linux(image_path, "linux.pslist.PsList")
        audit_id = get_last_audit_id()

        processes: list[dict] = []
        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("OFFSET"):
                continue
            parts = line.split()
            if len(parts) >= 5:
                processes.append({
                    "pid": parts[0],
                    "ppid": parts[1],
                    "comm": parts[2],
                    "create_time": parts[3] if len(parts) > 3 else "",
                    "file_output": parts[4] if len(parts) > 4 else "",
                })

        suspicious = [
            p for p in processes
            if any(kw in p.get("comm", "").lower() for kw in [
                "nc", "ncat", "nmap", "bash", "sh", "python", "perl", "ruby",
                "php", "curl", "wget", "socat", "meterpreter", "empire",
            ])
        ]

        # Middleware parser: structured classification via linux_parser
        for proc in processes:
            flags = classify_linux_process(proc)
            if flags:
                proc["threat_flags"] = flags
                proc["mitre_techniques"] = map_finding_to_techniques(" ".join(flags))
                if proc not in suspicious:
                    suspicious.append(proc)

        enrich_findings(rag, suspicious,
                        lambda p: f"Linux suspicious process {p.get('comm', '')} {p.get('threat_flags', [])} rootkit")

        data = {
            "image_path": image_path,
            "total_processes": len(processes),
            "suspicious_processes": suspicious[:30],
            "all_processes": processes[:200],
            "rag_context": build_rag_summary(rag, "Linux process anomaly rootkit reverse shell T1059.004"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_linux_processes", data, audit_id)

    @mcp.tool()
    def get_linux_bash_history(image_path: str) -> str:
        """
        Extract bash command history from a Linux memory image.

        The linux.bash plugin reads bash history from memory, including commands
        that were NOT saved to ~/.bash_history (e.g. when HISTFILE=/dev/null).
        This recovers commands an attacker may have deliberately hidden.

        Args:
            image_path: Absolute path to the Linux memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol_linux(image_path, "linux.bash.Bash")
        audit_id = get_last_audit_id()

        commands: list[dict] = []
        suspicious: list[dict] = []
        _SUSPICIOUS_CMDS = {
            "wget", "curl", "nc", "ncat", "chmod +x", "chmod 777",
            "base64", "python -c", "perl -e", "ruby -e", "bash -i",
            "/dev/tcp", "socat", "iptables", "crontab", "visudo",
            "passwd", "useradd", "usermod", "ssh-keygen", "authorized_keys",
            "rm -rf", "shred", "history -c", "unset HISTFILE",
        }

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("PID"):
                continue
            parts = line.split(maxsplit=3)
            if len(parts) >= 2:
                cmd_text = parts[-1] if len(parts) >= 2 else line
                entry = {"pid": parts[0], "command": cmd_text[:400]}
                commands.append(entry)
                if any(s in cmd_text for s in _SUSPICIOUS_CMDS):
                    entry["suspicious_reason"] = "Known malicious command pattern"
                    suspicious.append(entry)

        # Middleware parser: structured bash command classification
        classified: list[dict] = []
        for cmd_entry in commands:
            classified.append(classify_bash_command(
                cmd_entry.get("command", ""), cmd_entry.get("pid", "")
            ))
        mp_suspicious = [c for c in classified if c.get("risk_level") == "high"]
        enrich_findings(rag, mp_suspicious,
                        lambda c: f"Linux bash command attack {c.get('command', '')} {c.get('mitre', '')}")

        data = {
            "image_path": image_path,
            "total_commands": len(commands),
            "suspicious_commands": suspicious[:50],
            "classified_suspicious": mp_suspicious[:50],
            "all_commands": commands[:300],
            "rag_context": build_rag_summary(rag, "Linux bash history attack command T1059.004 T1105"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_linux_bash_history", data, audit_id)

    @mcp.tool()
    def get_linux_network(image_path: str) -> str:
        """
        List open files and network connections from a Linux memory image (linux.lsof).

        Returns: open sockets per process, listening ports, established connections,
        and flags unexpected network-facing processes.

        Args:
            image_path: Absolute path to the Linux memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol_linux(image_path, "linux.lsof.Lsof")
        audit_id = get_last_audit_id()

        entries: list[dict] = []
        sockets: list[dict] = []

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("PID"):
                continue
            entry = {"raw": line[:300]}
            entries.append(entry)
            if "socket" in line.lower() or re.search(r"\d+\.\d+\.\d+\.\d+", line):
                sockets.append(entry)

        data = {
            "image_path": image_path,
            "total_open_files": len(entries),
            "socket_entries": sockets[:100],
            "all_entries": entries[:200],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_linux_network", data, audit_id)

    @mcp.tool()
    def get_linux_modules(image_path: str) -> str:
        """
        Check loaded Linux kernel modules for rootkits using linux.check_modules.

        Compares kernel module lists to detect hidden modules (loaded but not
        in /proc/modules or /sys/module — DKOM equivalent for Linux).

        Args:
            image_path: Absolute path to the Linux memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol_linux(image_path, "linux.check_modules.Check_modules")
        audit_id = get_last_audit_id()

        hidden_modules: list[dict] = []
        all_modules: list[dict] = []

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility"):
                continue
            entry = {"raw": line[:300]}
            all_modules.append(entry)
            if "hidden" in line.lower() or "HIDDEN" in line:
                entry["hidden"] = True
                hidden_modules.append(entry)

        data = {
            "image_path": image_path,
            "total_modules": len(all_modules),
            "hidden_modules": hidden_modules[:30],
            "all_modules": all_modules[:100],
            "mitre": "T1014 — Rootkit: hidden kernel module detected" if hidden_modules else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_linux_modules", data, audit_id)

    @mcp.tool()
    def get_linux_syscall(image_path: str) -> str:
        """
        Check Linux syscall table for hooks (linux.check_syscall).

        Rootkits hook system call handlers to intercept open(), read(), write(),
        kill(), getdents() etc. Hooked entries point outside the kernel text
        segment. Detecting syscall hooks is a primary rootkit indicator on Linux.

        Args:
            image_path: Absolute path to the Linux memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol_linux(image_path, "linux.check_syscall.Check_syscall")
        audit_id = get_last_audit_id()

        hooked: list[dict] = []
        all_entries: list[dict] = []

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility"):
                continue
            entry = {"raw": line[:300]}
            all_entries.append(entry)
            if "HOOKED" in line or "hook" in line.lower():
                hooked.append(entry)

        data = {
            "image_path": image_path,
            "total_syscall_entries": len(all_entries),
            "hooked_syscalls": hooked[:30],
            "mitre": "T1014 — Rootkit: syscall table hook detected" if hooked else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_linux_syscall", data, audit_id)

    @mcp.tool()
    def get_linux_malfind(image_path: str) -> str:
        """
        Find injected code in Linux process memory (linux.malfind).

        Flags: private anonymous RWX memory regions, PE headers in ELF memory space,
        and memory regions with characteristics typical of shellcode injection.

        Args:
            image_path: Absolute path to the Linux memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol_linux(image_path, "linux.malfind.Malfind")
        audit_id = get_last_audit_id()

        findings: list[dict] = []
        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("PID"):
                continue
            findings.append({"raw": line[:400]})

        data = {
            "image_path": image_path,
            "finding_count": len(findings),
            "findings": findings[:100],
            "mitre": "T1055 — Process Injection" if findings else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_linux_malfind", data, audit_id)

    @mcp.tool()
    def get_linux_envars(image_path: str) -> str:
        """
        Extract environment variables from Linux processes in memory.

        Environment variables can reveal: LD_PRELOAD injection (T1574.006),
        malicious library paths, C2 configuration passed via env vars,
        and attacker credentials or tokens stored in variables.

        Args:
            image_path: Absolute path to the Linux memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol_linux(image_path, "linux.envars.Envars")
        audit_id = get_last_audit_id()

        entries: list[dict] = []
        suspicious: list[dict] = []

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("PID"):
                continue
            entry = {"raw": line[:400]}
            entries.append(entry)
            if any(kw in line for kw in ["LD_PRELOAD", "LD_LIBRARY_PATH", "SECRET", "TOKEN", "PASS", "KEY"]):
                entry["suspicious_reason"] = "Suspicious environment variable"
                suspicious.append(entry)

        ld_preload = [e for e in entries if "LD_PRELOAD" in e.get("raw", "")]

        data = {
            "image_path": image_path,
            "total_env_entries": len(entries),
            "ld_preload_entries": ld_preload[:20],
            "suspicious_entries": suspicious[:30],
            "all_entries": entries[:200],
            "mitre": "T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking" if ld_preload else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_linux_envars", data, audit_id)

    @mcp.tool()
    def get_linux_mounts(image_path: str) -> str:
        """
        List mounted file systems from a Linux memory image (linux.mount).

        Reveals: mounted network shares (NFS, SMB/CIFS), encrypted volumes,
        hidden tmpfs mounts used by malware, and removable media.

        Args:
            image_path: Absolute path to the Linux memory image.
        """
        increment_tool_counter()
        stdout, stderr = _vol_linux(image_path, "linux.mount.Mount")
        audit_id = get_last_audit_id()

        mounts: list[dict] = []
        suspicious: list[dict] = []

        for line in stdout.splitlines():
            if not line or line.startswith("Volatility") or line.startswith("Mount"):
                continue
            entry = {"raw": line[:300]}
            mounts.append(entry)
            if any(kw in line.lower() for kw in ["cifs", "nfs", "sshfs", "tmpfs /tmp/", "ramfs"]):
                entry["suspicious_reason"] = "Suspicious mount type or location"
                suspicious.append(entry)

        data = {
            "image_path": image_path,
            "total_mounts": len(mounts),
            "suspicious_mounts": suspicious[:20],
            "all_mounts": mounts[:100],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_linux_mounts", data, audit_id)

    @mcp.tool()
    def parse_syslog(log_dir: str, keywords: str = "", hours_back: int = 0) -> str:
        """
        Parse Linux system logs (syslog, auth.log, kern.log, secure, messages).

        Returns: authentication failures, sudo usage, SSH logons, cron jobs,
        kernel warnings, and service start/stop events.

        Args:
            log_dir:    Directory containing log files (e.g. /mnt/evidence/var/log/).
            keywords:   Comma-separated additional keywords to filter for.
            hours_back: Limit to events from the last N hours (0 = all).
        """
        increment_tool_counter()
        log_path = Path(log_dir)
        if not log_path.exists():
            return json.dumps({"error": f"Log directory not found: {log_dir}"})

        log_tool_execution("parse_syslog", [log_dir], "syslog parse")
        audit_id = get_last_audit_id()

        _INTERESTING = [
            "Failed password", "Accepted password", "Accepted publickey",
            "sudo:", "su:", "COMMAND=", "session opened", "session closed",
            "Invalid user", "authentication failure", "PAM",
            "sshd", "cron", "kernel:", "iptables", "segfault",
            "OOM killer", "auditd", "useradd", "userdel", "usermod",
        ]
        if keywords:
            _INTERESTING.extend(k.strip() for k in keywords.split(",") if k.strip())

        _LOG_FILES = ["syslog", "auth.log", "kern.log", "secure", "messages",
                      "syslog.1", "auth.log.1"]

        events: list[dict] = []
        failed_auth: list[str] = []
        ssh_logons: list[str] = []
        sudo_events: list[str] = []

        for log_name in _LOG_FILES:
            log_file = log_path / log_name
            if not log_file.exists():
                continue
            try:
                for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not any(kw in line for kw in _INTERESTING):
                        continue
                    events.append({"source": log_name, "line": line[:300]})
                    if "Failed password" in line or "authentication failure" in line:
                        failed_auth.append(line[:200])
                    if "Accepted" in line and "sshd" in line:
                        ssh_logons.append(line[:200])
                    if "sudo:" in line:
                        sudo_events.append(line[:200])
            except Exception:
                pass

        # Middleware parser: structured syslog classification
        line_tuples = [(e.get("source", ""), e.get("line", "")) for e in events]
        classified_events, summary_counts = classify_syslog_entries(line_tuples)
        auth_failures = [e for e in classified_events if e.get("event_type") == "auth_failure"]
        enrich_findings(rag, auth_failures,
                        lambda e: f"Linux SSH brute force authentication failure {e.get('line', '')} T1110")

        data = {
            "log_dir": log_dir,
            "total_events": len(events),
            "failed_auth_count": len(failed_auth),
            "ssh_logon_count": len(ssh_logons),
            "sudo_event_count": len(sudo_events),
            "classified_summary": summary_counts,
            "classified_events": classified_events[:100],
            "failed_auth_events": failed_auth[:50],
            "ssh_logon_events": ssh_logons[:50],
            "sudo_events": sudo_events[:50],
            "all_events": events[:300],
            "rag_context": build_rag_summary(rag, "Linux authentication brute force lateral movement T1110"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_syslog", data, audit_id)

    @mcp.tool()
    def parse_linux_crontab(evidence_root: str) -> str:
        """
        Analyse Linux cron persistence artifacts.

        Checks: /etc/crontab, /etc/cron.d/, /etc/cron.daily|weekly|monthly|hourly/,
        and user crontabs in /var/spool/cron/crontabs/.

        Persistent cron jobs added by an attacker are a primary Linux persistence
        mechanism (T1053.003 — Scheduled Task/Job: Cron).

        Args:
            evidence_root: Root of the mounted evidence (e.g. /mnt/evidence/).
                           Cron files are found relative to this path.
        """
        increment_tool_counter()
        root = Path(evidence_root)
        if not root.exists():
            return json.dumps({"error": f"Evidence root not found: {evidence_root}"})

        log_tool_execution("parse_linux_crontab", [evidence_root], "cron artifact parse")
        audit_id = get_last_audit_id()

        cron_locations = [
            "etc/crontab",
            "etc/cron.d",
            "etc/cron.daily",
            "etc/cron.weekly",
            "etc/cron.monthly",
            "etc/cron.hourly",
            "var/spool/cron/crontabs",
            "var/spool/cron",
        ]

        all_cron_jobs: list[dict] = []
        suspicious_jobs: list[dict] = []

        for loc in cron_locations:
            p = root / loc
            if p.is_file():
                files = [p]
            elif p.is_dir():
                files = list(p.iterdir())
            else:
                continue
            for f in files:
                if f.is_file():
                    try:
                        text = f.read_text(encoding="utf-8", errors="replace")
                        for line in text.splitlines():
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            job = {"source": str(f.relative_to(root)), "entry": line}
                            all_cron_jobs.append(job)
                            if any(kw in line for kw in [
                                "wget", "curl", "bash", "python", "perl", "ruby",
                                "/tmp", "/dev/shm", "base64", "nc ", "ncat",
                                "chmod", "rm -f", "> /dev/null",
                            ]):
                                job["suspicious_reason"] = "Suspicious cron command"
                                suspicious_jobs.append(job)
                    except Exception:
                        pass

        data = {
            "evidence_root": evidence_root,
            "total_cron_entries": len(all_cron_jobs),
            "suspicious_cron_jobs": suspicious_jobs[:30],
            "all_cron_entries": all_cron_jobs[:200],
            "mitre": "T1053.003 — Scheduled Task/Job: Cron" if suspicious_jobs else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("parse_linux_crontab", data, audit_id)
