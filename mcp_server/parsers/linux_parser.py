"""
Linux forensics middleware parser.

Classifies Linux process, network, shell history, and system log findings.
"""
from __future__ import annotations
import re

# Processes commonly used by attackers for reverse shells / C2
_SUSPICIOUS_LINUX_PROCS = {
    "nc", "ncat", "netcat", "nmap", "masscan",
    "socat", "msfconsole", "meterpreter", "empire",
    "python3 -c", "python -c", "perl -e", "ruby -e",
    "bash -i", "sh -i", "/dev/tcp", "/dev/udp",
    "cryptominer", "xmrig", "minerd",
}

# Bash commands that indicate attacker activity
_ATTACK_CMD_PATTERNS = re.compile(
    r"(wget\s|curl\s.*-[oO]\s"
    r"|chmod\s+(\+x|777|4777|4755)"
    r"|base64\s+(-d|--decode)"
    r"|python.*-c\s+['\"]"
    r"|perl\s+-e\s+['\"]"
    r"|bash\s+-i\s*>"
    r"|/dev/tcp/"
    r"|nc\s+-[elp]"
    r"|history\s+-c"
    r"|unset\s+HISTFILE"
    r"|HISTSIZE=0"
    r"|>/dev/null\s+2>&1"
    r"|ssh-keygen.*-f.*authorized_keys"
    r"|useradd|userdel|usermod\s+-aG.*sudo"
    r"|crontab\s+-[el]"
    r"|rm\s+-rf\s+/)"
    r"|(iptables|ufw)\s+(-F|-D)"
    r"|systemctl\s+(stop|disable)\s+(ufw|firewall|selinux)",
    re.IGNORECASE,
)

# LD_PRELOAD / library hijacking patterns
_LD_HIJACK_RE = re.compile(r"LD_PRELOAD|LD_LIBRARY_PATH=/tmp|LD_LIBRARY_PATH=/dev", re.IGNORECASE)

# Syslog patterns for authentication events
_AUTH_FAILURE_RE = re.compile(
    r"(Failed password|authentication failure|Invalid user|FAILED LOGIN|sudo:.*incorrect password)",
    re.IGNORECASE,
)
_AUTH_SUCCESS_RE = re.compile(
    r"(Accepted password|Accepted publickey|session opened for user)",
    re.IGNORECASE,
)
_SUDO_RE = re.compile(r"sudo:\s+\S+\s*:", re.IGNORECASE)


def classify_linux_process(proc: dict) -> list[str]:
    """
    Classify a Linux process dict for suspicious characteristics.

    Returns list of threat flags.
    """
    flags: list[str] = []
    comm = str(proc.get("comm", proc.get("name", ""))).lower()
    cmdline = str(proc.get("cmdline", proc.get("command", ""))).lower()

    if any(s in comm or s in cmdline for s in _SUSPICIOUS_LINUX_PROCS):
        flags.append("SUSPICIOUS_PROCESS_NAME")

    if _ATTACK_CMD_PATTERNS.search(cmdline):
        flags.append("ATTACK_COMMAND_PATTERN")

    if _LD_HIJACK_RE.search(cmdline):
        flags.append("LD_PRELOAD_HIJACK")

    ppid = str(proc.get("ppid", "0"))
    if ppid == "1" and comm not in {"init", "systemd", "kernel", "kthreadd"}:
        pass  # normal for many daemons

    return flags


def classify_bash_command(cmd: str, pid: str = "") -> dict:
    """
    Classify a single bash command for threat level and MITRE technique.
    """
    flags: list[str] = []

    if _ATTACK_CMD_PATTERNS.search(cmd):
        flags.append("ATTACK_COMMAND")
    if _LD_HIJACK_RE.search(cmd):
        flags.append("LD_PRELOAD_HIJACK")
    if re.search(r"history\s+-c|unset\s+HISTFILE|HISTSIZE=0", cmd, re.IGNORECASE):
        flags.append("HISTORY_WIPE")

    mitre = _cmd_to_mitre(cmd, flags)
    return {
        "command": cmd[:400],
        "pid": pid,
        "threat_flags": flags,
        "mitre": mitre,
        "risk_level": "high" if flags else "low",
    }


def _cmd_to_mitre(cmd: str, flags: list[str]) -> str:
    techniques: list[str] = []
    if re.search(r"wget|curl.*-[oO]", cmd, re.IGNORECASE):
        techniques.append("T1105 — Ingress Tool Transfer")
    if re.search(r"nc\s+-[elp]|socat|bash\s+-i|/dev/tcp", cmd, re.IGNORECASE):
        techniques.append("T1059.004 — Unix Shell")
    if re.search(r"crontab|/etc/cron", cmd, re.IGNORECASE):
        techniques.append("T1053.003 — Scheduled Task/Job: Cron")
    if re.search(r"useradd|usermod.*sudo", cmd, re.IGNORECASE):
        techniques.append("T1136.001 — Create Account: Local Account")
    if "LD_PRELOAD_HIJACK" in flags:
        techniques.append("T1574.006 — Hijack Execution Flow: Dynamic Linker")
    if "HISTORY_WIPE" in flags:
        techniques.append("T1070.003 — Indicator Removal: Clear Command History")
    if re.search(r"xmrig|cryptominer|minerd", cmd, re.IGNORECASE):
        techniques.append("T1496 — Resource Hijacking (Cryptomining)")
    return "; ".join(techniques)


def classify_syslog_line(line: str, source: str = "") -> dict | None:
    """
    Classify a single syslog line.

    Returns a finding dict if the line is interesting, else None.
    """
    event_type = ""
    mitre = ""

    if _AUTH_FAILURE_RE.search(line):
        event_type = "auth_failure"
        mitre = "T1110 — Brute Force"
    elif _AUTH_SUCCESS_RE.search(line):
        event_type = "auth_success"
        mitre = "T1078 — Valid Accounts"
    elif _SUDO_RE.search(line):
        event_type = "sudo_usage"
        mitre = "T1548.003 — Abuse Elevation Control Mechanism: Sudo"
    elif re.search(r"cron\[|CRON\[", line):
        event_type = "cron_execution"
        mitre = "T1053.003 — Scheduled Task/Job: Cron"
    elif re.search(r"kernel:.*oom|kernel:.*segfault|kernel:.*call trace", line, re.IGNORECASE):
        event_type = "kernel_event"
    else:
        return None

    return {
        "source": source,
        "event_type": event_type,
        "line": line[:300],
        "mitre": mitre,
    }


def classify_syslog_entries(lines: list[tuple[str, str]]) -> tuple[list[dict], dict]:
    """
    Classify a list of (source, line) tuples from syslog files.

    Returns: (classified_events, category_summary)
    """
    events: list[dict] = []
    summary: dict[str, int] = {
        "auth_failure": 0,
        "auth_success": 0,
        "sudo_usage": 0,
        "cron_execution": 0,
        "kernel_event": 0,
    }

    for source, line in lines:
        finding = classify_syslog_line(line, source)
        if finding:
            events.append(finding)
            category = finding.get("event_type", "")
            if category in summary:
                summary[category] += 1

    return events, summary
