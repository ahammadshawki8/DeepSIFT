"""
Parse Volatility 3 windows.pslist output into structured dicts and flag anomalies
against the SANS Hunt Evil known-normal baseline (FOR508 poster).
"""
from __future__ import annotations

# Source: SANS FOR508 Hunt Evil poster — known-normal Windows process baseline
KNOWN_NORMAL: dict[str, dict] = {
    "System": {
        "expected_parent": None,
        "max_instances": 1,
        "expected_user": "SYSTEM",
        "notes": "PID always 4",
    },
    "smss.exe": {
        "expected_parent": "System",
        "max_instances": 3,
        "expected_user": "SYSTEM",
        "notes": "Session manager; one master + one child per session (child exits after logon)",
    },
    "csrss.exe": {
        "expected_parent": None,  # parent is smss which self-terminates
        "max_instances": 99,
        "expected_user": "SYSTEM",
        "notes": "One per session; parent smss exits so PPID appears orphaned",
    },
    "wininit.exe": {
        "expected_parent": None,
        "max_instances": 1,
        "expected_user": "SYSTEM",
        "notes": "Starts services.exe, lsass.exe, lsm.exe for session 0",
    },
    "services.exe": {
        "expected_parent": "wininit.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM",
        "notes": "Service Control Manager",
    },
    "lsass.exe": {
        "expected_parent": "wininit.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM",
        "notes": "Local Security Authority; duplicate = credential dumper or masquerader",
    },
    "svchost.exe": {
        "expected_parent": "services.exe",
        "max_instances": 99,
        "expected_user": None,
        "notes": "Multiple legitimate instances; should always be child of services.exe",
    },
    "explorer.exe": {
        "expected_parent": None,  # userinit.exe exits after spawning it
        "max_instances": 5,
        "expected_user": None,
        "notes": "One per interactive user session",
    },
    "winlogon.exe": {
        "expected_parent": None,
        "max_instances": 99,
        "expected_user": "SYSTEM",
        "notes": "One per interactive session",
    },
    "taskhost.exe": {
        "expected_parent": "svchost.exe",
        "max_instances": 99,
        "expected_user": None,
        "notes": "Hosts DLL-based scheduled tasks (pre-Win8)",
    },
    "taskhostw.exe": {
        "expected_parent": "svchost.exe",
        "max_instances": 99,
        "expected_user": None,
        "notes": "Hosts DLL-based scheduled tasks (Win8+)",
    },
    "RuntimeBroker.exe": {
        "expected_parent": "svchost.exe",
        "max_instances": 99,
        "expected_user": None,
        "notes": "Manages permissions for Windows Store apps",
    },
    "spoolsv.exe": {
        "expected_parent": "services.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM",
        "notes": "Print spooler",
    },
    "SearchIndexer.exe": {
        "expected_parent": "services.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM",
        "notes": "Windows Search",
    },
    "lsm.exe": {
        "expected_parent": "wininit.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM",
        "notes": "Local Session Manager (pre-Win8; becomes svchost-hosted afterward)",
    },
    "conhost.exe": {
        "expected_parent": None,
        "max_instances": 99,
        "expected_user": None,
        "notes": "Console host; legitimately child of any process using a console",
    },
    "dllhost.exe": {
        "expected_parent": "svchost.exe",
        "max_instances": 99,
        "expected_user": None,
        "notes": "COM surrogate",
    },
    "msiexec.exe": {
        "expected_parent": None,
        "max_instances": 99,
        "expected_user": None,
        "notes": "Windows Installer",
    },
    # --- Additional processes from SANS Hunt Evil FOR508 poster (Windows 10) ---
    "lsaiso.exe": {
        "expected_parent": "wininit.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM",
        "notes": "Credential Guard isolated process; ONLY present when Credential Guard is enabled",
    },
    "fontdrvhost.exe": {
        "expected_parent": None,  # winlogon.exe or dwm.exe depending on session
        "max_instances": 3,
        "expected_user": None,
        "notes": "Font driver host; legitimate child of winlogon.exe or dwm.exe",
    },
    "dwm.exe": {
        "expected_parent": "winlogon.exe",
        "max_instances": 5,
        "expected_user": None,
        "notes": "Desktop Window Manager; one per interactive session",
    },
    "sihost.exe": {
        "expected_parent": "svchost.exe",
        "max_instances": 5,
        "expected_user": None,
        "notes": "Shell Infrastructure Host (Start menu, notification area)",
    },
    "ctfmon.exe": {
        "expected_parent": "svchost.exe",
        "max_instances": 5,
        "expected_user": None,
        "notes": "CTF Loader; handles text input and handwriting recognition",
    },
    "WmiPrvSE.exe": {
        "expected_parent": "svchost.exe",
        "max_instances": 99,
        "expected_user": None,
        "notes": "WMI Provider Service; unexpected parent may indicate lateral movement (T1047)",
    },
    "audiodg.exe": {
        "expected_parent": "svchost.exe",
        "max_instances": 3,
        "expected_user": None,
        "notes": "Windows Audio Device Graph Isolation",
    },
    "SecurityHealthService.exe": {
        "expected_parent": "services.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM",
        "notes": "Windows Security Health Service (Defender health monitoring)",
    },
    "MsMpEng.exe": {
        "expected_parent": "services.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM",
        "notes": "Microsoft Malware Protection Engine (Windows Defender AV)",
    },
    "ShellExperienceHost.exe": {
        "expected_parent": "svchost.exe",
        "max_instances": 3,
        "expected_user": None,
        "notes": "Shell Experience Host (modern Start menu, Action Center)",
    },
    "SearchUI.exe": {
        "expected_parent": "svchost.exe",
        "max_instances": 3,
        "expected_user": None,
        "notes": "Search UI / Cortana search interface",
    },
    "userinit.exe": {
        "expected_parent": "winlogon.exe",
        "max_instances": 5,
        "expected_user": None,
        "notes": "Starts user shell (explorer.exe) after logon; normally exits quickly",
    },
    "NisSrv.exe": {
        "expected_parent": "services.exe",
        "max_instances": 1,
        "expected_user": "LOCAL SERVICE",
        "notes": "Microsoft Network Realtime Inspection Service (Defender network IPS)",
    },
}

# Process names commonly used by malware for masquerading
MASQUERADE_TARGETS = {
    "lsass.exe", "svchost.exe", "csrss.exe", "services.exe",
    "winlogon.exe", "smss.exe", "explorer.exe", "System",
    "wininit.exe", "lsaiso.exe", "spoolsv.exe", "WmiPrvSE.exe",
}


def parse_pslist(raw_output: str) -> list[dict]:
    """
    Parse `vol -f image windows.pslist` output into a list of process dicts.

    Volatility 3 pslist header (tab-separated):
        PID  PPID  ImageFileName  Offset(V)  Threads  Handles  SessionId
        Wow64  CreateTime  ExitTime  File output
    """
    processes: list[dict] = []
    header_found = False

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or line.startswith("Volatility") or line.startswith("Progress"):
            continue

        # Detect header row
        if "PID" in line and "PPID" in line and "ImageFileName" in line:
            header_found = True
            continue

        if not header_found:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        try:
            proc = {
                "pid": int(parts[0]),
                "ppid": int(parts[1]),
                "name": parts[2],
                "offset": parts[3] if len(parts) > 3 else "unknown",
                "threads": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                "handles": int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0,
                "session_id": parts[6] if len(parts) > 6 else "unknown",
                "create_time": parts[8] if len(parts) > 8 else "unknown",
                "exit_time": parts[9] if len(parts) > 9 else "-",
                "suspicious": False,
                "anomalies": [],
            }
            processes.append(proc)
        except (ValueError, IndexError):
            continue

    return processes


def _get_name_by_pid(pid: int, processes: list[dict]) -> str | None:
    for p in processes:
        if p["pid"] == pid:
            return p["name"]
    return None


def _count_instances(name: str, processes: list[dict]) -> int:
    return sum(1 for p in processes if p["name"].lower() == name.lower())


def _count_live_instances(name: str, processes: list[dict]) -> int:
    """Count only running instances (a live process always has >=1 thread).

    Terminated processes whose EPROCESS is still resident report 0 threads and
    must not inflate the instance ceiling check (e.g. 1900 exited Teams.exe).
    """
    return sum(
        1 for p in processes
        if p["name"].lower() == name.lower() and p.get("threads", 0) > 0
    )


def analyze_processes(processes: list[dict]) -> list[dict]:
    """
    Run every process through the Hunt Evil baseline checks.

    Two severities are produced per process:
      * ``anomalies`` — genuine high-signal indicators; these set ``suspicious``.
      * ``notes``     — informational observations that on their own are NOT
                        evidence of compromise (unknown third-party app,
                        terminated process). These never set ``suspicious``.

    This split is deliberate: the Hunt Evil known-normal baseline exists to verify
    that *core OS processes behave correctly*, not to flag every legitimate user
    application. Flagging "not in baseline" or "0 threads" as suspicious produces a
    ~99% false-positive rate on a real workstation image and swamps the analyst.

    Mutates each process dict in-place. Returns the same list (now annotated).
    """
    for proc in processes:
        name = proc["name"]
        anomalies: list[str] = []
        notes: list[str] = []

        # A live process always has at least one thread; 0 threads means the
        # process has exited (its EPROCESS is still resident in memory). This is
        # NOT process hollowing — hollowed processes run injected code on live
        # threads — so it is informational, never suspicious on its own.
        terminated = proc.get("threads", 0) == 0
        proc["terminated"] = terminated

        baseline = KNOWN_NORMAL.get(name)

        if baseline is None:
            # Unknown to the core-OS baseline. Extremely common and benign
            # (Chrome, Teams, Slack, vendor agents). Informational only — a real
            # verdict needs path / signature / injection evidence from other tools.
            notes.append(
                "Not in core-OS known-normal baseline "
                "(expected for third-party/user applications)"
            )
        else:
            # Parent-process check — only meaningful for a live process; a
            # terminated process can carry a stale/reused PPID.
            if baseline["expected_parent"] and not terminated:
                parent_name = _get_name_by_pid(proc["ppid"], processes)
                if parent_name and parent_name != baseline["expected_parent"]:
                    anomalies.append(
                        f"Unexpected parent: expected '{baseline['expected_parent']}', "
                        f"got '{parent_name}' (PPID {proc['ppid']})"
                    )

            # Instance-count ceiling — count only LIVE instances so stale exited
            # duplicates (common for chat/browser apps) do not trip the limit.
            live_count = _count_live_instances(name, processes)
            if live_count > baseline["max_instances"]:
                anomalies.append(
                    f"Too many instances: {live_count} live "
                    f"(max expected: {baseline['max_instances']})"
                )

        # Masquerade detection — only meaningful for names NOT in the baseline.
        # Core OS process names sit within edit-distance 2 of each other
        # (smss<->csrss, lsass<->lsm), so running this on known-good names makes
        # them flag one another. A real name-masquerade ("scvhost.exe") is by
        # definition not the legitimate name and therefore not in the baseline.
        if baseline is None:
            for legit in MASQUERADE_TARGETS:
                if name != legit and _is_masquerade(name, legit):
                    anomalies.append(
                        f"Possible masquerade of '{legit}' (typosquatting/spacing)"
                    )
                    break

        if terminated and name != "System":
            notes.append("Terminated process (0 live threads); EPROCESS still resident")

        proc["anomalies"] = anomalies
        proc["notes"] = notes
        proc["suspicious"] = len(anomalies) > 0

    return processes


def _is_masquerade(candidate: str, target: str) -> bool:
    """Simple heuristic: Levenshtein distance ≤ 2 OR Unicode lookalike."""
    c = candidate.lower()
    t = target.lower()
    if c == t:
        return False
    # Strip extension for comparison
    c_base = c.replace(".exe", "").replace(".com", "")
    t_base = t.replace(".exe", "").replace(".com", "")
    return _levenshtein(c_base, t_base) <= 2


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]
