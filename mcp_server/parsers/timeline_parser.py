"""Parse psort/log2timeline CSV timeline output into structured event dicts."""
from __future__ import annotations
import csv
import io
from datetime import datetime

# High-interest source types for incident response
HIGH_INTEREST_SOURCES = {
    "WEBHIST", "EVT", "EVTX", "REG", "PREFETCH",
    "LNK", "RECBIN", "SETUPAPI", "SHELLBAG",
}

SUSPICIOUS_KEYWORDS = [
    "cmd.exe", "powershell", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "certutil", "bitsadmin", "wmic", "net.exe", "net1.exe",
    "mimikatz", "procdump", "psexec", "wce", "fgdump",
    "lsass", "sam ", "ntds.dit", "shadow",
    "base64", "encode", "decode", "bypass", "download",
    "invoke-", "-encodedcommand", "-enc ", "-nop",
]


def parse_timeline_csv(raw_output: str, max_events: int = 500) -> list[dict]:
    """
    Parse psort l2tcsv format output.

    l2tcsv columns:
        date, time, timezone, MACB, source, sourcetype, type,
        user, host, short, desc, version, filename, inode,
        notes, format, extra
    """
    events: list[dict] = []
    reader = csv.DictReader(io.StringIO(raw_output))

    for row in reader:
        if len(events) >= max_events:
            break
        try:
            event = {
                "datetime": f"{row.get('date', '')} {row.get('time', '')}".strip(),
                "timezone": row.get("timezone", "UTC"),
                "macb": row.get("MACB", ""),
                "source": row.get("source", ""),
                "sourcetype": row.get("sourcetype", ""),
                "type": row.get("type", ""),
                "user": row.get("user", ""),
                "host": row.get("host", ""),
                "short": row.get("short", ""),
                "description": row.get("desc", ""),
                "filename": row.get("filename", ""),
                "suspicious": False,
                "suspicion_reasons": [],
            }
            _flag_event(event)
            events.append(event)
        except (KeyError, ValueError):
            continue

    return events


def _flag_event(event: dict) -> None:
    reasons: list[str] = []
    desc_lower = (event["description"] + " " + event["short"]).lower()

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in desc_lower:
            reasons.append(f"Suspicious keyword in description: '{kw}'")

    if event["source"] in HIGH_INTEREST_SOURCES:
        event["high_interest"] = True

    event["suspicion_reasons"] = reasons
    event["suspicious"] = len(reasons) > 0


def filter_by_window(events: list[dict], start: str, end: str) -> list[dict]:
    """Filter events to a time window. Dates as 'MM/DD/YYYY HH:MM:SS'."""
    try:
        fmt = "%m/%d/%Y %H:%M:%S"
        t_start = datetime.strptime(start, fmt)
        t_end = datetime.strptime(end, fmt)
    except ValueError:
        return events

    filtered = []
    for e in events:
        try:
            t = datetime.strptime(e["datetime"], fmt)
            if t_start <= t <= t_end:
                filtered.append(e)
        except ValueError:
            continue
    return filtered


def summarize_timeline(events: list[dict]) -> dict:
    """Return a summary suitable for injecting into Claude's context."""
    suspicious = [e for e in events if e.get("suspicious")]
    sources = {}
    for e in events:
        s = e.get("source", "UNKNOWN")
        sources[s] = sources.get(s, 0) + 1

    return {
        "total_events": len(events),
        "suspicious_events": len(suspicious),
        "source_breakdown": sources,
        "top_suspicious": suspicious[:20],
    }
