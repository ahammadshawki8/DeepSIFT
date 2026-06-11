"""
Cloud storage artifact middleware parser.

Converts raw cloud client log/DB rows into structured exfiltration findings.
"""
from __future__ import annotations
import re

# Extensions strongly associated with data exfiltration
_SENSITIVE_EXTS = {
    ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    ".pdf", ".csv", ".sql", ".mdb", ".accdb",
    ".zip", ".7z", ".tar", ".gz", ".rar",
    ".kdbx", ".pfx", ".p12", ".pem", ".key",
    ".db", ".sqlite", ".bak", ".dump",
    ".pst", ".ost", ".eml",
    ".dwg", ".dxf",  # CAD files
}

# File name patterns suggesting sensitive data
_SENSITIVE_FILENAME_RE = re.compile(
    r"(password|passwd|cred|secret|token|api[_\-]?key|private[_\-]?key"
    r"|financial|salary|payroll|budget|quarterly|annual.?report"
    r"|source.?code|backup|dump|export|database|confidential|proprietary)",
    re.IGNORECASE,
)

# Byte threshold for considering a sync event a large-volume transfer
_LARGE_TRANSFER_BYTES = 50 * 1024 * 1024  # 50 MB


def classify_sync_event(event: dict) -> list[str]:
    """
    Classify a single sync event dict.

    Looks at: filename, file_size, direction (upload/download), path.
    Returns list of threat flags.
    """
    flags: list[str] = []
    fname = str(event.get("filename", event.get("file_name", event.get("path", "")))).lower()
    size = int(event.get("file_size", event.get("size", 0)) or 0)
    direction = str(event.get("direction", event.get("event_type", ""))).lower()

    ext = "." + fname.rsplit(".", 1)[-1] if "." in fname else ""
    if ext in _SENSITIVE_EXTS:
        flags.append("SENSITIVE_FILE_TYPE")
    if _SENSITIVE_FILENAME_RE.search(fname):
        flags.append("SENSITIVE_FILENAME")
    if size > _LARGE_TRANSFER_BYTES:
        flags.append("LARGE_VOLUME_TRANSFER")
    if "upload" in direction or "added" in direction or "modified" in direction:
        flags.append("OUTBOUND_SYNC")

    return flags


def classify_sync_events(events: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Classify a list of cloud sync events.

    Returns: (all_events, suspicious_events)
    """
    suspicious: list[dict] = []
    for event in events:
        flags = classify_sync_event(event)
        if flags:
            event["threat_flags"] = flags
            event["mitre"] = _flags_to_mitre(flags)
            suspicious.append(event)
    return events, suspicious


def _flags_to_mitre(flags: list[str]) -> str:
    parts: list[str] = []
    if any(f in flags for f in ["SENSITIVE_FILE_TYPE", "SENSITIVE_FILENAME", "LARGE_VOLUME_TRANSFER"]):
        parts.append("T1567.002 — Exfiltration to Cloud Storage")
    if "OUTBOUND_SYNC" in flags:
        parts.append("T1048 — Exfiltration Over Alternative Protocol")
    return "; ".join(parts)


def build_cloud_summary(provider: str, all_events: list[dict], suspicious: list[dict]) -> dict:
    """
    Build a structured exfiltration risk summary for a cloud provider artifact.
    """
    sensitive_files = [e for e in suspicious if "SENSITIVE_FILE_TYPE" in e.get("threat_flags", []) or
                       "SENSITIVE_FILENAME" in e.get("threat_flags", [])]
    large_transfers = [e for e in suspicious if "LARGE_VOLUME_TRANSFER" in e.get("threat_flags", [])]
    total_bytes = sum(int(e.get("file_size", e.get("size", 0)) or 0) for e in suspicious)

    risk = "HIGH" if (sensitive_files and large_transfers) else "MEDIUM" if suspicious else "LOW"

    return {
        "provider": provider,
        "total_events": len(all_events),
        "suspicious_event_count": len(suspicious),
        "sensitive_file_count": len(sensitive_files),
        "large_transfer_count": len(large_transfers),
        "estimated_suspicious_bytes": total_bytes,
        "exfiltration_risk": risk,
        "suspicious_events": suspicious[:100],
        "mitre": "T1567.002 — Exfiltration to Cloud Storage" if suspicious else "",
    }
