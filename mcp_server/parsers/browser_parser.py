"""
Browser artifact middleware parser.

Converts raw browser SQLite rows into structured, classified findings.
All classification logic lives here — tool functions stay thin.
"""
from __future__ import annotations
import re

# Cloud storage / exfiltration surface domains
_CLOUD_EXFIL_DOMAINS = re.compile(
    r"(dropbox\.com|onedrive\.live\.com|drive\.google\.com|docs\.google\.com"
    r"|icloud\.com|box\.com|mega\.nz|wetransfer\.com|sendspace\.com|paste\.ee"
    r"|sharepoint\.com|my\.sharepoint\.com|1drv\.ms|sharefile\.com"
    r"|pastebin\.com|filebin\.net|gofile\.io|upload\.ee)",
    re.IGNORECASE,
)

# Known C2 / malware-related domain patterns
_C2_PATTERNS = re.compile(
    r"(\.ru/|\.cn/|\.tk/|\.ml/|\.ga/|\.cf/|\.pw/)"
    r"|(ngrok\.io|serveo\.net|pagekite\.me|localtunnel)"
    r"|(raw\.githubusercontent\.com.*\.ps1|pastebin\.com/raw)",
    re.IGNORECASE,
)

# Suspicious file download extensions in URLs
_SUSP_DOWNLOAD_EXTS = re.compile(
    r"\.(exe|dll|bat|ps1|vbs|js|hta|cmd|scr|msi|jar|iso|img|msp|cab)\b",
    re.IGNORECASE,
)

# URL shorteners that mask destinations
_URL_SHORTENERS = re.compile(
    r"(bit\.ly|t\.co|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|shorte\.st)",
    re.IGNORECASE,
)


def classify_url(url: str) -> list[str]:
    """
    Return a list of threat flags for a browser URL.
    Empty list = benign/unknown.
    """
    flags: list[str] = []
    if _CLOUD_EXFIL_DOMAINS.search(url):
        flags.append("CLOUD_EXFIL_DOMAIN")
    if _C2_PATTERNS.search(url):
        flags.append("C2_PATTERN")
    if _SUSP_DOWNLOAD_EXTS.search(url):
        flags.append("SUSPICIOUS_DOWNLOAD")
    if _URL_SHORTENERS.search(url):
        flags.append("URL_SHORTENER")
    return flags


def classify_chrome_rows(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Classify Chrome/Firefox history rows.

    Returns: (all_rows, suspicious_rows) — suspicious rows have 'threat_flags' added.
    """
    suspicious: list[dict] = []
    for row in rows:
        url = str(row.get("url", ""))
        flags = classify_url(url)
        if flags:
            row["threat_flags"] = flags
            row["mitre"] = _flags_to_mitre(flags)
            suspicious.append(row)
    return rows, suspicious


def classify_downloads(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Classify browser download rows. Returns (all_downloads, suspicious_downloads).
    """
    suspicious: list[dict] = []
    for row in rows:
        target = str(row.get("target_path", row.get("url", "")))
        flags = []
        if _SUSP_DOWNLOAD_EXTS.search(target):
            flags.append("EXECUTABLE_DOWNLOADED")
        if _CLOUD_EXFIL_DOMAINS.search(str(row.get("url", ""))):
            flags.append("CLOUD_EXFIL_DOMAIN")
        if flags:
            row["threat_flags"] = flags
            row["mitre"] = _flags_to_mitre(flags)
            suspicious.append(row)
    return rows, suspicious


def _flags_to_mitre(flags: list[str]) -> str:
    mapping = {
        "CLOUD_EXFIL_DOMAIN": "T1567.002 — Exfiltration to Cloud Storage",
        "C2_PATTERN": "T1071.001 — Web Protocols C2",
        "SUSPICIOUS_DOWNLOAD": "T1105 — Ingress Tool Transfer",
        "URL_SHORTENER": "T1036 — Masquerading via URL Shortener",
        "EXECUTABLE_DOWNLOADED": "T1105 — Ingress Tool Transfer",
    }
    techniques = list(dict.fromkeys(mapping[f] for f in flags if f in mapping))
    return "; ".join(techniques)


def build_browser_summary(all_visits: list[dict], suspicious: list[dict]) -> dict:
    """
    Build a structured summary dict from classified browser history data.
    """
    cloud_visits = [v for v in suspicious if "CLOUD_EXFIL_DOMAIN" in v.get("threat_flags", [])]
    download_hits = [v for v in suspicious if "SUSPICIOUS_DOWNLOAD" in v.get("threat_flags", [])]
    c2_hits = [v for v in suspicious if "C2_PATTERN" in v.get("threat_flags", [])]

    return {
        "total_visits": len(all_visits),
        "suspicious_count": len(suspicious),
        "cloud_exfil_visits": len(cloud_visits),
        "suspicious_downloads": len(download_hits),
        "c2_pattern_visits": len(c2_hits),
        "suspicious_visits": suspicious[:100],
        "mitre": (
            "T1567.002 — Exfiltration to Cloud Storage" if cloud_visits else
            "T1105 — Ingress Tool Transfer" if download_hits else ""
        ),
    }
