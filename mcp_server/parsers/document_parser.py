"""
Malicious document middleware parser.

Classifies document threat indicators across PDF, OLE/VBA, RTF, DDE, and ZIP.
"""
from __future__ import annotations
import re

# PDF keyword risk weights
_PDF_KEYWORD_RISK: dict[str, int] = {
    "/JavaScript": 40,
    "/JS":         40,
    "/OpenAction": 30,
    "/AA":         25,
    "/Launch":     35,
    "/EmbeddedFile": 20,
    "/XFA":        20,
    "/URI":        10,
    "/SubmitForm": 15,
    "/RichMedia":  15,
}

# VBA macro patterns that strongly indicate malicious behaviour
_VBA_MALICIOUS_PATTERNS = re.compile(
    r"(Shell\s*\(|WScript\.Shell|CreateObject|AutoOpen|Document_Open|Workbook_Open"
    r"|URLDownloadToFile|XMLHTTP|Chr\(\d+\)|ChrW\(\d+\)|StrReverse"
    r"|powershell|cmd\.exe|wscript\.exe|mshta\.exe|regsvr32|rundll32"
    r"|GetObject|environ\(|environ\s*\(|CreateTextFile|Write\s*#\d)",
    re.IGNORECASE,
)

# RTF CLSID indicators
_MALICIOUS_CLSIDS = {
    "0002CE02": "Equation Editor (CVE-2017-11882)",
    "0003000C": "Packager Shell Object (code execution)",
    "00020820": "Excel Chart (macro execution risk)",
    "00020821": "Excel Worksheet (macro execution risk)",
}

# DDE detection patterns
_DDE_PATTERNS = re.compile(
    r"(=\s*cmd\s*\|"
    r"|DDEAUTO\b"
    r"|DDE\s*\("
    r"|\|'/c\s+"
    r"|powershell\s*-"
    r"|wscript\.exe"
    r"|mshta\.exe)",
    re.IGNORECASE,
)

# Suspicious ZIP entry patterns
_SUSPICIOUS_ZIP_EXTS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".cmd", ".scr", ".com", ".hta"}


def classify_pdf(keyword_counts: dict[str, int]) -> tuple[str, list[str], list[dict]]:
    """
    Classify a PDF based on pdfid keyword counts.

    Returns: (risk_level, mitre_techniques, findings_list)
    """
    total_risk = sum(
        _PDF_KEYWORD_RISK.get(kw, 0) * count
        for kw, count in keyword_counts.items()
        if count > 0
    )
    risk = "HIGH" if total_risk >= 40 else "MEDIUM" if total_risk >= 20 else "LOW"
    findings = [
        {"keyword": kw, "count": count, "risk_weight": _PDF_KEYWORD_RISK.get(kw, 5)}
        for kw, count in keyword_counts.items()
        if count > 0
    ]
    mitre = []
    if "/JavaScript" in keyword_counts or "/JS" in keyword_counts:
        mitre.append("T1059.007 — JavaScript")
    if "/OpenAction" in keyword_counts or "/Launch" in keyword_counts:
        mitre.append("T1566.001 — Phishing Attachment")
    if "/EmbeddedFile" in keyword_counts:
        mitre.append("T1027 — Obfuscated Files")
    return risk, mitre, findings


def classify_vba_macro(code: str) -> tuple[str, list[str]]:
    """
    Classify a VBA macro string.

    Returns: (risk_level, matched_patterns)
    """
    patterns: list[str] = []
    for m in _VBA_MALICIOUS_PATTERNS.finditer(code):
        patterns.append(m.group(0)[:40])
    risk = "HIGH" if len(patterns) >= 2 else "MEDIUM" if patterns else "LOW"
    return risk, list(dict.fromkeys(patterns))


def classify_rtf_clsid(clsid: str) -> tuple[bool, str]:
    """
    Check a CLSID string against known malicious COM class IDs.

    Returns: (is_malicious, description)
    """
    clsid_upper = clsid.upper().replace("-", "").replace("{", "").replace("}", "")
    for prefix, desc in _MALICIOUS_CLSIDS.items():
        if prefix in clsid_upper:
            return True, desc
    return False, ""


def classify_dde_text(text: str) -> list[dict]:
    """
    Find DDE injection patterns in text.

    Returns list of finding dicts.
    """
    findings: list[dict] = []
    for m in _DDE_PATTERNS.finditer(text):
        context_start = max(0, m.start() - 40)
        findings.append({
            "pattern": m.group(0)[:60],
            "context": text[context_start:m.end() + 80][:200],
            "mitre": "T1559.002 — Dynamic Data Exchange",
        })
    return findings


def classify_zip_entry(filename: str, compress_size: int, file_size: int, is_encrypted: bool) -> list[str]:
    """
    Classify a ZIP entry for suspicious characteristics.

    Returns list of flag strings.
    """
    flags: list[str] = []
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in _SUSPICIOUS_ZIP_EXTS:
        flags.append("EXECUTABLE_IN_ARCHIVE")
    if ".." in filename or "/" in filename.lstrip("/"):
        if ".." in filename:
            flags.append("PATH_TRAVERSAL")
    if compress_size > 0 and file_size / compress_size > 50:
        flags.append("ZIP_BOMB_CANDIDATE")
    if filename.lower().endswith(".zip"):
        flags.append("NESTED_ZIP")
    if is_encrypted:
        flags.append("ENCRYPTED_ENTRY")
    return flags


def doc_mitre_map(doc_type: str, risk: str, flags: list[str]) -> list[dict]:
    """
    Map document findings to MITRE ATT&CK techniques.
    """
    from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques
    text = f"{doc_type} document {risk} risk {' '.join(flags)}"
    return map_finding_to_techniques(text)
