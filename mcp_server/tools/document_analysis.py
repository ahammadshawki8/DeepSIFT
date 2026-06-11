"""
Document and file analysis tools for malicious document detection.

Tools:
  analyze_pdf_doc    — pdf-parser.py: PDF object analysis, embedded JS, /OpenAction
  analyze_ole_doc    — olevba: VBA macro extraction and analysis from Office docs
  analyze_rtf_doc    — rtfobj: RTF embedded object extraction
  extract_doc_meta   — exiftool metadata + hidden author/company fields
  analyze_zip_archive — ZIP structure analysis: password-protected, nested ZIPs, suspicious entries
  detect_dde_payload — DDE field detection in Office XML files
"""
from __future__ import annotations
import json
import re
import subprocess
import zipfile
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import MAX_TOOL_TIMEOUT
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.parsers.document_parser import (
    classify_pdf, classify_vba_macro, classify_rtf_clsid, classify_dde_text, classify_zip_entry, doc_mitre_map
)
from mcp_server.parsers.rag_enrichment import enrich_findings, enrich_single, build_rag_summary
from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques


def register_document_analysis_tools(mcp, rag=None):

    @mcp.tool()
    def analyze_pdf_doc(pdf_path: str) -> str:
        """
        Analyse a PDF file for malicious content using pdf-parser.py.

        Checks for:
        - /JavaScript and /JS objects (drive-by download scripts)
        - /OpenAction and /AA (auto-run actions on open)
        - Embedded files (/EmbeddedFile) and launch actions (/Launch)
        - URI actions pointing to external URLs
        - Suspicious stream compression (FlateDecode with embedded shellcode)

        Requires: pip3 install pdfid pdfparser  (Didier Stevens tools)

        Args:
            pdf_path: Absolute path to the PDF file to analyse.
        """
        increment_tool_counter()
        if not Path(pdf_path).exists():
            return json.dumps({"error": f"PDF not found: {pdf_path}"})

        log_tool_execution("analyze_pdf_doc", [pdf_path], "PDF malware analysis")
        audit_id = get_last_audit_id()

        # Try pdfid first (quick summary)
        pdfid_result = ""
        try:
            r = subprocess.run(
                ["python3", "-m", "pdfid", pdf_path],
                capture_output=True, text=True, timeout=60,
            )
            pdfid_result = r.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if not pdfid_result:
            try:
                r = subprocess.run(
                    ["pdfid.py", pdf_path],
                    capture_output=True, text=True, timeout=60,
                )
                pdfid_result = r.stdout
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pdfid_result = "pdfid not found — install: pip3 install pdfid"

        # Parse pdfid output for suspicious keywords
        _SUSPICIOUS_KEYWORDS = [
            "/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch",
            "/EmbeddedFile", "/XFA", "/URI", "/SubmitForm", "/RichMedia",
        ]
        suspicious_keywords: dict[str, int] = {}
        for kw in _SUSPICIOUS_KEYWORDS:
            match = re.search(re.escape(kw) + r"\s+(\d+)", pdfid_result)
            if match and int(match.group(1)) > 0:
                suspicious_keywords[kw] = int(match.group(1))

        # Try pdf-parser for deep object analysis
        pdf_objects: list[str] = []
        try:
            for kw in list(suspicious_keywords.keys())[:3]:
                r2 = subprocess.run(
                    ["pdf-parser.py", "-s", kw, pdf_path],
                    capture_output=True, text=True, timeout=60,
                )
                if r2.stdout.strip():
                    pdf_objects.append(f"=== {kw} ===\n{r2.stdout[:1000]}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Middleware parser: structured PDF risk classification
        risk_level, mitre_techniques, kw_findings = classify_pdf(suspicious_keywords)
        enrich_findings(rag, kw_findings,
                        lambda f: f"PDF malicious keyword {f.get('keyword', '')} malware phishing")

        data = {
            "pdf_path": pdf_path,
            "suspicious_pdf_keywords": suspicious_keywords,
            "risk_level": risk_level,
            "mitre_techniques": mitre_techniques,
            "keyword_findings": kw_findings,
            "pdfid_summary": pdfid_result[:2000],
            "suspicious_objects": pdf_objects[:10],
            "mitre": "T1566.001 — Phishing: Spearphishing Attachment" if suspicious_keywords else "",
            "rag_context": build_rag_summary(rag, "malicious PDF JavaScript OpenAction phishing attachment exploit"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("analyze_pdf_doc", data, audit_id)

    @mcp.tool()
    def analyze_ole_doc(doc_path: str) -> str:
        """
        Extract and analyze VBA macros from Office documents using olevba.

        Detects: Auto-execute macros (AutoOpen, Document_Open, Workbook_Open),
        shell execution (Shell, WScript.Shell, CreateObject), file system access,
        network downloads (URLDownloadToFile, MSXML2.XMLHTTP), obfuscation
        (Chr(), Asc(), Base64), and known exploit patterns.

        Supports: .doc, .xls, .ppt, .docm, .xlsm, .pptm, .docx (macro-enabled).

        Requires: pip3 install oletools

        Args:
            doc_path: Absolute path to the Office document.
        """
        increment_tool_counter()
        if not Path(doc_path).exists():
            return json.dumps({"error": f"Document not found: {doc_path}"})

        cmd = ["olevba", "--json", doc_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
            log_tool_execution("analyze_ole_doc", cmd, result.stdout[:500], error=result.stderr[:200])
        except FileNotFoundError:
            return json.dumps({"error": "olevba not found. Install: pip3 install oletools"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "olevba timed out"})

        audit_id = get_last_audit_id()

        macros: list[dict] = []
        iocs: list[dict] = []
        risk_level = "LOW"

        try:
            report = json.loads(result.stdout)
            for item in report if isinstance(report, list) else [report]:
                for macro in item.get("macros", []):
                    macros.append({
                        "vba_filename": macro.get("vba_filename", ""),
                        "code_snippet": macro.get("code", "")[:1000],
                    })
                for ioc in item.get("iocs", []):
                    iocs.append(ioc)
                if item.get("analysis"):
                    for finding in item["analysis"]:
                        severity = finding.get("risk", "").upper()
                        if severity in ("HIGH", "MEDIUM"):
                            risk_level = severity
        except (json.JSONDecodeError, TypeError):
            macros = [{"raw": result.stdout[:3000]}]

        # Middleware parser: classify each macro code block
        classified_macros: list[dict] = []
        for m in macros:
            code = m.get("code_snippet", "")
            mp_risk, patterns = classify_vba_macro(code)
            m["classified_risk"] = mp_risk
            m["malicious_patterns"] = patterns
            m["mitre_techniques"] = doc_mitre_map("OLE", mp_risk, patterns)
            classified_macros.append(m)

        enrich_findings(rag, [m for m in classified_macros if m.get("classified_risk") == "HIGH"],
                        lambda m: f"malicious VBA macro AutoOpen Shell CreateObject {m.get('malicious_patterns', [])}")

        data = {
            "doc_path": doc_path,
            "macro_count": len(macros),
            "risk_level": risk_level,
            "macros": classified_macros[:20],
            "iocs": iocs[:50],
            "mitre": "T1566.001 — Phishing: Spearphishing Attachment; T1059.005 — VBA" if macros else "",
            "rag_context": build_rag_summary(rag, "VBA macro malware maldoc phishing T1059.005"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("analyze_ole_doc", data, audit_id)

    @mcp.tool()
    def analyze_rtf_doc(rtf_path: str) -> str:
        """
        Extract embedded OLE objects from RTF documents using rtfobj.

        RTF files can embed OLE objects that auto-execute when the document is
        opened. This is a common phishing payload delivery mechanism (T1566.001).
        Detects CVE-2017-11882 and similar equation editor exploits.

        Requires: pip3 install oletools

        Args:
            rtf_path: Absolute path to the RTF document.
        """
        increment_tool_counter()
        if not Path(rtf_path).exists():
            return json.dumps({"error": f"RTF not found: {rtf_path}"})

        cmd = ["rtfobj", "-j", rtf_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
            log_tool_execution("analyze_rtf_doc", cmd, result.stdout[:500], error=result.stderr[:200])
        except FileNotFoundError:
            return json.dumps({"error": "rtfobj not found. Install: pip3 install oletools"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "rtfobj timed out"})

        audit_id = get_last_audit_id()

        objects: list[dict] = []
        suspicious: list[dict] = []

        try:
            report = json.loads(result.stdout)
            if isinstance(report, list):
                objects = report
            else:
                objects = report.get("objects", [])
        except (json.JSONDecodeError, TypeError):
            objects = [{"raw": result.stdout[:2000]}]

        _SUSPICIOUS_CLSIDS = {
            "{0002CE02-0000-0000-C000-000000000046}": "Equation Editor (CVE-2017-11882)",
            "{0003000C-0000-0000-C000-000000000046}": "Packager Shell Object",
            "{00020820-0000-0000-C000-000000000046}": "Excel Chart (macro risk)",
        }

        for obj in objects:
            clsid = str(obj.get("class_name", obj.get("clsid", ""))).upper()
            for known_clsid, desc in _SUSPICIOUS_CLSIDS.items():
                if known_clsid.upper() in clsid or clsid in known_clsid.upper():
                    obj["suspicious_reason"] = desc
                    suspicious.append(obj)
                    break
            if obj.get("format_id") == "4" or "executable" in str(obj).lower():
                obj["suspicious_reason"] = "Embedded executable"
                suspicious.append(obj)

        data = {
            "rtf_path": rtf_path,
            "embedded_object_count": len(objects),
            "suspicious_objects": suspicious[:20],
            "all_objects": objects[:50],
            "mitre": "T1566.001 — Phishing Attachment; T1203 — Exploitation" if suspicious else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("analyze_rtf_doc", data, audit_id)

    @mcp.tool()
    def analyze_zip_archive(zip_path: str) -> str:
        """
        Analyse a ZIP archive structure for suspicious content.

        Detects: password protection (T1027), nested ZIPs (T1027 evasion),
        executable files masquerading as non-executables, path traversal entries
        (../../../etc/passwd), unusually large compression ratios (zip bombs),
        and suspicious file names.

        Works on any ZIP-based format: .zip, .jar, .apk, .docx, .xlsx, .pptx.

        Args:
            zip_path: Absolute path to the ZIP archive.
        """
        increment_tool_counter()
        if not Path(zip_path).exists():
            return json.dumps({"error": f"Archive not found: {zip_path}"})

        log_tool_execution("analyze_zip_archive", [zip_path], "ZIP analysis")
        audit_id = get_last_audit_id()

        entries: list[dict] = []
        suspicious: list[dict] = []
        password_protected = False
        is_encrypted = False

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                is_encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
                password_protected = is_encrypted

                for info in zf.infolist():
                    ext = Path(info.filename).suffix.lower()
                    compress_ratio = (info.file_size / info.compress_size) if info.compress_size > 0 else 0
                    entry = {
                        "filename": info.filename,
                        "compressed_size": info.compress_size,
                        "original_size": info.file_size,
                        "compression_ratio": round(compress_ratio, 1),
                        "is_encrypted": bool(info.flag_bits & 0x1),
                    }
                    entries.append(entry)

                    is_susp = False
                    reasons = []
                    if ".." in info.filename:
                        reasons.append("Path traversal attack")
                        is_susp = True
                    if ext in {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".cmd", ".scr", ".com"}:
                        reasons.append(f"Executable inside archive ({ext})")
                        is_susp = True
                    if compress_ratio > 50:
                        reasons.append(f"Zip bomb candidate (ratio {compress_ratio:.0f}x)")
                        is_susp = True
                    if info.filename.endswith(".zip"):
                        reasons.append("Nested ZIP (evasion technique)")
                        is_susp = True
                    if is_susp:
                        entry["suspicious_reasons"] = reasons
                        suspicious.append(entry)

        except zipfile.BadZipFile:
            return json.dumps({"error": "Not a valid ZIP file", "zip_path": zip_path})
        except Exception as e:
            return json.dumps({"error": str(e), "zip_path": zip_path})

        data = {
            "zip_path": zip_path,
            "total_entries": len(entries),
            "password_protected": password_protected,
            "suspicious_entries": suspicious[:50],
            "all_entries": entries[:200],
            "mitre": "T1027 — Obfuscated Files or Information" if (password_protected or suspicious) else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("analyze_zip_archive", data, audit_id)

    @mcp.tool()
    def detect_dde_payload(doc_path: str) -> str:
        """
        Detect Dynamic Data Exchange (DDE) payloads in Office Open XML documents.

        DDE allows Office documents to execute arbitrary commands without VBA macros
        by embedding DDE fields like =cmd|'/c powershell.exe ...'!A1 in cells or fields.
        This bypasses macro-security warnings (T1559.002 — DDE).

        Works on: .docx, .xlsx, .csv files (inspect XML for DDE fields).

        Args:
            doc_path: Absolute path to the Office document or CSV.
        """
        increment_tool_counter()
        if not Path(doc_path).exists():
            return json.dumps({"error": f"Document not found: {doc_path}"})

        log_tool_execution("detect_dde_payload", [doc_path], "DDE payload detection")
        audit_id = get_last_audit_id()

        dde_findings: list[dict] = []
        _DDE_PATTERNS = [
            r"=\s*cmd\|",
            r"=\s*DDEAUTO\b",
            r"=\s*DDE\b",
            r"\|'/c\s+",
            r"powershell",
            r"wscript",
            r"mshta",
            r"cscript",
        ]

        def _scan_text(text: str, source: str) -> None:
            for pat in _DDE_PATTERNS:
                for m in re.finditer(pat, text, re.IGNORECASE):
                    context = text[max(0, m.start() - 50):m.end() + 100]
                    dde_findings.append({
                        "source": source,
                        "pattern": pat,
                        "context": context[:300],
                        "mitre": "T1559.002 — Inter-Process Communication: DDE",
                    })
                    break  # One finding per pattern per source

        # Try ZIP-based OOXML extraction
        try:
            with zipfile.ZipFile(doc_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".xml") or name.endswith(".rels"):
                        try:
                            content = zf.read(name).decode("utf-8", errors="replace")
                            _scan_text(content, name)
                        except Exception:
                            pass
        except zipfile.BadZipFile:
            # Plain text / CSV / older binary format
            try:
                content = Path(doc_path).read_text(encoding="utf-8", errors="replace")
                _scan_text(content, doc_path)
            except Exception:
                pass

        # Middleware parser: use document_parser for structured DDE detection
        mp_dde = classify_dde_text(" ".join(str(f.get("context", "")) for f in dde_findings))
        dde_findings.extend(mp_dde)
        enrich_findings(rag, dde_findings,
                        lambda f: f"DDE Dynamic Data Exchange command injection {f.get('pattern', '')} T1559.002")

        data = {
            "doc_path": doc_path,
            "dde_finding_count": len(dde_findings),
            "dde_findings": dde_findings[:50],
            "risk_level": "HIGH" if dde_findings else "LOW",
            "mitre": "T1559.002 — DDE" if dde_findings else "",
            "rag_context": build_rag_summary(rag, "DDE Dynamic Data Exchange Office exploitation T1559.002"),
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("detect_dde_payload", data, audit_id)
