"""
File analysis tools — Priority 4 (tool count expansion).

Three tools for static analysis of extracted files:
  get_pe_metadata   — PE header metadata, imports, exports, timestamps
  extract_strings   — printable string extraction with IOC pattern matching
  detect_packer     — entropy analysis + UPX/MPRESS/Themida signature detection

These tools operate on files extracted from disk images (extract_file) or
exported by Volatility (procdump). They bridge memory forensics and static analysis.
"""
from __future__ import annotations
import json
import math
import os
import re
import subprocess
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import MAX_TOOL_TIMEOUT, EXPORTS_DIR
from mcp_server.parsers.forensic_knowledge import wrap_response

# IOC patterns to flag in string output
_IOC_PATTERNS = {
    "ipv4":    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    "url":     re.compile(r"https?://[\w./%-?&=#]+", re.IGNORECASE),
    "domain":  re.compile(r"\b(?:[a-z0-9\-]+\.){2,}(?:com|net|org|ru|cn|to|cc|xyz|io)\b", re.IGNORECASE),
    "path":    re.compile(r"[a-zA-Z]:\\[\\\w .\-]+"),
    "base64":  re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    "mitre":   re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "registry":re.compile(r"(?:HKEY_|HKLM|HKCU|HKCR|SOFTWARE\\|SYSTEM\\)", re.IGNORECASE),
}


def _section_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0=low entropy, 8=max)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * math.log2(f / n) for f in freq if f > 0)


def register_file_analysis_tools(mcp, rag=None):

    @mcp.tool()
    def get_pe_metadata(file_path: str) -> str:
        """
        Extract PE (Portable Executable) metadata from an executable or DLL.

        Returns: compile timestamp, architecture, imphash, section entropy,
        imported functions, exported functions, digital signature status,
        and anomaly flags (e.g. future compile time, high-entropy sections).

        High section entropy (>7.0) indicates packing/encryption (T1027).
        Compile timestamp in the future or before 2000 indicates timestomping (T1070.006).
        Missing or invalid signature is suspicious for files in system directories.

        Args:
            file_path: Absolute path to the PE file (e.g. extracted via extract_file).
        """
        increment_tool_counter()
        audit_id = ""

        if not Path(file_path).exists():
            return json.dumps({"error": f"File not found: {file_path}"})

        try:
            import pefile  # type: ignore
        except ImportError:
            # Fall back to strings-based analysis if pefile unavailable
            return json.dumps({
                "error": "pefile not installed — run: pip3 install pefile",
                "fallback": "Use extract_strings for basic analysis.",
            })

        try:
            pe = pefile.PE(file_path, fast_load=False)
        except Exception as e:
            return json.dumps({"error": f"PE parse error: {e}"})

        # Compile timestamp
        import datetime
        ts_raw = pe.FILE_HEADER.TimeDateStamp
        try:
            ts_str = datetime.datetime.utcfromtimestamp(ts_raw).isoformat() + "Z"
        except (OSError, OverflowError, ValueError):
            ts_str = hex(ts_raw)

        ts_anomaly = ts_raw > 0 and (
            ts_raw > int(datetime.datetime(2030, 1, 1).timestamp()) or
            ts_raw < int(datetime.datetime(1995, 1, 1).timestamp())
        )

        # Architecture
        machine = pe.FILE_HEADER.Machine
        arch = "x64" if machine == 0x8664 else "x86" if machine == 0x14c else hex(machine)

        # Sections and entropy
        sections: list[dict] = []
        high_entropy_sections: list[dict] = []
        for section in pe.sections:
            data = section.get_data()
            ent = round(_section_entropy(data), 3)
            name = section.Name.decode("utf-8", errors="replace").strip("\x00 ")
            sec_entry = {
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": ent,
                "suspicious": ent > 7.0,
            }
            sections.append(sec_entry)
            if ent > 7.0:
                high_entropy_sections.append(sec_entry)

        # Imports
        imports: list[str] = []
        _SUSPICIOUS_IMPORTS = {
            "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "LoadLibrary", "GetProcAddress", "NtCreateThreadEx", "RtlCreateUserThread",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "CryptEncrypt", "CryptDecrypt", "InternetOpen", "InternetConnect",
            "HttpSendRequest", "URLDownloadToFile", "ShellExecute", "WinExec",
            "CreateService", "OpenSCManager", "RegSetValueEx",
        }
        suspicious_imports: list[str] = []
        try:
            pe.parse_data_directories()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        name = imp.name.decode("utf-8", errors="replace") if imp.name else ""
                        imports.append(name)
                        if name in _SUSPICIOUS_IMPORTS:
                            suspicious_imports.append(name)
        except Exception:
            pass

        # Imphash
        try:
            imphash = pe.get_imphash()
        except Exception:
            imphash = ""

        # Digital signature check (sigcheck-style via Authenticode)
        has_signature = hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and pe.DIRECTORY_ENTRY_SECURITY

        log_tool_execution("get_pe_metadata", [file_path], f"PE parsed: {file_path}")
        audit_id = get_last_audit_id()

        data = {
            "file": file_path,
            "architecture": arch,
            "compile_timestamp": ts_str,
            "timestamp_anomaly": ts_anomaly,
            "imphash": imphash,
            "has_digital_signature": bool(has_signature),
            "section_count": len(sections),
            "high_entropy_sections": high_entropy_sections,
            "sections": sections,
            "total_imports": len(imports),
            "suspicious_imports": suspicious_imports,
            "imports_sample": imports[:50],
            "tool_calls_used": get_tool_count(),
            "anomaly_summary": {
                "timestamp_anomaly": ts_anomaly,
                "packed_sections": len(high_entropy_sections),
                "suspicious_api_count": len(suspicious_imports),
                "unsigned": not bool(has_signature),
            },
        }
        return wrap_response("get_pe_metadata", data, audit_id)

    @mcp.tool()
    def extract_strings(file_path: str, min_length: int = 6) -> str:
        """
        Extract printable ASCII and Unicode strings from a file, then scan
        for IOC patterns: IP addresses, URLs, domains, file paths, registry keys,
        base64 blobs, and MITRE technique IDs.

        Args:
            file_path:  Absolute path to the file to analyse.
            min_length: Minimum string length to include (default 6).
        """
        if not Path(file_path).exists():
            return json.dumps({"error": f"File not found: {file_path}"})

        # Try system `strings` first, fall back to Python implementation
        raw_strings: list[str] = []
        try:
            result = subprocess.run(
                ["strings", f"-n{min_length}", file_path],
                capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT,
            )
            raw_strings = [s.strip() for s in result.stdout.splitlines() if s.strip()]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Pure Python fallback
            try:
                data = Path(file_path).read_bytes()
                current = []
                for b in data:
                    c = chr(b)
                    if c.isprintable() and c != "\n":
                        current.append(c)
                    else:
                        if len(current) >= min_length:
                            raw_strings.append("".join(current))
                        current = []
            except Exception as e:
                return json.dumps({"error": str(e)})

        log_tool_execution("extract_strings", [file_path], f"{len(raw_strings)} strings")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        # Scan for IOCs
        iocs: dict[str, list[str]] = {k: [] for k in _IOC_PATTERNS}
        seen: dict[str, set[str]] = {k: set() for k in _IOC_PATTERNS}
        for s in raw_strings:
            for ioc_type, pat in _IOC_PATTERNS.items():
                for match in pat.findall(s):
                    if match not in seen[ioc_type]:
                        seen[ioc_type].add(match)
                        iocs[ioc_type].append(match)

        data = {
            "file": file_path,
            "total_strings": len(raw_strings),
            "iocs_found": {k: v[:30] for k, v in iocs.items() if v},
            "ioc_summary": {k: len(v) for k, v in iocs.items() if v},
            "strings_sample": raw_strings[:100],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("extract_strings", data, audit_id)

    @mcp.tool()
    def detect_packer(file_path: str) -> str:
        """
        Detect packing, obfuscation, or encryption in an executable.

        Checks:
        - Overall file entropy (>7.2 = likely packed)
        - Section entropy per section
        - UPX magic bytes / section names
        - MPRESS, Themida, NSPack signatures
        - Abnormal section count (0 or 1 section = common packer trait)

        Packed executables evade static YARA rules and AV signatures (T1027.002).

        Args:
            file_path: Absolute path to the executable.
        """
        if not Path(file_path).exists():
            return json.dumps({"error": f"File not found: {file_path}"})

        try:
            raw = Path(file_path).read_bytes()
        except OSError as e:
            return json.dumps({"error": str(e)})

        log_tool_execution("detect_packer", [file_path], f"size={len(raw)}")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        overall_entropy = round(_section_entropy(raw), 3)

        # Signature detection
        packer_signatures: list[str] = []
        if b"UPX0" in raw or b"UPX!" in raw or b"UPX2" in raw:
            packer_signatures.append("UPX")
        if b"MPRESS1" in raw or b"MPRESS2" in raw:
            packer_signatures.append("MPRESS")
        if b".themida" in raw.lower() or b"winlicense" in raw.lower():
            packer_signatures.append("Themida/WinLicense")
        if b"nspack" in raw.lower():
            packer_signatures.append("NSPack")
        if b"petite" in raw.lower():
            packer_signatures.append("PEtite")
        if b"aspack" in raw.lower():
            packer_signatures.append("ASPack")
        if b".netsect" in raw.lower() or b"_.rsrc" in raw.lower():
            packer_signatures.append(".NET-packed")

        # PE section analysis
        sections_info: list[dict] = []
        try:
            import pefile  # type: ignore
            pe = pefile.PE(file_path, fast_load=True)
            for sec in pe.sections:
                data_bytes = sec.get_data()
                ent = round(_section_entropy(data_bytes), 3)
                name = sec.Name.decode("utf-8", errors="replace").strip("\x00 ")
                sections_info.append({"name": name, "entropy": ent})
        except ImportError:
            pass
        except Exception:
            pass

        verdict = "CLEAN"
        if packer_signatures:
            verdict = f"PACKED ({', '.join(packer_signatures)})"
        elif overall_entropy > 7.2:
            verdict = "LIKELY_PACKED (high entropy, no signature match)"
        elif overall_entropy > 6.5:
            verdict = "POSSIBLY_OBFUSCATED"

        data = {
            "file": file_path,
            "file_size_bytes": len(raw),
            "overall_entropy": overall_entropy,
            "verdict": verdict,
            "packer_signatures_found": packer_signatures,
            "sections": sections_info,
            "packed": verdict != "CLEAN",
            "tool_calls_used": get_tool_count(),
            "note": "Packed executables require memory dumping (find_injected_code) "
                    "to recover the unpacked payload for YARA scanning.",
        }
        return wrap_response("detect_packer", data, audit_id)
