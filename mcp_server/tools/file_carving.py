"""
File carving and advanced static analysis tools.

Tools:
  run_bulk_extractor    — bulk_extractor: emails, URLs, CCNs, phone numbers, JSON
  carve_files_foremost  — foremost: file carving from raw image/partition
  carve_files_scalpel   — scalpel: header/footer based carving
  analyze_with_exiftool — exiftool: metadata extraction from any file type
  calculate_file_hashes — SHA256/MD5/SHA1 + ssdeep fuzzy hash
  detect_capabilities   — capa: malware capability detection (MITRE ATT&CK mapped)
  extract_floss_strings — FLOSS: decode obfuscated strings from executables
  get_file_type         — file + magic bytes: determine true file type
"""
from __future__ import annotations
import hashlib
import json
import re
import subprocess
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import MAX_TOOL_TIMEOUT, EXPORTS_DIR
from mcp_server.parsers.forensic_knowledge import wrap_response


def register_file_carving_tools(mcp, rag=None):

    @mcp.tool()
    def run_bulk_extractor(image_path: str, output_dir: str = "") -> str:
        """
        Run bulk_extractor to extract features from a disk image or file.

        bulk_extractor scans for: email addresses, URLs, credit card numbers,
        phone numbers, GPS coordinates, ZIP contents, JSON structures, Base64 blobs,
        and domain names — without mounting the image or parsing the file system.

        Works even on corrupted file systems and encrypted volumes (finds plaintext leakage).

        Args:
            image_path: Absolute path to disk image, memory image, or any file.
            output_dir: Directory for bulk_extractor output (default: exports/bulk/).
        """
        increment_tool_counter()
        if not Path(image_path).exists():
            return json.dumps({"error": f"Image not found: {image_path}"})

        out_dir = Path(output_dir) if output_dir else EXPORTS_DIR / "bulk_extractor"
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = ["bulk_extractor", "-o", str(out_dir), image_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT * 4)
            log_tool_execution("run_bulk_extractor", cmd, result.stdout, error=result.stderr)
        except FileNotFoundError:
            return json.dumps({"error": "bulk_extractor not found. Install: sudo apt install bulk-extractor"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "bulk_extractor timed out (large image)"})

        audit_id = get_last_audit_id()

        # Summarise output files
        output_summary: dict[str, int] = {}
        iocs: dict[str, list[str]] = {}
        for out_file in sorted(out_dir.glob("*.txt")):
            lines = [l.strip() for l in out_file.read_text(encoding="utf-8", errors="replace").splitlines()
                     if l.strip() and not l.startswith("#")]
            output_summary[out_file.name] = len(lines)
            if lines:
                iocs[out_file.stem] = lines[:50]

        data = {
            "image_path": image_path,
            "output_dir": str(out_dir),
            "feature_file_summary": output_summary,
            "top_iocs": {k: v[:20] for k, v in iocs.items()},
            "emails": iocs.get("email", [])[:50],
            "urls": iocs.get("url", [])[:50],
            "domains": iocs.get("domain", [])[:50],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("run_bulk_extractor", data, audit_id)

    @mcp.tool()
    def carve_files_foremost(image_path: str, output_dir: str = "", file_types: str = "") -> str:
        """
        Carve deleted files from a disk image using foremost.

        foremost recovers files based on file header/footer signatures regardless
        of the file system. Recovers: JPEG, PNG, GIF, BMP, AVI, WAV, RIFF, WMV,
        OLE, ZIP, PDF, HTML, EXE, DLL, and more from unallocated space.

        Args:
            image_path: Path to disk image or partition raw data.
            output_dir: Directory for carved files (default: exports/foremost/).
            file_types: Comma-separated file types to carve (e.g. 'jpg,pdf,exe').
                        Leave empty for all supported types.
        """
        increment_tool_counter()
        if not Path(image_path).exists():
            return json.dumps({"error": f"Image not found: {image_path}"})

        out_dir = Path(output_dir) if output_dir else EXPORTS_DIR / "foremost"
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = ["foremost", "-o", str(out_dir), "-i", image_path]
        if file_types:
            cmd += ["-t", file_types]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT * 3)
            log_tool_execution("carve_files_foremost", cmd, result.stdout, error=result.stderr)
        except FileNotFoundError:
            return json.dumps({"error": "foremost not found. Install: sudo apt install foremost"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "foremost timed out"})

        audit_id = get_last_audit_id()

        # Read audit.txt summary
        audit_file = out_dir / "audit.txt"
        audit_text = audit_file.read_text(encoding="utf-8", errors="replace") if audit_file.exists() else ""

        # Count recovered files by type
        file_counts: dict[str, int] = {}
        for type_dir in out_dir.iterdir():
            if type_dir.is_dir():
                count = sum(1 for _ in type_dir.iterdir())
                if count:
                    file_counts[type_dir.name] = count

        data = {
            "image_path": image_path,
            "output_dir": str(out_dir),
            "recovered_files_by_type": file_counts,
            "total_recovered": sum(file_counts.values()),
            "audit_summary": audit_text[:2000],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("carve_files_foremost", data, audit_id)

    @mcp.tool()
    def carve_files_scalpel(image_path: str, config_path: str = "", output_dir: str = "") -> str:
        """
        Carve deleted files from a disk image using scalpel.

        scalpel is a faster alternative to foremost with configurable header/footer
        patterns. Particularly effective for carved Office documents, ZIP archives,
        and proprietary file formats.

        Args:
            image_path:  Path to disk image.
            config_path: Path to scalpel.conf (default: /etc/scalpel/scalpel.conf).
            output_dir:  Output directory (default: exports/scalpel/).
        """
        increment_tool_counter()
        if not Path(image_path).exists():
            return json.dumps({"error": f"Image not found: {image_path}"})

        out_dir = Path(output_dir) if output_dir else EXPORTS_DIR / "scalpel"
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = ["scalpel", "-o", str(out_dir), image_path]
        if config_path and Path(config_path).exists():
            cmd += ["-c", config_path]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT * 3)
            log_tool_execution("carve_files_scalpel", cmd, result.stdout, error=result.stderr)
        except FileNotFoundError:
            return json.dumps({"error": "scalpel not found. Install: sudo apt install scalpel"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "scalpel timed out"})

        audit_id = get_last_audit_id()

        file_counts: dict[str, int] = {}
        for type_dir in out_dir.iterdir():
            if type_dir.is_dir():
                count = sum(1 for _ in type_dir.iterdir())
                if count:
                    file_counts[type_dir.name] = count

        data = {
            "image_path": image_path,
            "output_dir": str(out_dir),
            "recovered_files_by_type": file_counts,
            "total_recovered": sum(file_counts.values()),
            "stdout": result.stdout[:1000],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("carve_files_scalpel", data, audit_id)

    @mcp.tool()
    def analyze_with_exiftool(file_path: str) -> str:
        """
        Extract metadata from any file using ExifTool.

        ExifTool reads metadata from 100+ file types: JPEG/PNG/GIF (GPS, camera model,
        software), PDF (author, creation software, modification date), Office documents
        (author, company, last modified by), executables (version info, company),
        and more.

        GPS coordinates in photos can geolocate evidence. Author fields in Office
        documents may reveal the attacker's identity or workstation name.

        Args:
            file_path: Absolute path to any file.
        """
        increment_tool_counter()
        if not Path(file_path).exists():
            return json.dumps({"error": f"File not found: {file_path}"})

        cmd = ["exiftool", "-json", "-a", "-G1", file_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            log_tool_execution("analyze_with_exiftool", cmd, result.stdout, error=result.stderr)
        except FileNotFoundError:
            return json.dumps({"error": "exiftool not found. Install: sudo apt install libimage-exiftool-perl"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "exiftool timed out"})

        audit_id = get_last_audit_id()

        metadata: list[dict] = []
        try:
            raw = json.loads(result.stdout)
            metadata = raw if isinstance(raw, list) else [raw]
        except json.JSONDecodeError:
            metadata = [{"raw": result.stdout[:2000]}]

        # Flag interesting fields
        interesting: dict = {}
        for m in metadata:
            for k, v in m.items():
                kl = k.lower()
                if any(kw in kl for kw in [
                    "author", "creator", "software", "gps", "created", "modified",
                    "company", "producer", "subject", "comment", "revision",
                    "lastmodifiedby", "lastsavedby",
                ]):
                    interesting[k] = str(v)[:200]

        data = {
            "file_path": file_path,
            "metadata_field_count": sum(len(m) for m in metadata),
            "interesting_fields": interesting,
            "full_metadata": metadata[0] if metadata else {},
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("analyze_with_exiftool", data, audit_id)

    @mcp.tool()
    def calculate_file_hashes(file_path: str) -> str:
        """
        Calculate cryptographic and fuzzy hashes for a file.

        Returns: MD5, SHA1, SHA256, SHA512, and ssdeep fuzzy hash.
        Use SHA256 or SHA1 for VirusTotal lookups (lookup_hash_reputation).
        Use ssdeep for similarity comparison to known malware samples.

        Args:
            file_path: Absolute path to the file to hash.
        """
        increment_tool_counter()
        if not Path(file_path).exists():
            return json.dumps({"error": f"File not found: {file_path}"})

        log_tool_execution("calculate_file_hashes", [file_path], "hash computation")
        audit_id = get_last_audit_id()

        raw = Path(file_path).read_bytes()
        hashes: dict = {
            "md5":    hashlib.md5(raw).hexdigest(),
            "sha1":   hashlib.sha1(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "sha512": hashlib.sha512(raw).hexdigest(),
            "file_size_bytes": len(raw),
        }

        # ssdeep fuzzy hash
        try:
            result = subprocess.run(
                ["ssdeep", "-s", file_path],
                capture_output=True, text=True, timeout=30,
            )
            lines = [l for l in result.stdout.splitlines() if "," in l]
            hashes["ssdeep"] = lines[0].split(",")[0] if lines else ""
        except FileNotFoundError:
            hashes["ssdeep"] = "ssdeep not installed (apt install ssdeep)"

        data = {
            "file_path": file_path,
            "hashes": hashes,
            "next_step": f"lookup_hash_reputation('{hashes['sha256']}') for VirusTotal check",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("calculate_file_hashes", data, audit_id)

    @mcp.tool()
    def detect_capabilities_capa(file_path: str) -> str:
        """
        Detect malware capabilities in an executable using capa.

        capa identifies: process injection, privilege escalation, network communication,
        anti-analysis techniques, persistence mechanisms, and credential access —
        each mapped to MITRE ATT&CK techniques.

        Requires: pip3 install capa  OR  download from github.com/mandiant/capa

        Args:
            file_path: Absolute path to the PE executable or shellcode.
        """
        increment_tool_counter()
        if not Path(file_path).exists():
            return json.dumps({"error": f"File not found: {file_path}"})

        cmd = ["capa", "-j", file_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT * 2)
            log_tool_execution("detect_capabilities_capa", cmd, result.stdout[:500], error=result.stderr[:200])
        except FileNotFoundError:
            return json.dumps({
                "error": "capa not found. Install: pip3 install capa",
                "note": "capa detects malware capabilities and maps them to MITRE ATT&CK.",
            })
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "capa timed out"})

        audit_id = get_last_audit_id()

        capabilities: list[dict] = []
        mitre_techniques: list[str] = []
        try:
            report = json.loads(result.stdout)
            for rule_name, rule_data in report.get("rules", {}).items():
                cap = {
                    "capability": rule_name,
                    "namespace": rule_data.get("meta", {}).get("namespace", ""),
                    "mitre_attack": rule_data.get("meta", {}).get("attack", []),
                }
                capabilities.append(cap)
                for attack in cap["mitre_attack"]:
                    if isinstance(attack, dict):
                        tid = attack.get("id", "")
                        if tid:
                            mitre_techniques.append(tid)
        except json.JSONDecodeError:
            capabilities = [{"raw": result.stdout[:2000]}]

        data = {
            "file_path": file_path,
            "capability_count": len(capabilities),
            "mitre_techniques": list(dict.fromkeys(mitre_techniques)),
            "capabilities": capabilities[:100],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("detect_capabilities_capa", data, audit_id)

    @mcp.tool()
    def extract_floss_strings(file_path: str) -> str:
        """
        Extract obfuscated and encoded strings from an executable using FLOSS
        (FireEye Labs Obfuscated String Solver).

        Unlike regular `strings`, FLOSS emulates small code sequences to decode:
        XOR-encoded strings, stack-built strings, and Base64-decoded strings —
        the techniques malware uses to evade string-based YARA/AV detection.

        Requires: pip3 install floss  (or download from github.com/mandiant/flare-floss)

        Args:
            file_path: Absolute path to the PE executable.
        """
        increment_tool_counter()
        if not Path(file_path).exists():
            return json.dumps({"error": f"File not found: {file_path}"})

        cmd = ["floss", "--json", file_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT * 2)
            log_tool_execution("extract_floss_strings", cmd, result.stdout[:500], error=result.stderr[:200])
        except FileNotFoundError:
            return json.dumps({
                "error": "floss not found. Install: pip3 install floss",
                "fallback": "Use extract_strings for basic (unobfuscated) strings.",
            })
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "FLOSS timed out"})

        audit_id = get_last_audit_id()

        decoded_strings: list[str] = []
        stack_strings: list[str] = []
        tight_strings: list[str] = []
        try:
            report = json.loads(result.stdout)
            decoded_strings = [s.get("string", "") for s in report.get("decoded_strings", [])
                               if s.get("string", "").strip()]
            stack_strings = [s.get("string", "") for s in report.get("stack_strings", [])
                             if s.get("string", "").strip()]
            tight_strings = [s.get("string", "") for s in report.get("tight_strings", [])
                             if s.get("string", "").strip()]
        except (json.JSONDecodeError, TypeError):
            # Fallback: parse text output
            for line in result.stdout.splitlines():
                if line.strip() and not line.startswith("["):
                    decoded_strings.append(line.strip())

        # Scan for IOCs in decoded strings
        import re as _re
        ioc_ips = list({m for s in decoded_strings + stack_strings for m in _re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", s)})
        ioc_urls = list({m for s in decoded_strings + stack_strings for m in _re.findall(r"https?://\S+", s)})

        data = {
            "file_path": file_path,
            "decoded_string_count": len(decoded_strings),
            "stack_string_count": len(stack_strings),
            "tight_string_count": len(tight_strings),
            "decoded_strings": decoded_strings[:200],
            "stack_strings": stack_strings[:100],
            "ioc_ips_in_decoded": ioc_ips[:30],
            "ioc_urls_in_decoded": ioc_urls[:30],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("extract_floss_strings", data, audit_id)

    @mcp.tool()
    def get_file_type(file_path: str) -> str:
        """
        Determine the true file type of a file using magic bytes.

        Compares the file's actual magic bytes against its extension to detect:
        - Masquerading: .txt file that is actually a PE executable (T1036.007)
        - Mislabeled archives: .pdf that is actually a ZIP (common in phishing)
        - Encoded payloads hidden as image files

        Args:
            file_path: Absolute path to the file.
        """
        increment_tool_counter()
        if not Path(file_path).exists():
            return json.dumps({"error": f"File not found: {file_path}"})

        log_tool_execution("get_file_type", [file_path], "magic byte check")
        audit_id = get_last_audit_id()

        file_result = ""
        mime_result = ""
        try:
            r1 = subprocess.run(["file", "-b", file_path], capture_output=True, text=True, timeout=10)
            file_result = r1.stdout.strip()
            r2 = subprocess.run(["file", "-b", "--mime-type", file_path], capture_output=True, text=True, timeout=10)
            mime_result = r2.stdout.strip()
        except FileNotFoundError:
            # Python fallback using magic bytes
            raw = Path(file_path).read_bytes()[:32]
            magic_map = {
                b"MZ": "PE executable (Windows)",
                b"\x7fELF": "ELF executable (Linux)",
                b"PK\x03\x04": "ZIP archive",
                b"%PDF": "PDF document",
                b"\xff\xd8\xff": "JPEG image",
                b"\x89PNG": "PNG image",
                b"GIF8": "GIF image",
                b"RIFF": "RIFF file (AVI/WAV)",
                b"\xd0\xcf\x11\xe0": "Microsoft Office OLE2 (legacy .doc/.xls/.ppt)",
                b"{\x5c\x72\x74\x66": "RTF document",
            }
            for sig, desc in magic_map.items():
                if raw.startswith(sig):
                    file_result = desc
                    break
            else:
                file_result = f"Unknown (first bytes: {raw[:8].hex()})"

        # Extension vs magic mismatch detection
        ext = Path(file_path).suffix.lower()
        ext_type_map = {
            ".exe": "PE", ".dll": "PE", ".txt": "ASCII", ".pdf": "PDF",
            ".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".zip": "Zip",
            ".docx": "Zip", ".xlsx": "Zip", ".pptx": "Zip",
        }
        expected = ext_type_map.get(ext, "")
        mismatch = bool(expected and expected.lower() not in file_result.lower())

        data = {
            "file_path": file_path,
            "file_extension": ext,
            "detected_type": file_result,
            "mime_type": mime_result,
            "extension_mismatch": mismatch,
            "masquerade_suspected": mismatch,
            "mitre": "T1036.007 — Masquerading: Double File Extension" if mismatch else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_file_type", data, audit_id)
