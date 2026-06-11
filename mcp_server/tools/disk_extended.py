"""
Extended disk forensics tools — file system, image verification, and raw analysis.

Tools:
  get_fs_statistics     — fsstat: file system metadata, cluster size, sector offsets
  get_image_info        — ewfinfo / mmls: image format details and partitions
  create_mac_timeline   — mactime: body-file based MAC(B) timeline generation
  read_raw_block        — blkcat: read raw sectors from a disk image
  analyze_slack_space   — Identify and extract file system slack space
  verify_image_integrity — Verify disk image hash integrity (MD5/SHA256 + ewfverify)
"""
from __future__ import annotations
import hashlib
import json
import subprocess
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.config import MAX_TOOL_TIMEOUT, EXPORTS_DIR
from mcp_server.parsers.forensic_knowledge import wrap_response


def register_disk_extended_tools(mcp, rag=None):

    @mcp.tool()
    def get_fs_statistics(image_path: str, offset: int = 0) -> str:
        """
        Get file system statistics from a disk image using fsstat (Sleuth Kit).

        Returns: file system type, block size, cluster size, sector size, volume
        name, creation date, last mount time, and partition offsets. This metadata
        is required before running fls/icat on specific partitions.

        Args:
            image_path: Absolute path to the disk image.
            offset:     Partition offset in sectors (from get_partition_table output).
                        Use 0 for a single-partition image.
        """
        increment_tool_counter()
        if not Path(image_path).exists():
            return json.dumps({"error": f"Image not found: {image_path}"})

        cmd = ["fsstat", "-o", str(offset), image_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
            log_tool_execution("get_fs_statistics", cmd, result.stdout, error=result.stderr)
        except FileNotFoundError:
            return json.dumps({"error": "fsstat not found. Install Sleuth Kit: sudo apt install sleuthkit"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "fsstat timed out"})

        audit_id = get_last_audit_id()

        parsed: dict = {}
        for line in result.stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                parsed[k.strip()] = v.strip()

        data = {
            "image_path": image_path,
            "offset_sectors": offset,
            "fs_type": parsed.get("File System Type", ""),
            "volume_name": parsed.get("Volume Name", ""),
            "block_size": parsed.get("Block Size", parsed.get("Cluster Size", "")),
            "sector_size": parsed.get("Sector Size", ""),
            "creation_time": parsed.get("Created", ""),
            "last_mount": parsed.get("Last Mount Time", ""),
            "full_stats": parsed,
            "raw_output": result.stdout[:3000],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_fs_statistics", data, audit_id)

    @mcp.tool()
    def get_image_info(image_path: str) -> str:
        """
        Get disk image format information using ewfinfo (for E01/EWF) or mmls (for raw).

        For E01 images: case number, examiner name, acquisition date, MD5 hash
        recorded during acquisition, and media size.

        For raw/DD images: partition table (using mmls).

        Args:
            image_path: Absolute path to the disk image (.E01, .vmdk, .raw, .img, .dd).
        """
        increment_tool_counter()
        if not Path(image_path).exists():
            return json.dumps({"error": f"Image not found: {image_path}"})

        log_tool_execution("get_image_info", [image_path], "image info")
        audit_id = get_last_audit_id()

        ext = Path(image_path).suffix.lower()
        ewf_info: dict = {}
        mmls_output = ""

        # Try ewfinfo for E01 images
        if ext in (".e01", ".ewf", ".ex01"):
            try:
                r = subprocess.run(
                    ["ewfinfo", image_path],
                    capture_output=True, text=True, timeout=60,
                )
                for line in r.stdout.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        ewf_info[k.strip()] = v.strip()
            except FileNotFoundError:
                ewf_info["note"] = "ewfinfo not found (install libewf-utils)"

        # Try mmls for partition table
        try:
            r2 = subprocess.run(
                ["mmls", image_path],
                capture_output=True, text=True, timeout=60,
            )
            mmls_output = r2.stdout[:3000]
        except FileNotFoundError:
            mmls_output = "mmls not found (install sleuthkit)"

        data = {
            "image_path": image_path,
            "image_format": ext,
            "ewf_metadata": ewf_info,
            "partition_table": mmls_output,
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("get_image_info", data, audit_id)

    @mcp.tool()
    def create_mac_timeline(body_file_path: str, output_path: str = "", start_date: str = "", end_date: str = "") -> str:
        """
        Generate a MAC(B) timeline from a Sleuth Kit body file using mactime.

        The body file is output by fls -r -m. mactime converts it into a
        chronological timeline of file system events sorted by Modified/Accessed/
        Changed/Born timestamps — the foundation of timeline analysis.

        Args:
            body_file_path: Path to the body file (output of fls -r -m).
            output_path:    Path for the mactime output (default: exports/mactime.csv).
            start_date:     Start date filter: YYYY-MM-DD (optional).
            end_date:       End date filter: YYYY-MM-DD (optional).
        """
        increment_tool_counter()
        if not Path(body_file_path).exists():
            return json.dumps({"error": f"Body file not found: {body_file_path}"})

        out_path = Path(output_path) if output_path else EXPORTS_DIR / "mactime.csv"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = ["mactime", "-b", body_file_path, "-d"]
        if start_date:
            cmd += ["-s", start_date]
        if end_date:
            cmd += ["-e", end_date]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT * 2)
            log_tool_execution("create_mac_timeline", cmd, result.stdout[:500], error=result.stderr[:200])
        except FileNotFoundError:
            return json.dumps({"error": "mactime not found. Install: sudo apt install sleuthkit"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "mactime timed out (large body file)"})

        audit_id = get_last_audit_id()

        out_path.write_text(result.stdout, encoding="utf-8")

        # Return sample rows
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        sample = lines[:50]

        data = {
            "body_file_path": body_file_path,
            "output_path": str(out_path),
            "total_timeline_entries": len(lines),
            "date_range": f"{start_date or 'all'} to {end_date or 'all'}",
            "sample_entries": sample,
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("create_mac_timeline", data, audit_id)

    @mcp.tool()
    def read_raw_block(image_path: str, block_number: int, offset: int = 0, count: int = 1) -> str:
        """
        Read raw sectors/blocks from a disk image using blkcat (Sleuth Kit).

        Use this to inspect specific sectors: boot record (block 0), MFT entries,
        deleted file content, and suspected hidden data in slack space or after
        the last partition.

        Args:
            image_path:   Absolute path to the disk image.
            block_number: Block/sector number to read.
            offset:       Partition offset in sectors.
            count:        Number of blocks to read (default: 1).
        """
        increment_tool_counter()
        if not Path(image_path).exists():
            return json.dumps({"error": f"Image not found: {image_path}"})

        cmd = ["blkcat", "-o", str(offset), image_path, str(block_number), str(count)]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            log_tool_execution("read_raw_block", cmd, f"block {block_number}", error=result.stderr.decode()[:200])
        except FileNotFoundError:
            return json.dumps({"error": "blkcat not found. Install: sudo apt install sleuthkit"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "blkcat timed out"})

        audit_id = get_last_audit_id()

        raw_bytes = result.stdout
        hex_lines: list[str] = []
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in raw_bytes[:512])

        # Hexdump first 512 bytes
        for i in range(0, min(512, len(raw_bytes)), 16):
            chunk = raw_bytes[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_lines.append(f"{i:04x}  {hex_part:<47}  {asc_part}")

        # Magic byte detection
        magic_map = {
            b"\x55\xAA": "MBR signature",
            b"MZ": "PE executable",
            b"\x7fELF": "ELF executable",
            b"FILE": "NTFS MFT record",
            b"RSTR": "NTFS log restart area",
            b"INDX": "NTFS index record",
        }
        detected = ""
        for sig, desc in magic_map.items():
            if raw_bytes[:len(sig)] == sig:
                detected = desc
                break

        data = {
            "image_path": image_path,
            "block_number": block_number,
            "offset_sectors": offset,
            "blocks_read": count,
            "bytes_read": len(raw_bytes),
            "detected_structure": detected,
            "hexdump": "\n".join(hex_lines),
            "printable_ascii": printable[:200],
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("read_raw_block", data, audit_id)

    @mcp.tool()
    def analyze_slack_space(image_path: str, offset: int = 0, output_dir: str = "") -> str:
        """
        Identify and extract file slack space from an NTFS or FAT file system image.

        Slack space is the unused area between the end of a file and the end of
        its last cluster. Malware and insiders hide data in slack space (T1027 / T1564).
        blkls -s extracts the raw slack space bytes for analysis.

        Args:
            image_path: Absolute path to the disk image.
            offset:     Partition offset in sectors (from get_partition_table).
            output_dir: Directory for slack space output (default: exports/slack/).
        """
        increment_tool_counter()
        if not Path(image_path).exists():
            return json.dumps({"error": f"Image not found: {image_path}"})

        out_dir = Path(output_dir) if output_dir else EXPORTS_DIR / "slack"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "slack_space.bin"

        cmd = ["blkls", "-o", str(offset), "-s", image_path]
        try:
            with open(str(out_file), "wb") as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=MAX_TOOL_TIMEOUT * 2)
            log_tool_execution("analyze_slack_space", cmd, f"slack written to {out_file}", error=result.stderr.decode()[:200])
        except FileNotFoundError:
            return json.dumps({"error": "blkls not found. Install: sudo apt install sleuthkit"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "blkls timed out"})

        audit_id = get_last_audit_id()

        slack_size = out_file.stat().st_size if out_file.exists() else 0

        # Search slack for strings
        strings_found: list[str] = []
        if out_file.exists():
            raw = out_file.read_bytes()
            import re as _re
            # Find printable ASCII strings >= 8 chars
            strings_found = [m.decode("ascii") for m in _re.findall(rb"[ -~]{8,}", raw)][:100]

        # Look for IOC patterns in slack strings
        import re as _re2
        ips_in_slack = list({m for s in strings_found for m in _re2.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", s)})
        urls_in_slack = list({m for s in strings_found for m in _re2.findall(r"https?://\S+", s)})

        data = {
            "image_path": image_path,
            "offset_sectors": offset,
            "slack_space_file": str(out_file),
            "slack_space_bytes": slack_size,
            "strings_found_count": len(strings_found),
            "interesting_strings": strings_found[:50],
            "ips_in_slack": ips_in_slack[:20],
            "urls_in_slack": urls_in_slack[:20],
            "mitre": "T1027 — Obfuscated Files or Information" if (ips_in_slack or urls_in_slack) else "",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("analyze_slack_space", data, audit_id)

    @mcp.tool()
    def verify_image_integrity(image_path: str, expected_md5: str = "", expected_sha256: str = "") -> str:
        """
        Verify the cryptographic integrity of a disk image.

        Computes MD5 and SHA256 of the image and compares against expected values
        recorded at acquisition time. For E01 images, also runs ewfverify.

        Chain-of-custody requires proving the image was not modified after acquisition.
        A hash mismatch means the evidence may be inadmissible.

        Args:
            image_path:      Absolute path to the disk image.
            expected_md5:    Expected MD5 hash (from acquisition report), if known.
            expected_sha256: Expected SHA256 hash, if known.
        """
        increment_tool_counter()
        if not Path(image_path).exists():
            return json.dumps({"error": f"Image not found: {image_path}"})

        log_tool_execution("verify_image_integrity", [image_path], "hash verification")
        audit_id = get_last_audit_id()

        # Stream-hash the file (may be very large)
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        size = 0
        try:
            with open(image_path, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    md5.update(chunk)
                    sha256.update(chunk)
                    size += len(chunk)
        except OSError as e:
            return json.dumps({"error": f"Failed to read image: {e}"})

        computed_md5 = md5.hexdigest()
        computed_sha256 = sha256.hexdigest()

        md5_match = (computed_md5 == expected_md5.lower()) if expected_md5 else None
        sha256_match = (computed_sha256 == expected_sha256.lower()) if expected_sha256 else None

        # For E01, also run ewfverify
        ewf_verify: dict = {}
        if Path(image_path).suffix.lower() in (".e01", ".ewf", ".ex01"):
            try:
                r = subprocess.run(
                    ["ewfverify", image_path],
                    capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT * 4,
                )
                ewf_verify = {"stdout": r.stdout[:2000], "returncode": r.returncode}
            except FileNotFoundError:
                ewf_verify = {"note": "ewfverify not found"}

        integrity_ok = True
        if md5_match is False or sha256_match is False:
            integrity_ok = False

        data = {
            "image_path": image_path,
            "image_size_bytes": size,
            "computed_md5": computed_md5,
            "computed_sha256": computed_sha256,
            "expected_md5": expected_md5 or "not provided",
            "expected_sha256": expected_sha256 or "not provided",
            "md5_match": md5_match,
            "sha256_match": sha256_match,
            "integrity_verified": integrity_ok,
            "ewf_verification": ewf_verify,
            "chain_of_custody": "VERIFIED" if integrity_ok else "BROKEN — hash mismatch!",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("verify_image_integrity", data, audit_id)
