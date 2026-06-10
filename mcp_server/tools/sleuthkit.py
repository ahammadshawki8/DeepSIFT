"""Sleuth Kit MCP tool wrappers (fls, mmls, icat)."""
from __future__ import annotations
import json
import subprocess
from pathlib import Path

from mcp_server.config import FLS_CMD, MMLS_CMD, ICAT_CMD, EXPORTS_DIR, MAX_TOOL_TIMEOUT
from mcp_server.audit import log_tool_execution


def _run(cmd: list[str], tool_name: str) -> tuple[str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT)
        log_tool_execution(tool_name, cmd, result.stdout, error=result.stderr)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        msg = f"'{tool_name}' timed out"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg
    except FileNotFoundError:
        msg = f"Tool not found: {cmd[0]}. Is The Sleuth Kit installed?"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg


def register_sleuthkit_tools(mcp, rag=None):

    @mcp.tool()
    def get_partition_table(image_path: str) -> str:
        """
        Lists the partition table of a disk image.

        Run this first on a disk image to get partition offsets needed for
        file system operations (get_file_listing, extract_file).

        Args:
            image_path: Absolute path to the disk image file.
        """
        cmd = [MMLS_CMD, image_path]
        stdout, stderr = _run(cmd, "get_partition_table")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        partitions = _parse_mmls(stdout)
        return json.dumps({
            "partitions": partitions,
            "note": "Use 'offset' value (in sectors) with get_file_listing to browse a partition.",
        }, default=str)

    @mcp.tool()
    def get_file_listing(image_path: str, partition_offset: int, directory: str = "") -> str:
        """
        Lists files and directories in a disk image partition.

        Args:
            image_path: Absolute path to the disk image.
            partition_offset: Sector offset from get_partition_table.
            directory: Inode or path to list (leave empty for root).
        """
        cmd = [FLS_CMD, "-o", str(partition_offset), "-r", "-l"]
        if directory:
            cmd += [image_path, directory]
        else:
            cmd.append(image_path)

        stdout, stderr = _run(cmd, "get_file_listing")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        files = _parse_fls(stdout)
        deleted = [f for f in files if f.get("deleted")]

        return json.dumps({
            "total_files": len(files),
            "deleted_files": len(deleted),
            "files": files[:200],
            "deleted_file_list": deleted[:50],
        }, default=str)

    @mcp.tool()
    def extract_file(image_path: str, partition_offset: int, inode: str, output_name: str) -> str:
        """
        Extracts a specific file from a disk image by inode number.

        Use inodes from get_file_listing output. Extracted file is saved to exports/.

        Args:
            image_path: Absolute path to the disk image.
            partition_offset: Sector offset from get_partition_table.
            inode: Inode number from get_file_listing (e.g. '32456-128-1').
            output_name: Filename to save the extracted file as in exports/.
        """
        output_path = str(EXPORTS_DIR / output_name)
        cmd = [ICAT_CMD, "-o", str(partition_offset), image_path, inode]

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=MAX_TOOL_TIMEOUT)
            log_tool_execution("extract_file", cmd, f"[binary output: {len(result.stdout)} bytes]")
            with open(output_path, "wb") as f:
                f.write(result.stdout)
            return json.dumps({
                "status": "extracted",
                "output_file": output_path,
                "size_bytes": len(result.stdout),
            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    def search_deleted_files(image_path: str, partition_offset: int) -> str:
        """
        Lists only deleted/unallocated files from a disk image partition.

        Useful for finding evidence of anti-forensic activity or recently deleted
        tools and exfiltrated files.

        Args:
            image_path: Absolute path to the disk image.
            partition_offset: Sector offset from get_partition_table.
        """
        cmd = [FLS_CMD, "-o", str(partition_offset), "-r", "-d", image_path]
        stdout, stderr = _run(cmd, "search_deleted_files")

        if stderr and not stdout:
            return json.dumps({"error": stderr})

        files = _parse_fls(stdout)
        return json.dumps({
            "deleted_file_count": len(files),
            "files": files[:100],
        }, default=str)


def _parse_mmls(raw: str) -> list[dict]:
    partitions = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("DOS") or line.startswith("Units") or line.startswith("Slot"):
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[0].isdigit():
            partitions.append({
                "slot": parts[0],
                "start": int(parts[2]),
                "end": int(parts[3]),
                "length": int(parts[4]),
                "description": " ".join(parts[5:]) if len(parts) > 5 else "",
            })
    return partitions


def _parse_fls(raw: str) -> list[dict]:
    files = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        deleted = line.startswith("*")
        line_clean = line.lstrip("* ").strip()
        parts = line_clean.split("\t") if "\t" in line_clean else line_clean.split(None, 2)
        if len(parts) >= 2:
            files.append({
                "type_inode": parts[0],
                "name": parts[1] if len(parts) > 1 else "",
                "deleted": deleted,
            })
    return files
