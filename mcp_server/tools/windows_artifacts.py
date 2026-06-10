"""EZ Tools / Windows artifact MCP tool wrappers."""
from __future__ import annotations
import json
import subprocess
from pathlib import Path

from mcp_server.config import EZ_TOOLS_DIR, EXPORTS_DIR, MAX_TOOL_TIMEOUT
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
        msg = f"Tool not found: {cmd[0]}. Check EZ_TOOLS_DIR in .env"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg


def _ez(tool: str) -> str:
    return str(EZ_TOOLS_DIR / tool)


def register_windows_artifact_tools(mcp, rag=None):

    @mcp.tool()
    def parse_prefetch(prefetch_dir: str) -> str:
        """
        Parses Windows Prefetch files to recover program execution history.

        Prefetch files record the last 8 run times and file paths accessed.
        Critical for proving what programs ran on a system and when.
        Prefetch is located at C:\\Windows\\Prefetch\\ on the evidence volume.

        Args:
            prefetch_dir: Path to the directory containing .pf files.
        """
        output_dir = str(EXPORTS_DIR / "prefetch")
        cmd = [_ez("PECmd.exe"), "-d", prefetch_dir, "--csv", output_dir]
        stdout, stderr = _run(cmd, "parse_prefetch")

        output_path = Path(output_dir)
        csv_files = list(output_path.glob("*.csv")) if output_path.exists() else []

        entries = []
        for csv_file in csv_files:
            try:
                import csv as _csv
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        entries.append({
                            "executable": row.get("ExecutableName", ""),
                            "run_count": row.get("RunCount", ""),
                            "last_run": row.get("LastRun", ""),
                            "previous_runs": row.get("PreviousRun0", ""),
                            "volume_name": row.get("VolumeSerialNumber", ""),
                        })
            except Exception:
                continue

        return json.dumps({
            "total_prefetch_entries": len(entries),
            "entries": sorted(entries, key=lambda x: x.get("last_run", ""), reverse=True)[:100],
        }, default=str)

    @mcp.tool()
    def parse_lnk_files(lnk_dir: str) -> str:
        """
        Parses Windows LNK (shortcut) files to recover recently accessed file paths.

        LNK files record the target file path, timestamps, volume information, and
        network path. Found in Recent Items and user Desktop.

        Args:
            lnk_dir: Path to directory containing .lnk files.
        """
        output_dir = str(EXPORTS_DIR / "lnk")
        cmd = [_ez("LECmd.exe"), "-d", lnk_dir, "--csv", output_dir]
        stdout, stderr = _run(cmd, "parse_lnk_files")

        output_path = Path(output_dir)
        entries = []
        for csv_file in output_path.glob("*.csv") if output_path.exists() else []:
            try:
                import csv as _csv
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        entries.append({
                            "source_file": row.get("SourceFile", ""),
                            "target_path": row.get("LocalPath", ""),
                            "network_path": row.get("NetworkPath", ""),
                            "created": row.get("TargetCreated", ""),
                            "modified": row.get("TargetModified", ""),
                            "accessed": row.get("TargetAccessed", ""),
                        })
            except Exception:
                continue

        return json.dumps({
            "total_lnk_files": len(entries),
            "entries": entries[:100],
        }, default=str)

    @mcp.tool()
    def parse_jump_lists(jumplist_dir: str) -> str:
        """
        Parses Windows Jump List files to recover recent file and application activity.

        Jump Lists are stored in AppData\\Roaming\\Microsoft\\Windows\\Recent\\
        in AutomaticDestinations\\ and CustomDestinations\\ subdirectories.

        Args:
            jumplist_dir: Path to directory containing jump list files.
        """
        output_dir = str(EXPORTS_DIR / "jumplists")
        cmd = [_ez("JLECmd.exe"), "-d", jumplist_dir, "--csv", output_dir]
        stdout, stderr = _run(cmd, "parse_jump_lists")

        output_path = Path(output_dir)
        entries = []
        for csv_file in output_path.glob("*.csv") if output_path.exists() else []:
            try:
                import csv as _csv
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        entries.append(dict(row))
            except Exception:
                continue

        return json.dumps({
            "total_jumplist_entries": len(entries),
            "entries": entries[:100],
        }, default=str)

    @mcp.tool()
    def parse_registry_hive(hive_path: str, search_pattern: str = "") -> str:
        """
        Parse a registry hive file using RECmd and return key/value data.

        Useful for examining offline registry hives extracted from evidence.
        Can search for specific patterns within the hive.

        Args:
            hive_path: Absolute path to the registry hive file (e.g. NTUSER.DAT, SOFTWARE).
            search_pattern: Optional keyword to search for within key names or values.
        """
        output_dir = str(EXPORTS_DIR / "registry")
        cmd = [_ez("RECmd.exe"), "-f", hive_path, "--csv", output_dir]
        if search_pattern:
            cmd += ["--sk", search_pattern]

        stdout, stderr = _run(cmd, "parse_registry_hive")

        output_path = Path(output_dir)
        entries = []
        for csv_file in output_path.glob("*.csv") if output_path.exists() else []:
            try:
                import csv as _csv
                with open(csv_file, encoding="utf-8-sig") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        entries.append({
                            "key_path": row.get("KeyPath", ""),
                            "value_name": row.get("ValueName", ""),
                            "value_type": row.get("ValueType", ""),
                            "value_data": row.get("ValueData", "")[:500],
                            "last_write": row.get("LastWriteTimestamp", ""),
                        })
            except Exception:
                continue

        return json.dumps({
            "hive": hive_path,
            "search_pattern": search_pattern,
            "total_entries": len(entries),
            "entries": entries[:200],
        }, default=str)

    @mcp.tool()
    def lookup_ip_reputation(ip_address: str) -> str:
        """
        Check an IP address against AbuseIPDB and VirusTotal threat intelligence.

        Use this for every external IP found by get_network_connections.
        Returns abuse confidence score, ISP, country, and known malicious activity.

        Args:
            ip_address: IPv4 or IPv6 address to check.
        """
        import requests
        from mcp_server.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY

        result = {"ip": ip_address, "abuseipdb": None, "virustotal": None}

        if ABUSEIPDB_API_KEY:
            try:
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
                    params={"ipAddress": ip_address, "maxAgeInDays": 90},
                    timeout=10,
                )
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    result["abuseipdb"] = {
                        "abuse_confidence_score": data.get("abuseConfidenceScore"),
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "total_reports": data.get("totalReports"),
                        "last_reported": data.get("lastReportedAt"),
                        "is_whitelisted": data.get("isWhitelisted"),
                    }
            except Exception as e:
                result["abuseipdb"] = {"error": str(e)}

        if VIRUSTOTAL_API_KEY:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                    timeout=10,
                )
                if r.status_code == 200:
                    attrs = r.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    result["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "country": attrs.get("country"),
                        "as_owner": attrs.get("as_owner"),
                        "reputation": attrs.get("reputation"),
                    }
            except Exception as e:
                result["virustotal"] = {"error": str(e)}

        return json.dumps(result)
