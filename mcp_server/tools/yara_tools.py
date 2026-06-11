"""YARA hunting MCP tool wrappers."""
from __future__ import annotations
import json
import subprocess
from pathlib import Path

from mcp_server.config import YARA_CMD, VOLATILITY_CMD, YARA_RULES_DIR, EXPORTS_DIR, MAX_TOOL_TIMEOUT
from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter
from mcp_server.parsers.forensic_knowledge import wrap_response

BUILTIN_RULE_SETS = {
    "suspicious_strings": "suspicious_strings.yar",
    "webshells": "webshells.yar",
    "ransomware": "ransomware.yar",
    "rats": "rats.yar",
    "packers": "packers.yar",
}


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
        msg = f"Tool not found: {cmd[0]}. Is YARA installed?"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg


def register_yara_tools(mcp, rag=None):

    @mcp.tool()
    def scan_file_with_yara(file_path: str, rule_set: str = "suspicious_strings") -> str:
        """
        Scan a file with YARA rules and return all matches.

        Built-in rule sets: suspicious_strings, webshells, ransomware, rats, packers.
        You can also provide an absolute path to a custom .yar file.

        Args:
            file_path: Absolute path to the file to scan.
            rule_set: Name of built-in rule set OR absolute path to a .yar file.
        """
        if rule_set in BUILTIN_RULE_SETS:
            rules_path = str(YARA_RULES_DIR / BUILTIN_RULE_SETS[rule_set])
        else:
            rules_path = rule_set

        cmd = [YARA_CMD, "-r", rules_path, file_path]
        stdout, stderr = _run(cmd, "scan_file_with_yara")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        matches = _parse_yara_output(stdout)
        data = {
            "file": file_path,
            "rule_set": rule_set,
            "match_count": len(matches),
            "matches": matches,
        }
        return wrap_response("scan_file_with_yara", data, audit_id)

    @mcp.tool()
    def scan_memory_with_yara(image_path: str, rule_set: str = "suspicious_strings") -> str:
        """
        Scan a memory image for YARA rule matches using Volatility's yarascan plugin.

        More thorough than file scanning — finds matches in memory-resident code,
        decrypted payloads, and injected shellcode that may not exist on disk.

        Args:
            image_path: Absolute path to the memory image.
            rule_set: Name of built-in rule set OR absolute path to a .yar file.
        """
        if rule_set in BUILTIN_RULE_SETS:
            rules_path = str(YARA_RULES_DIR / BUILTIN_RULE_SETS[rule_set])
        else:
            rules_path = rule_set

        cmd = VOLATILITY_CMD + ["-f", image_path, "windows.yarascan.YaraScan", "--yara-file", rules_path]
        stdout, stderr = _run(cmd, "scan_memory_with_yara")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        matches = _parse_yara_output(stdout)
        data = {
            "image": image_path,
            "rule_set": rule_set,
            "match_count": len(matches),
            "matches": matches[:50],
        }
        return wrap_response("scan_memory_with_yara", data, audit_id)

    @mcp.tool()
    def list_yara_rule_sets() -> str:
        """
        Lists all available YARA rule sets in the yara_rules/ directory.
        Use this to discover what hunting rules are available before scanning.
        """
        available = {}
        for name, filename in BUILTIN_RULE_SETS.items():
            path = YARA_RULES_DIR / filename
            available[name] = {"file": filename, "exists": path.exists()}

        custom = [f.name for f in YARA_RULES_DIR.glob("*.yar") if f.name not in BUILTIN_RULE_SETS.values()]

        return json.dumps({
            "builtin_rule_sets": available,
            "custom_rules": custom,
        })


def _parse_yara_output(raw: str) -> list[dict]:
    matches = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if " " in line:
            parts = line.split(" ", 2)
            matches.append({
                "rule": parts[0],
                "target": parts[-1] if len(parts) > 1 else "",
                "raw": line,
            })
    return matches
