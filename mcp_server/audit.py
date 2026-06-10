"""Chain-of-custody audit logging for every tool execution."""
import json
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Lazy import to avoid circular dependency at module load
def _get_dirs():
    from mcp_server.config import EXPORTS_DIR, ANALYSIS_DIR
    return EXPORTS_DIR, ANALYSIS_DIR


def log_tool_execution(
    tool_name: str,
    command: list,
    raw_output: str,
    result_summary: str = "",
    error: str = ""
) -> dict:
    """
    Write one audit entry per tool call.
    Saves raw output to exports/ and appends a JSON line to forensic_audit.log.
    Returns the entry dict so callers can embed it in their response.
    """
    exports_dir, analysis_dir = _get_dirs()
    timestamp = datetime.now(timezone.utc).isoformat()
    safe_ts = timestamp.replace(":", "-").replace(".", "-")
    output_hash = hashlib.sha256(raw_output.encode()).hexdigest()

    export_file = exports_dir / f"{tool_name}_{safe_ts}.txt"
    export_file.write_text(raw_output, encoding="utf-8")

    entry = {
        "timestamp": timestamp,
        "tool": tool_name,
        "command": " ".join(str(c) for c in command),
        "raw_output_sha256": output_hash,
        "raw_output_file": str(export_file),
        "result_summary": result_summary,
        "error": error,
    }

    audit_log = analysis_dir / "forensic_audit.log"
    with open(audit_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    return entry
