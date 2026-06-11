"""Chain-of-custody audit logging and evidence path guard for every tool execution."""
import json
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Top-level directory names that are read-only evidence on SIFT Workstation.
# No tool output may be written to /cases/, /mnt/, or /media/.
# This is architectural safety enforcement — not prompt-based.
_EVIDENCE_TOP_DIRS = {"cases", "mnt", "media"}


def guard_output_path(path: str) -> str:
    """
    Verify that a planned output path does NOT resolve into evidence directories.

    Raises PermissionError if path is inside /cases/, /mnt/, or /media/ (SIFT conventions).
    Returns the resolved absolute path as a string on success.

    Uses path parts for cross-platform correctness (Linux /cases/ and Windows C:\\cases\\).
    Call this before any tool that writes files to user-supplied paths.
    """
    resolved = Path(path).resolve()
    parts = resolved.parts
    # On Linux: Path("/cases/foo").parts == ('/', 'cases', 'foo')
    # On Windows: Path("C:/cases/foo").parts == ('C:\\', 'cases', 'foo')
    if len(parts) >= 2 and parts[1] in _EVIDENCE_TOP_DIRS:
        raise PermissionError(
            f"Writing to evidence path is forbidden (architectural safety enforcement): "
            f"{path!r} resolves to {str(resolved)!r}. "
            "Evidence directories (/cases/, /mnt/, /media/) are strictly read-only."
        )
    return str(resolved)

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
    # exports_dir is always inside the project — guard not needed here, but
    # validate it never accidentally resolves to an evidence path
    try:
        guard_output_path(str(export_file))
    except PermissionError as e:
        logger.error(f"Audit log refused to write to evidence path: {e}")
        raise
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
