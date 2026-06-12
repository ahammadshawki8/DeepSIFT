"""log2timeline / Plaso MCP tool wrappers."""
import json
import subprocess
from pathlib import Path

from mcp_server.config import LOG2TIMELINE_CMD, PSORT_CMD, EXPORTS_DIR, MAX_TOOL_TIMEOUT
from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter
from mcp_server.parsers.timeline_parser import parse_timeline_csv, summarize_timeline
from mcp_server.parsers.forensic_knowledge import wrap_response


def _run(cmd: list[str], tool_name: str, timeout: int | None = None) -> tuple[str, str]:
    t = timeout or MAX_TOOL_TIMEOUT
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=t)
        log_tool_execution(tool_name, cmd, result.stdout, error=result.stderr)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        msg = f"'{tool_name}' timed out after {t}s"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg
    except FileNotFoundError:
        msg = f"Tool not found: {cmd[0]}. Is log2timeline installed?"
        log_tool_execution(tool_name, cmd, "", error=msg)
        return "", msg


def register_log2timeline_tools(mcp, rag=None):

    @mcp.tool()
    def create_super_timeline(image_path: str, output_name: str) -> str:
        """
        Creates a Plaso super-timeline storage file from a disk image or directory.

        This is a long-running operation (minutes to hours for large images).
        The output .plaso file is saved to exports/ for follow-up filtering.
        After creation, call filter_timeline to extract events for a specific time window.

        Args:
            image_path: Absolute path to disk image or evidence directory.
            output_name: Base name for the output file (no extension). E.g. 'rocba_disk'.
        """
        output_path = str(EXPORTS_DIR / f"{output_name}.plaso")
        cmd = [LOG2TIMELINE_CMD, output_path, image_path]
        stdout, stderr = _run(cmd, "create_super_timeline", timeout=3600)
        audit_id = get_last_audit_id()
        increment_tool_counter()

        if stderr and "error" in stderr.lower() and not stdout:
            return json.dumps({"error": stderr, "audit_id": audit_id})

        data = {
            "status": "timeline_created",
            "plaso_file": output_path,
            "next_step": (
                "Use filter_timeline to extract events for your investigation window. "
                "Example: filter_timeline with start='11/13/2020 18:00:00' end='11/14/2020 06:00:00'"
            ),
        }
        return wrap_response("create_super_timeline", data, audit_id)

    @mcp.tool()
    def filter_timeline(
        plaso_file: str,
        output_name: str,
        start_time: str = "",
        end_time: str = "",
        filter_query: str = "",
    ) -> str:
        """
        Filter a Plaso storage file and return structured timeline events.

        Args:
            plaso_file: Path to .plaso file created by create_super_timeline.
            output_name: Base name for the CSV output file.
            start_time: Start of time window as 'YYYY-MM-DDTHH:MM:SS' (optional).
            end_time: End of time window as 'YYYY-MM-DDTHH:MM:SS' (optional).
            filter_query: Plaso filter query string (optional, e.g. 'filename contains cmd.exe').
        """
        csv_output = str(EXPORTS_DIR / f"{output_name}.csv")
        cmd = [PSORT_CMD, "-o", "l2tcsv", plaso_file, "-w", csv_output]

        if start_time and end_time:
            cmd += ["--slice", f"{start_time}..{end_time}"]
        if filter_query:
            cmd += [filter_query]

        stdout, stderr = _run(cmd, "filter_timeline")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        try:
            csv_content = Path(csv_output).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            csv_content = stdout

        if not csv_content.strip():
            return json.dumps({
                "error": "No events returned. Check time window or filter query.",
                "stderr": stderr,
                "audit_id": audit_id,
            })

        events = parse_timeline_csv(csv_content, max_events=200)
        summary = summarize_timeline(events)

        data = {
            "csv_file": csv_output,
            "summary": summary,
            "suspicious_events": [e for e in events if e.get("suspicious")][:50],
        }
        return wrap_response("filter_timeline", data, audit_id)

    @mcp.tool()
    def get_browser_history(plaso_file: str, output_name: str) -> str:
        """
        Extracts only browser history events from a Plaso timeline.

        Useful for finding web-based exfiltration, downloads, and C2 URLs.
        Filters for WEBHIST source type automatically.

        Args:
            plaso_file: Path to .plaso file.
            output_name: Base name for output CSV.
        """
        csv_output = str(EXPORTS_DIR / f"{output_name}_webhist.csv")
        cmd = [PSORT_CMD, "-o", "l2tcsv", plaso_file, "-w", csv_output, "source is 'WEBHIST'"]
        stdout, stderr = _run(cmd, "get_browser_history")
        audit_id = get_last_audit_id()
        increment_tool_counter()

        try:
            csv_content = Path(csv_output).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            csv_content = stdout

        events = parse_timeline_csv(csv_content, max_events=500)
        data = {
            "total_browser_events": len(events),
            "events": events[:100],
        }
        return wrap_response("get_browser_history", data, audit_id)
