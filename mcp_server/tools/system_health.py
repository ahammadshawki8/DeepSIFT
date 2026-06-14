"""System-health MCP tool: lets a Claude Code judge (or the agent) query, as structured
JSON, which forensic tool groups are operational in the current environment before relying
on them. Pure introspection — touches no evidence."""
from mcp_server.audit import get_last_audit_id, increment_tool_counter
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.preflight import check_dependencies


def register_system_health_tools(mcp, rag=None):

    @mcp.tool()
    def check_tool_availability() -> str:
        """
        Report which external forensic tool groups (Volatility, Sleuth Kit, EZ Tools,
        Plaso, YARA, Hayabusa, bulk_extractor, capa, FLOSS, exiftool) are installed and
        operational in THIS environment, plus the pure-Python tool families that always
        work. Tools backed by a missing binary return a clear 'unavailable' status rather
        than crashing — call this first to know what to rely on.

        Returns a structured report: operational count, available/unavailable groups with
        representative tools and install hints, and an overall verdict.
        """
        increment_tool_counter()
        rep = check_dependencies()
        return wrap_response("check_tool_availability", rep, get_last_audit_id())
