"""
DeepSIFT MCP Server — main entry point.

Wraps SANS SIFT forensic tools as typed, structured MCP functions.
Every tool returns structured JSON parsed by Python — raw CLI output never
reaches the LLM context.

Usage on SIFT Workstation:
    python3 mcp_server/server.py

Connect via Claude Code:
    Add to ~/.claude.json mcpServers:
    {
      "deepsift": {
        "command": "python3",
        "args": ["/path/to/deepsift/mcp_server/server.py"]
      }
    }
"""
import logging
from mcp.server.fastmcp import FastMCP

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("deepsift")

import os as _os

mcp = FastMCP(
    "DeepSIFT Forensic Server",
    instructions=(
        "You are a senior DFIR analyst with typed SIFT Workstation tools. All tools return "
        "structured JSON — never interpret raw CLI output. Triage to the evidence: for a memory "
        "image start with get_process_list; for a DISK-ONLY case start with disk/Windows artifacts "
        "(parse_event_logs, parse_shellbags, parse_userassist, parse_lnk_files, parse_jump_lists, "
        "parse_usb_history, parse_shimcache, parse_chrome_history, parse_mft). Reason explicitly: "
        "record_hypothesis for each theory, then update_hypothesis (confirm/disprove/inconclusive "
        "with confidence + the evidence audit_ids) as you test it — self-correct when contradicted. "
        "Run until the evidence is sufficient, then call finish_analysis (every claim must cite an "
        "audit_id). Never fabricate; never modify evidence — all tools are read-only on evidence."
    ),
    host=_os.getenv("DEEPSIFT_MCP_HOST", "127.0.0.1"),
    port=int(_os.getenv("DEEPSIFT_MCP_PORT", "8000")),
)

# ── Initialize RAG pipeline (optional — graceful degradation if unavailable) ──
rag = None
try:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from rag.knowledge_base import ForensicKnowledgeBase
    rag = ForensicKnowledgeBase()
    logger.info("RAG knowledge base loaded successfully")
except ImportError:
    logger.warning("RAG pipeline not available (chromadb/sentence-transformers not installed). Continuing without threat intel enrichment.")
except Exception as e:
    logger.warning(f"RAG pipeline failed to initialize: {e}. Continuing without it.")

# ── Register all tool modules ──────────────────────────────────────────────
from mcp_server.tools.volatility import register_volatility_tools
from mcp_server.tools.volatility_extended import register_volatility_extended_tools
from mcp_server.tools.volatility_advanced import register_volatility_advanced_tools
from mcp_server.tools.log2timeline import register_log2timeline_tools
from mcp_server.tools.sleuthkit import register_sleuthkit_tools
from mcp_server.tools.yara_tools import register_yara_tools
from mcp_server.tools.windows_artifacts import register_windows_artifact_tools
from mcp_server.tools.hayabusa import register_hayabusa_tools
from mcp_server.tools.file_analysis import register_file_analysis_tools
from mcp_server.tools.network_analysis import register_network_analysis_tools
from mcp_server.tools.correlation import register_correlation_tools
from mcp_server.tools.browser_artifacts import register_browser_artifact_tools
from mcp_server.tools.email_artifacts import register_email_artifact_tools
from mcp_server.tools.cloud_artifacts import register_cloud_artifact_tools
from mcp_server.tools.registry_extended import register_registry_extended_tools
from mcp_server.tools.file_carving import register_file_carving_tools
from mcp_server.tools.linux_forensics import register_linux_forensics_tools
from mcp_server.tools.anti_forensics import register_anti_forensics_tools
from mcp_server.tools.document_analysis import register_document_analysis_tools
from mcp_server.tools.network_extended import register_network_extended_tools
from mcp_server.tools.disk_extended import register_disk_extended_tools
from mcp_server.tools.threat_intel_extended import register_threat_intel_extended_tools
from mcp_server.tools.system_health import register_system_health_tools
from mcp_server.tools.investigation_state import register_investigation_state_tools

register_volatility_tools(mcp, rag)
register_volatility_extended_tools(mcp, rag)
register_volatility_advanced_tools(mcp, rag)
register_log2timeline_tools(mcp, rag)
register_sleuthkit_tools(mcp, rag)
register_yara_tools(mcp, rag)
register_windows_artifact_tools(mcp, rag)
register_hayabusa_tools(mcp, rag)
register_file_analysis_tools(mcp, rag)
register_network_analysis_tools(mcp, rag)
register_correlation_tools(mcp, rag)
register_browser_artifact_tools(mcp, rag)
register_email_artifact_tools(mcp, rag)
register_cloud_artifact_tools(mcp, rag)
register_registry_extended_tools(mcp, rag)
register_file_carving_tools(mcp, rag)
register_linux_forensics_tools(mcp, rag)
register_anti_forensics_tools(mcp, rag)
register_document_analysis_tools(mcp, rag)
register_network_extended_tools(mcp, rag)
register_disk_extended_tools(mcp, rag)
register_threat_intel_extended_tools(mcp, rag)
register_system_health_tools(mcp, rag)
register_investigation_state_tools(mcp, rag)

try:
    # list_tools() is async in FastMCP; read the registry synchronously here.
    tool_count = len(mcp._tool_manager.list_tools())
    logger.info(f"DeepSIFT MCP server initialized with {tool_count} tools")
except Exception:
    logger.info("DeepSIFT MCP server initialized")

if __name__ == "__main__":
    # Client-agnostic transport. Default 'stdio' (Claude Code / Claude Desktop spawn it).
    # Set DEEPSIFT_MCP_TRANSPORT=sse|streamable-http to expose an HTTP endpoint that ANY
    # MCP client (Cherry Studio, LibreChat, a remote agent, a gateway) can connect to —
    # the same typed, audited, guard-railed tool surface, served over the network.
    transport = _os.getenv("DEEPSIFT_MCP_TRANSPORT", "stdio").strip()
    if transport not in ("stdio", "sse", "streamable-http"):
        logger.warning(f"Unknown DEEPSIFT_MCP_TRANSPORT={transport!r}; falling back to stdio")
        transport = "stdio"
    if transport != "stdio":
        logger.info(f"Serving over {transport} at "
                    f"{_os.getenv('DEEPSIFT_MCP_HOST','127.0.0.1')}:{_os.getenv('DEEPSIFT_MCP_PORT','8000')}")
    mcp.run(transport=transport)
