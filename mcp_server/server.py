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

mcp = FastMCP(
    "DeepSIFT Forensic Server",
    instructions=(
        "You are a forensic analysis assistant with access to SIFT Workstation tools. "
        "All tools return structured JSON — do not attempt to interpret raw CLI output. "
        "Always call get_process_list first for memory images. "
        "Call finish_analysis when you have sufficient evidence. "
        "Never exceed 10 tool calls without calling finish_analysis or reporting partial findings. "
        "Never modify evidence files — all tools are read-only on evidence."
    ),
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
from mcp_server.tools.log2timeline import register_log2timeline_tools
from mcp_server.tools.sleuthkit import register_sleuthkit_tools
from mcp_server.tools.yara_tools import register_yara_tools
from mcp_server.tools.windows_artifacts import register_windows_artifact_tools
from mcp_server.tools.hayabusa import register_hayabusa_tools
from mcp_server.tools.file_analysis import register_file_analysis_tools
from mcp_server.tools.network_analysis import register_network_analysis_tools
from mcp_server.tools.correlation import register_correlation_tools

register_volatility_tools(mcp, rag)
register_volatility_extended_tools(mcp, rag)
register_log2timeline_tools(mcp, rag)
register_sleuthkit_tools(mcp, rag)
register_yara_tools(mcp, rag)
register_windows_artifact_tools(mcp, rag)
register_hayabusa_tools(mcp, rag)
register_file_analysis_tools(mcp, rag)
register_network_analysis_tools(mcp, rag)
register_correlation_tools(mcp, rag)

try:
    tool_count = len(mcp.list_tools())
    logger.info(f"DeepSIFT MCP server initialized with {tool_count} tools")
except Exception:
    logger.info("DeepSIFT MCP server initialized")

if __name__ == "__main__":
    mcp.run()
