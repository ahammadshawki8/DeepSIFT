"""
Evidence-index MCP tools — token-scale querying of the FULL artifact set.

The parsed tool responses cap their entries (so they fit the prompt); these tools let
the agent index the COMPLETE rows the EZ tools wrote to exports/<artifact>/*.csv into a
stdlib SQLite store, then pull only the rows that match a query — so a 100k-row MFT or a
full shellbag set is reachable without dumping it into context.
"""
import json
from pathlib import Path

from mcp_server.config import EXPORTS_DIR
from mcp_server.audit import get_last_audit_id, increment_tool_counter
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.evidence_store import EvidenceStore


def register_evidence_index_tools(mcp, rag=None):

    @mcp.tool()
    def index_evidence(export_path: str, source: str = "", audit_id: str = "") -> str:
        """
        Index the FULL rows of a parsed artifact into the queryable evidence store, so you
        can later pull subsets without dumping everything into context.

        Point it at a CSV file or a directory of CSVs the tools wrote (e.g.
        'exports/shellbags', 'exports/mft', 'exports/userassist'). Returns the row count.

        Args:
            export_path: CSV file or directory under exports/ (absolute or repo-relative).
            source:      Label for these rows (defaults to the file/dir name, e.g. 'mft').
            audit_id:    Optional chain-of-custody link to the tool call that produced it.
        """
        increment_tool_counter()
        p = Path(export_path)
        if not p.is_absolute() and not p.exists():
            cand = EXPORTS_DIR / export_path
            if cand.exists():
                p = cand
        if not p.exists():
            return json.dumps({"error": f"path not found: {export_path}"})
        store = EvidenceStore()
        n = store.ingest_path(source or p.stem, p, audit_id)
        stats = store.stats()
        store.close()
        return wrap_response("index_evidence",
                             {"indexed_rows": n, "source": source or p.stem, "store": stats},
                             get_last_audit_id())

    @mcp.tool()
    def query_evidence(query: str = "", source: str = "", limit: int = 50) -> str:
        """
        Query the indexed evidence store and return ONLY matching rows (token-bounded) —
        the scalable way to reach the full artifact set. Substring match across all
        columns; optionally restrict to one source and cap the number of rows.

        Args:
            query:  substring to match (e.g. 'StarkResearch', 'VeraCrypt', a SID, a path).
            source: optional artifact label to restrict to (e.g. 'shellbags').
            limit:  max rows to return (default 50).
        """
        increment_tool_counter()
        store = EvidenceStore()
        total = store.count(query, source)
        rows = store.query(query, source, limit)
        store.close()
        return wrap_response("query_evidence",
                             {"query": query, "source": source or "(any)",
                              "matched_total": total, "returned": len(rows), "rows": rows},
                             get_last_audit_id())

    @mcp.tool()
    def evidence_store_stats() -> str:
        """Report what is in the indexed evidence store (row counts per artifact source)."""
        increment_tool_counter()
        store = EvidenceStore()
        stats = store.stats()
        store.close()
        return wrap_response("evidence_store_stats", stats, get_last_audit_id())
