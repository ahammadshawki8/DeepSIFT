"""
RAG enrichment helpers — shared by all tool modules.

Every suspicious finding gets: threat_intel from RAG query + MITRE auto-map
from the rule-based mapper. This ensures RAG context appears in EVERY tool
response that has suspicious findings, not just the Volatility tools.
"""
from __future__ import annotations
from typing import Callable


def enrich_findings(
    rag,
    findings: list[dict],
    query_fn: Callable[[dict], str],
    *,
    max_enriched: int = 20,
) -> None:
    """
    Mutate findings in-place: add 'threat_intel' from RAG and 'mitre_techniques'
    from the rule-based mapper for each finding.

    Args:
        rag:          RAG knowledge base instance (may be None — graceful no-op).
        findings:     List of finding dicts to enrich.
        query_fn:     Callable(finding) → query string for RAG.
        max_enriched: Maximum number of findings to enrich (rate-limit protection).
    """
    from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques

    for i, item in enumerate(findings[:max_enriched]):
        # MITRE auto-mapping
        text = " ".join(str(v) for v in item.values() if isinstance(v, (str, list, int)))
        if not item.get("mitre_techniques"):
            item["mitre_techniques"] = map_finding_to_techniques(text)

        # RAG threat intel enrichment
        if rag is not None and not item.get("threat_intel"):
            try:
                query = query_fn(item)
                if query:
                    item["threat_intel"] = rag.query(query, n_results=2)
            except Exception:
                pass


def enrich_single(rag, item: dict, query: str) -> None:
    """
    Add RAG threat intel and MITRE techniques to a single finding dict.
    Mutates in-place.
    """
    from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques

    text = " ".join(str(v) for v in item.values() if isinstance(v, (str, list, int)))
    if not item.get("mitre_techniques"):
        item["mitre_techniques"] = map_finding_to_techniques(text)

    if rag is not None and not item.get("threat_intel"):
        try:
            item["threat_intel"] = rag.query(query, n_results=2)
        except Exception:
            pass


def build_rag_summary(rag, topic: str, n_results: int = 3) -> list:
    """
    Query RAG for a topic and return results (empty list on failure/no RAG).
    Use this to enrich the top-level response with context beyond individual findings.
    """
    if rag is None:
        return []
    try:
        return rag.query(topic, n_results=n_results) or []
    except Exception:
        return []
