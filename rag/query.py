"""Semantic search interface — thin wrapper around ForensicKnowledgeBase."""
from __future__ import annotations
from rag.knowledge_base import ForensicKnowledgeBase

_kb: ForensicKnowledgeBase | None = None


def get_kb() -> ForensicKnowledgeBase:
    global _kb
    if _kb is None:
        _kb = ForensicKnowledgeBase()
    return _kb


def search(query: str, n: int = 3) -> str:
    return get_kb().query(query, n_results=n)


def search_structured(query: str, n: int = 3) -> list[dict]:
    return get_kb().query_structured(query, n_results=n)
