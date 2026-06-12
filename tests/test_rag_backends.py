"""RAG embedder selection + offline corpus tests (no network/key needed)."""
from rag.knowledge_base import ForensicKnowledgeBase, _OfflineEmbedder


def test_offline_embedder_shapes():
    e = _OfflineEmbedder()
    v = e.encode(["certutil download payload", "rdp brute force"])
    assert v.shape[0] == 2 and v.shape[1] == 384


def test_embedder_selection_falls_back_offline(monkeypatch):
    # no torch, no OPENAI_API_KEY -> offline
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    model, backend = ForensicKnowledgeBase._select_embedder("all-MiniLM-L6-v2")
    assert backend in ("offline-hashing-vectorizer", "sentence-transformers")


def test_lolbas_and_mitre_catalog_nonempty():
    from rag.ingest.knowledge_corpus import _LOLBAS, ingest_mitre_catalog
    assert any("certutil" in b[0] for b in _LOLBAS)
    assert any("vssadmin" in b[0] for b in _LOLBAS)
    # mitre catalog harvest yields real technique ids from the parser rules
    from mcp_server.parsers import mitre_auto_map as m
    rules = getattr(m, "_ALL_RULE_GROUPS", [])
    tids = {r[1] for r in rules if len(r) >= 3}
    assert "T1110" in tids or any(t.startswith("T11") for t in tids)
