"""
ForensicKnowledgeBase — ChromaDB-backed semantic search over threat intelligence.

Ingests: MITRE ATT&CK techniques, Hunt Evil process baseline notes,
         threat intel feeds, and previous case findings.

At query time, injects relevant context into MCP tool results so Claude
sees grounded threat intel alongside parsed forensic data.
"""
from __future__ import annotations
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class _OfflineEmbedder:
    """Deterministic, dependency-light embedder for air-gapped / constrained hosts
    (e.g. a SIFT VM with no GPU build of torch and a throttled uplink that cannot
    pull the all-MiniLM model). Uses a hashing vectorizer over word n-grams — purely
    lexical, but fully offline and good enough to ground IOC/keyword lookups when the
    transformer model is unavailable. Exposes the SentenceTransformer.encode() API."""

    def __init__(self, n_features: int = 384):
        from sklearn.feature_extraction.text import HashingVectorizer
        self.vec = HashingVectorizer(
            n_features=n_features, alternate_sign=False, norm="l2",
            ngram_range=(1, 2), stop_words="english",
        )
        self.backend = "offline-hashing-vectorizer"

    def encode(self, texts):
        import numpy as np
        if isinstance(texts, str):
            texts = [texts]
        return np.asarray(self.vec.transform(texts).todense(), dtype="float32")


class _OpenAIEmbedder:
    """Real semantic embeddings via the OpenAI embeddings API (text-embedding-3-small
    by default). Small requests, works over constrained links; needs OPENAI_API_KEY."""

    def __init__(self, model: str = "text-embedding-3-small"):
        import os
        import openai  # raises if not installed -> caller falls back
        key = os.getenv("OPENAI_API_KEY", "")
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        self.client = openai.OpenAI(api_key=key)
        self.model = model
        self.backend = f"openai:{model}"

    def encode(self, texts):
        import numpy as np
        if isinstance(texts, str):
            texts = [texts]
        # batch to stay within request limits
        vecs = []
        for i in range(0, len(texts), 256):
            resp = self.client.embeddings.create(model=self.model, input=texts[i:i + 256])
            vecs.extend(d.embedding for d in resp.data)
        return np.asarray(vecs, dtype="float32")


class ForensicKnowledgeBase:
    @staticmethod
    def _select_embedder(model_name: str):
        try:
            from sentence_transformers import SentenceTransformer
            return SentenceTransformer(model_name), "sentence-transformers"
        except Exception as e:
            logger.warning(f"sentence-transformers unavailable ({e})")
        try:
            emb = _OpenAIEmbedder()
            logger.info("Using OpenAI embeddings (semantic)")
            return emb, emb.backend
        except Exception as e:
            logger.warning(f"OpenAI embeddings unavailable ({e}); using offline embedder")
        emb = _OfflineEmbedder()
        return emb, getattr(emb, "backend", "offline")

    def __init__(self, db_path: str | None = None):
        import chromadb

        if db_path is None:
            from mcp_server.config import RAG_DB_PATH, EMBED_MODEL
            db_path = RAG_DB_PATH
            model_name = EMBED_MODEL
        else:
            model_name = "all-MiniLM-L6-v2"

        Path(db_path).mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=db_path)
        # Embedding backend, best available first:
        #  1. sentence-transformers (local semantic) if torch + model are present;
        #  2. OpenAI embeddings API (real semantic, small requests) if OPENAI_API_KEY set;
        #  3. offline hashing embedder (lexical, fully air-gapped) as last resort.
        self.embed_model, self.embed_backend = self._select_embedder(model_name)
        self.collection = self.client.get_or_create_collection(
            name="forensic_knowledge",
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(f"ForensicKnowledgeBase ready — {self.collection.count()} documents indexed")

    # ── Ingestion ──────────────────────────────────────────────────────────

    def ingest_mitre_attack(self, mitre_json_path: str) -> int:
        """
        Load MITRE ATT&CK enterprise techniques into the knowledge base.
        Download the JSON from: https://github.com/mitre/cti

        Returns number of techniques ingested.
        """
        with open(mitre_json_path, encoding="utf-8") as f:
            data = json.load(f)

        documents, ids, metadatas = [], [], []
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            tid = next(
                (ref["external_id"] for ref in obj.get("external_references", [])
                 if ref.get("source_name") == "mitre-attack"),
                obj.get("id", "unknown"),
            )
            name = obj.get("name", "")
            desc = obj.get("description", "")[:1000]
            tactics = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
            platforms = obj.get("x_mitre_platforms", [])

            doc = (
                f"MITRE ATT&CK {tid}: {name}\n"
                f"Tactics: {', '.join(tactics)}\n"
                f"Platforms: {', '.join(platforms)}\n"
                f"Description: {desc}"
            )
            documents.append(doc)
            ids.append(f"mitre_{tid}")
            metadatas.append({
                "source": "mitre_attack",
                "technique_id": tid,
                "name": name,
                "tactics": ",".join(tactics),
            })

        self._batch_add(documents, ids, metadatas)
        logger.info(f"Ingested {len(documents)} MITRE ATT&CK techniques")
        return len(documents)

    def ingest_hunt_evil_baseline(self) -> int:
        """
        Load the SANS Hunt Evil known-normal process baseline as documents.
        This lets Claude query 'what is normal for svchost.exe' with grounded answers.
        """
        from mcp_server.parsers.pslist_parser import KNOWN_NORMAL

        documents, ids, metadatas = [], [], []
        for proc_name, info in KNOWN_NORMAL.items():
            doc = (
                f"Windows process baseline: {proc_name}\n"
                f"Expected parent: {info.get('expected_parent', 'varies')}\n"
                f"Max instances: {info.get('max_instances', 'unlimited')}\n"
                f"Expected user: {info.get('expected_user', 'varies')}\n"
                f"Notes: {info.get('notes', '')}"
            )
            documents.append(doc)
            ids.append(f"baseline_{proc_name.lower().replace('.', '_')}")
            metadatas.append({"source": "hunt_evil_baseline", "process": proc_name})

        self._batch_add(documents, ids, metadatas)
        logger.info(f"Ingested {len(documents)} Hunt Evil baseline entries")
        return len(documents)

    def ingest_document(self, doc_id: str, content: str, source: str, metadata: dict | None = None) -> None:
        """Add a single document (case finding, IOC, threat report snippet)."""
        meta = {"source": source}
        if metadata:
            meta.update(metadata)
        self._batch_add([content], [doc_id], [meta])

    def add_case_finding(self, case_id: str, finding: str, case_metadata: dict | None = None) -> None:
        """Persist a finding from a completed investigation for future reference."""
        import hashlib
        doc_id = f"case_{case_id}_{hashlib.md5(finding.encode()).hexdigest()[:8]}"
        meta = {"source": "case_history", "case_id": case_id}
        if case_metadata:
            meta.update(case_metadata)
        self._batch_add([finding], [doc_id], [meta])
        logger.info(f"Added case finding to knowledge base: {doc_id}")

    # ── Querying ───────────────────────────────────────────────────────────

    def query(self, finding: str, n_results: int = 3) -> str:
        """
        Semantic search for threat intelligence relevant to a forensic finding.
        Returns a formatted context string ready for injection into tool results.
        """
        if self.collection.count() == 0:
            return ""

        query_embedding = self.embed_model.encode([finding]).tolist()
        try:
            results = self.collection.query(
                query_embeddings=query_embedding,
                n_results=min(n_results, self.collection.count()),
            )
        except Exception as e:
            logger.warning(f"RAG query failed: {e}")
            return ""

        context_parts = []
        for i, (doc, meta) in enumerate(zip(
            results["documents"][0],
            results["metadatas"][0],
        )):
            source = meta.get("source", "unknown")
            context_parts.append(f"[{i+1}] ({source}) {doc[:400]}")

        return "Relevant threat intelligence:\n" + "\n\n".join(context_parts)

    def query_structured(self, finding: str, n_results: int = 3) -> list[dict]:
        """Returns structured results instead of a formatted string."""
        if self.collection.count() == 0:
            return []

        query_embedding = self.embed_model.encode([finding]).tolist()
        try:
            results = self.collection.query(
                query_embeddings=query_embedding,
                n_results=min(n_results, self.collection.count()),
                include=["documents", "metadatas", "distances"],
            )
        except Exception:
            return []

        return [
            {
                "document": doc,
                "metadata": meta,
                "relevance_score": round(1 - dist, 4),
            }
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            )
        ]

    def get_stats(self) -> dict:
        """Return collection statistics."""
        return {
            "total_documents": self.collection.count(),
            "collection_name": self.collection.name,
        }

    # ── Internal ───────────────────────────────────────────────────────────

    def _batch_add(
        self,
        documents: list[str],
        ids: list[str],
        metadatas: list[dict],
        batch_size: int = 100,
    ) -> None:
        """Add documents in batches to avoid memory issues with large corpora."""
        embeddings = self.embed_model.encode(documents).tolist()
        for i in range(0, len(documents), batch_size):
            batch_docs = documents[i:i + batch_size]
            batch_ids = ids[i:i + batch_size]
            batch_meta = metadatas[i:i + batch_size]
            batch_emb = embeddings[i:i + batch_size]

            # Upsert to avoid duplicate-ID errors on re-ingest
            existing = self.collection.get(ids=batch_ids)["ids"]
            new_mask = [j for j, bid in enumerate(batch_ids) if bid not in existing]

            if new_mask:
                self.collection.add(
                    documents=[batch_docs[j] for j in new_mask],
                    embeddings=[batch_emb[j] for j in new_mask],
                    ids=[batch_ids[j] for j in new_mask],
                    metadatas=[batch_meta[j] for j in new_mask],
                )
