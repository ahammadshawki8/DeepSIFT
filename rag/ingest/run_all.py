"""
One-command RAG seeding: MITRE ATT&CK + Hunt Evil baseline + ROCBA case IOCs.

Usage:
    python3 rag/ingest/run_all.py
    python3 rag/ingest/run_all.py --mitre-path /path/to/enterprise-attack.json
"""
import argparse
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Seed all RAG knowledge bases")
    parser.add_argument("--mitre-path", default=None,
                        help="Path to enterprise-attack.json (downloaded if absent)")
    parser.add_argument("--skip-mitre", action="store_true",
                        help="Skip MITRE ATT&CK ingestion (use if already seeded)")
    parser.add_argument("--ioc-csv", default=None,
                        help="Optional path to custom IOC CSV to ingest")
    parser.add_argument("--abuseipdb-csv", default=None,
                        help="Optional path to AbuseIPDB bulk blacklist CSV")
    args = parser.parse_args()

    from rag.knowledge_base import ForensicKnowledgeBase
    kb = ForensicKnowledgeBase()
    initial_count = kb.get_stats()["total_documents"]
    logger.info(f"Starting RAG seeding. Current document count: {initial_count}")

    total = 0

    # ── MITRE ATT&CK + Hunt Evil baseline ────────────────────────────────────
    if not args.skip_mitre:
        logger.info("Ingesting MITRE ATT&CK Enterprise framework...")
        from rag.ingest.mitre_attack import ingest as ingest_mitre
        n = ingest_mitre(args.mitre_path)
        logger.info(f"  + {n} MITRE ATT&CK techniques")
        total += n
    else:
        logger.info("Skipping MITRE ATT&CK ingestion (--skip-mitre)")

    # ── ROCBA case IOCs ───────────────────────────────────────────────────────
    logger.info("Ingesting ROCBA case IOCs and findings...")
    from rag.ingest.rocba_iocs import ingest_rocba_iocs
    n = ingest_rocba_iocs()
    logger.info(f"  + {n} ROCBA case documents")
    total += n

    # ── Custom IOC CSV ────────────────────────────────────────────────────────
    if args.ioc_csv:
        from rag.ingest.threat_intel import ingest_ioc_csv
        n = ingest_ioc_csv(args.ioc_csv)
        logger.info(f"  + {n} custom IOCs from {args.ioc_csv}")
        total += n

    # ── AbuseIPDB blacklist ───────────────────────────────────────────────────
    if args.abuseipdb_csv:
        from rag.ingest.threat_intel import ingest_abuse_ipdb_blacklist
        n = ingest_abuse_ipdb_blacklist(args.abuseipdb_csv)
        logger.info(f"  + {n} AbuseIPDB malicious IPs from {args.abuseipdb_csv}")
        total += n

    final_count = kb.get_stats()["total_documents"]
    logger.info(f"RAG seeding complete. Total new documents: {total}. "
                f"Database now contains {final_count} documents.")
    print(f"\nRAG knowledge base ready: {final_count} documents indexed.")


if __name__ == "__main__":
    main()
