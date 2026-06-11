"""
One-command RAG seeding: MITRE ATT&CK Enterprise + Hunt Evil baseline.

Optionally seed case-specific IOCs from a JSON file (any case, not just ROCBA).

Usage:
    # Baseline seed (MITRE ATT&CK only)
    python3 rag/ingest/run_all.py

    # With a pre-downloaded ATT&CK JSON
    python3 rag/ingest/run_all.py --mitre-path /path/to/enterprise-attack.json

    # With case-specific IOC/findings JSON
    python3 rag/ingest/run_all.py --case-ioc-json analysis/findings.json

    # ROCBA case specifically (shorthand)
    python3 rag/ingest/run_all.py --load-rocba

    # With AbuseIPDB bulk blacklist
    python3 rag/ingest/run_all.py --abuseipdb-csv /path/to/blacklist.csv

    # Skip MITRE if already seeded (faster re-runs)
    python3 rag/ingest/run_all.py --skip-mitre --case-ioc-json my_case_iocs.json
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
    parser.add_argument("--case-ioc-json", default="",
                        help="Path to a case-specific findings/IOC JSON file to ingest")
    parser.add_argument("--load-rocba", action="store_true",
                        help="Load the built-in ROCBA-2020 case IOCs (shorthand for that case)")
    parser.add_argument("--ioc-csv", default=None,
                        help="Optional path to custom IOC CSV to ingest (columns: type,value,description,tags)")
    parser.add_argument("--abuseipdb-csv", default=None,
                        help="Optional path to AbuseIPDB bulk blacklist CSV")
    parser.add_argument("--case-history-dir", default="",
                        help="Optional directory containing findings.json files from past cases")
    args = parser.parse_args()

    from rag.knowledge_base import ForensicKnowledgeBase
    kb = ForensicKnowledgeBase()
    initial_count = kb.get_stats()["total_documents"]
    logger.info(f"Starting RAG seeding. Current document count: {initial_count}")

    total = 0

    # ── MITRE ATT&CK + Hunt Evil baseline ─────────────────────────────────
    if not args.skip_mitre:
        logger.info("Ingesting MITRE ATT&CK Enterprise framework...")
        from rag.ingest.mitre_attack import ingest as ingest_mitre
        n = ingest_mitre(args.mitre_path)
        logger.info(f"  + {n} MITRE ATT&CK techniques")
        total += n
    else:
        logger.info("Skipping MITRE ATT&CK ingestion (--skip-mitre)")

    # ── Case-specific IOC JSON ─────────────────────────────────────────────
    if args.case_ioc_json:
        from pathlib import Path
        if Path(args.case_ioc_json).exists():
            from rag.ingest.case_history import ingest_findings_json
            n = ingest_findings_json(args.case_ioc_json)
            logger.info(f"  + {n} case documents from {args.case_ioc_json}")
            total += n
        else:
            logger.warning(f"Case IOC file not found: {args.case_ioc_json}")

    # ── ROCBA-2020 built-in IOCs (opt-in only) ─────────────────────────────
    if args.load_rocba:
        logger.info("Ingesting ROCBA-2020 case IOCs...")
        from rag.ingest.rocba_iocs import ingest_rocba_iocs
        n = ingest_rocba_iocs()
        logger.info(f"  + {n} ROCBA case documents")
        total += n

    # ── Custom IOC CSV ─────────────────────────────────────────────────────
    if args.ioc_csv:
        from rag.ingest.threat_intel import ingest_ioc_csv
        n = ingest_ioc_csv(args.ioc_csv)
        logger.info(f"  + {n} custom IOCs from {args.ioc_csv}")
        total += n

    # ── AbuseIPDB blacklist ────────────────────────────────────────────────
    if args.abuseipdb_csv:
        from rag.ingest.threat_intel import ingest_abuse_ipdb_blacklist
        n = ingest_abuse_ipdb_blacklist(args.abuseipdb_csv)
        logger.info(f"  + {n} AbuseIPDB malicious IPs from {args.abuseipdb_csv}")
        total += n

    # ── Past case findings ─────────────────────────────────────────────────
    if args.case_history_dir:
        from rag.ingest.case_history import ingest_all_cases
        n = ingest_all_cases(args.case_history_dir)
        logger.info(f"  + {n} items from case history in {args.case_history_dir}")
        total += n

    final_count = kb.get_stats()["total_documents"]
    logger.info(
        f"RAG seeding complete. New documents this run: {total}. "
        f"Database now contains {final_count} documents."
    )
    print(f"\nRAG knowledge base ready: {final_count} documents indexed.")


if __name__ == "__main__":
    main()
