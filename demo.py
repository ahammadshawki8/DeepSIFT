#!/usr/bin/env python3
"""
DeepSIFT end-to-end demonstration script.

Usage on SIFT Workstation:
    python3 demo.py --image /cases/ROCBA/Rocba-Memory.raw

With disk image (full analysis):
    python3 demo.py \\
        --image /cases/ROCBA/Rocba-Memory.raw \\
        --disk-image /cases/ROCBA/Rocba-Disk.E01 \\
        --evidence-mount /mnt/evidence

With Protocol SIFT baseline comparison:
    python3 demo.py \\
        --image /cases/ROCBA/Rocba-Memory.raw \\
        --baseline /cases/ROCBA-BASELINE/analysis/findings.json \\
        --ground-truth benchmark/ground_truth/rocba_ground_truth.json

With case-specific IOCs loaded into RAG:
    python3 demo.py \\
        --image /cases/ROCBA/Rocba-Memory.raw \\
        --case-ioc-json rag/ingest/rocba_iocs.py

Outputs:
    <case-dir>/findings.json         <- DeepSIFT investigation results
    analysis/forensic_audit.log      <- Chain-of-custody log
    exports/                         <- Raw tool outputs (SHA-256 indexed)
    docs/accuracy_report.html        <- Visual comparison (if --baseline + --ground-truth provided)
"""
import argparse
import json
import logging
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

# logging is configured inside main() after output dirs are created
logger = logging.getLogger("deepsift.demo")


def _print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║           DeepSIFT — Zero-Hallucination Forensics        ║
║        AI-Driven Incident Response · SANS DFIR           ║
╚══════════════════════════════════════════════════════════╝
""")


def _seed_rag(case_ioc_json: str = "") -> bool:
    """
    Ensure RAG knowledge base is seeded with MITRE ATT&CK.
    Optionally load case-specific IOCs from a JSON file.
    Returns True if RAG is ready.
    """
    try:
        from rag.knowledge_base import ForensicKnowledgeBase
        kb = ForensicKnowledgeBase()
        stats = kb.get_stats()
        count = stats["total_documents"]

        if count == 0:
            logger.info("RAG knowledge base is empty — seeding MITRE ATT&CK (this may take a few minutes)...")
            from rag.ingest.mitre_attack import ingest as ingest_mitre
            n = ingest_mitre()
            logger.info(f"Ingested {n} MITRE ATT&CK techniques")

        # Load case-specific IOCs if a JSON file was provided
        if case_ioc_json and Path(case_ioc_json).exists():
            logger.info(f"Loading case-specific IOCs from {case_ioc_json}...")
            try:
                from rag.ingest.case_history import ingest_findings_json
                n = ingest_findings_json(case_ioc_json)
                logger.info(f"Ingested {n} case-specific documents")
            except Exception as e:
                logger.warning(f"Case IOC ingestion failed: {e}")
        elif case_ioc_json:
            logger.warning(f"Case IOC file not found: {case_ioc_json}")

        stats = kb.get_stats()
        logger.info(f"RAG ready: {stats['total_documents']} documents indexed")
        return True

    except ImportError as e:
        logger.warning(f"RAG pipeline not available ({e}). Continuing without threat intel enrichment.")
        return False
    except Exception as e:
        logger.warning(f"RAG seeding failed: {e}. Continuing without threat intel.")
        return False


def _run_investigation(
    image_path: str,
    case_dir: str,
    disk_image_path: str = "",
    evidence_mount_path: str = "",
) -> dict:
    """Run the multi-agent forensic investigation."""
    Path(case_dir).mkdir(parents=True, exist_ok=True)

    rag = None
    try:
        from rag.knowledge_base import ForensicKnowledgeBase
        rag = ForensicKnowledgeBase()
    except Exception:
        pass

    from agents.orchestrator import ForensicOrchestrator
    orchestrator = ForensicOrchestrator(rag=rag)

    logger.info(f"Starting investigation: {image_path}")
    start = time.time()

    findings = orchestrator.investigate(
        image_path=image_path,
        case_dir=case_dir,
        disk_image_path=disk_image_path,
        evidence_mount_path=evidence_mount_path,
    )

    elapsed = time.time() - start
    logger.info(f"Investigation complete in {elapsed:.1f}s")
    return findings


def _print_findings_summary(findings: dict):
    print("\n" + "=" * 60)
    print("  INVESTIGATION FINDINGS")
    print("=" * 60)
    print(f"\nSummary: {findings.get('summary', 'N/A')}")

    procs = findings.get("suspicious_processes", [])
    if procs:
        print(f"\nSuspicious Processes ({len(procs)}):")
        for p in procs[:10]:
            print(f"  * {p}")

    iocs = findings.get("network_iocs", [])
    if iocs:
        print(f"\nNetwork IOCs ({len(iocs)}):")
        for ip in iocs[:10]:
            print(f"  * {ip}")

    mitre = findings.get("mitre_techniques", [])
    if mitre:
        print(f"\nMITRE ATT&CK Techniques ({len(mitre)}):")
        for t in mitre[:10]:
            print(f"  * {t}")

    print(f"\nConfidence: {findings.get('confidence', 'N/A')}")
    print("=" * 60 + "\n")


def _generate_comparison_report(
    deepsift_findings_path: str,
    baseline_findings_path: str,
    ground_truth_path: str,
    output_path: str,
):
    """Generate visual HTML comparison between DeepSIFT and Protocol SIFT."""
    try:
        from benchmark.reports.html_report import generate_from_files
        generate_from_files(
            baseline_findings_path=baseline_findings_path,
            deepsift_findings_path=deepsift_findings_path,
            ground_truth_path=ground_truth_path,
            output_path=output_path,
        )
        logger.info(f"Comparison report written to {output_path}")
        print(f"\n  Comparison report: {output_path}")
    except Exception as e:
        logger.warning(f"Could not generate comparison report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="DeepSIFT end-to-end forensic investigation demo"
    )
    parser.add_argument("--image", required=True,
                        help="Path to memory image (.raw, .vmem, .mem)")
    parser.add_argument("--case-dir", default="./analysis",
                        help="Output directory for findings (default: ./analysis)")
    parser.add_argument("--disk-image", default="",
                        help="Optional disk image path for full artifact analysis")
    parser.add_argument("--evidence-mount", default="",
                        help="Optional mounted evidence path for EZ Tools")
    parser.add_argument("--baseline", default="",
                        help="Protocol SIFT findings.json path for comparison report")
    parser.add_argument("--ground-truth", default="",
                        help="Ground truth JSON for scoring (e.g. benchmark/ground_truth/rocba_ground_truth.json)")
    parser.add_argument("--report-output", default="docs/accuracy_report.html",
                        help="Output path for HTML comparison report")
    parser.add_argument("--case-ioc-json", default="",
                        help="Optional case-specific IOC JSON file to load into RAG")
    parser.add_argument("--skip-rag", action="store_true",
                        help="Skip RAG seeding (faster, no threat intel enrichment)")
    args = parser.parse_args()

    # Create output directories FIRST — before any logging setup that writes files
    Path(args.case_dir).mkdir(parents=True, exist_ok=True)
    Path("docs").mkdir(parents=True, exist_ok=True)

    # Set up logging after directories exist
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(str(Path(args.case_dir) / "demo.log"), mode="w"),
        ],
    )

    _print_banner()

    # Validate image exists
    if not Path(args.image).exists():
        print(f"ERROR: Memory image not found: {args.image}")
        sys.exit(1)

    # Step 1: Seed RAG
    if not args.skip_rag:
        print("Step 1/3: Seeding RAG knowledge base...")
        _seed_rag(case_ioc_json=args.case_ioc_json)
    else:
        print("Step 1/3: Skipping RAG (--skip-rag)")

    # Step 2: Run investigation
    print(f"Step 2/3: Running investigation on {args.image}")
    findings = _run_investigation(
        image_path=args.image,
        case_dir=args.case_dir,
        disk_image_path=args.disk_image,
        evidence_mount_path=args.evidence_mount,
    )
    _print_findings_summary(findings)

    # Save findings to the case directory (orchestrator also saves internally,
    # but we save the returned dict here to guarantee the file exists)
    findings_path = str(Path(args.case_dir) / "findings.json")
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"  Findings saved: {findings_path}")

    # Step 3: Generate comparison report
    print("Step 3/3: Generating comparison report...")
    if not args.ground_truth:
        print("  (No --ground-truth provided — skipping comparison report)")
    elif not Path(args.ground_truth).exists():
        print(f"  (Ground truth file not found: {args.ground_truth} — skipping)")
    else:
        baseline_path = args.baseline if (args.baseline and Path(args.baseline).exists()) else ""
        _generate_comparison_report(
            deepsift_findings_path=findings_path,
            baseline_findings_path=baseline_path,
            ground_truth_path=args.ground_truth,
            output_path=args.report_output,
        )

    print("\nInvestigation complete.")
    print(f"  Findings:    {findings_path}")
    print(f"  Audit log:   analysis/forensic_audit.log")
    print(f"  Raw exports: exports/")
    if args.ground_truth and Path(args.ground_truth).exists():
        print(f"  Report:      {args.report_output}")
    print()


if __name__ == "__main__":
    main()
