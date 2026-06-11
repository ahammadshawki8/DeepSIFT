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

With pre-existing Protocol SIFT baseline for comparison:
    python3 demo.py \\
        --image /cases/ROCBA/Rocba-Memory.raw \\
        --baseline /cases/ROCBA-BASELINE/analysis/findings.json

Outputs:
    analysis/findings.json          ← DeepSIFT investigation results
    analysis/forensic_audit.log     ← Chain-of-custody log
    exports/                        ← Raw tool outputs (SHA-256 indexed)
    docs/accuracy_report.html       ← Visual comparison (if --baseline provided)
"""
import argparse
import json
import logging
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("analysis/demo.log", mode="w"),
    ],
)
logger = logging.getLogger("deepsift.demo")


def _print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║           DeepSIFT — Zero-Hallucination Forensics        ║
║        AI-Driven Incident Response · SANS DFIR           ║
╚══════════════════════════════════════════════════════════╝
""")


def _seed_rag() -> bool:
    """Ensure RAG knowledge base is seeded. Returns True if ready."""
    try:
        from rag.knowledge_base import ForensicKnowledgeBase
        kb = ForensicKnowledgeBase()
        stats = kb.get_stats()
        count = stats["total_documents"]

        if count == 0:
            logger.info("RAG knowledge base is empty — seeding now (this may take a few minutes)...")
            from rag.ingest.mitre_attack import ingest as ingest_mitre
            n = ingest_mitre()
            logger.info(f"Ingested {n} MITRE ATT&CK techniques")

        # Always ensure ROCBA IOCs are loaded
        from rag.ingest.rocba_iocs import ingest_rocba_iocs
        ingest_rocba_iocs()

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

    try:
        from rag.knowledge_base import ForensicKnowledgeBase
        rag = ForensicKnowledgeBase()
    except Exception:
        rag = None

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
    print("\n" + "═" * 60)
    print("  INVESTIGATION FINDINGS")
    print("═" * 60)
    print(f"\nSummary: {findings.get('summary', 'N/A')}")

    procs = findings.get("suspicious_processes", [])
    if procs:
        print(f"\nSuspicious Processes ({len(procs)}):")
        for p in procs[:10]:
            print(f"  • {p}")

    iocs = findings.get("network_iocs", [])
    if iocs:
        print(f"\nNetwork IOCs ({len(iocs)}):")
        for ip in iocs[:10]:
            print(f"  • {ip}")

    mitre = findings.get("mitre_techniques", [])
    if mitre:
        print(f"\nMITRE ATT&CK Techniques ({len(mitre)}):")
        for t in mitre[:10]:
            print(f"  • {t}")

    print(f"\nConfidence: {findings.get('confidence', 'N/A')}")
    print("═" * 60 + "\n")


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
        print(f"\n✔ Comparison report: {output_path}")
    except Exception as e:
        logger.warning(f"Could not generate comparison report: {e}")


def main():
    _print_banner()

    parser = argparse.ArgumentParser(
        description="DeepSIFT end-to-end forensic investigation demo"
    )
    parser.add_argument("--image", required=True,
                        help="Path to memory image (.raw, .vmem, .mem)")
    parser.add_argument("--case-dir", default="./analysis",
                        help="Output directory (default: ./analysis)")
    parser.add_argument("--disk-image", default="",
                        help="Optional disk image path for full artifact analysis")
    parser.add_argument("--evidence-mount", default="",
                        help="Optional mounted evidence path for EZ Tools")
    parser.add_argument("--baseline", default="",
                        help="Protocol SIFT findings.json path for comparison report")
    parser.add_argument("--ground-truth",
                        default="benchmark/ground_truth/rocba_ground_truth.json",
                        help="Ground truth JSON for scoring (default: ROCBA ground truth)")
    parser.add_argument("--report-output", default="docs/accuracy_report.html",
                        help="Output path for HTML comparison report")
    parser.add_argument("--skip-rag", action="store_true",
                        help="Skip RAG seeding (faster, no threat intel enrichment)")
    args = parser.parse_args()

    # Validate image exists
    if not Path(args.image).exists():
        print(f"ERROR: Memory image not found: {args.image}")
        sys.exit(1)

    # Step 1: Seed RAG
    if not args.skip_rag:
        print("► Step 1/3: Seeding RAG knowledge base...")
        _seed_rag()
    else:
        print("► Step 1/3: Skipping RAG (--skip-rag)")

    # Step 2: Run investigation
    print(f"► Step 2/3: Running investigation on {args.image}")
    findings = _run_investigation(
        image_path=args.image,
        case_dir=args.case_dir,
        disk_image_path=args.disk_image,
        evidence_mount_path=args.evidence_mount,
    )
    _print_findings_summary(findings)

    findings_path = str(Path(args.case_dir) / "findings.json")
    print(f"✔ Findings saved: {findings_path}")

    # Step 3: Generate comparison report
    print("► Step 3/3: Generating comparison report...")
    if args.baseline and Path(args.baseline).exists():
        _generate_comparison_report(
            deepsift_findings_path=findings_path,
            baseline_findings_path=args.baseline,
            ground_truth_path=args.ground_truth,
            output_path=args.report_output,
        )
    elif Path(args.ground_truth).exists():
        # Generate report comparing against empty baseline (DeepSIFT-only view)
        _generate_comparison_report(
            deepsift_findings_path=findings_path,
            baseline_findings_path="",
            ground_truth_path=args.ground_truth,
            output_path=args.report_output,
        )
    else:
        print("  (No baseline or ground truth found — skipping comparison report)")

    print("\n✔ Investigation complete.")
    print(f"  Findings:    {findings_path}")
    print(f"  Audit log:   analysis/forensic_audit.log")
    print(f"  Raw exports: exports/")
    if args.baseline:
        print(f"  Report:      {args.report_output}")
    print()


if __name__ == "__main__":
    main()
