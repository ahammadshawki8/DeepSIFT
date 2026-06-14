#!/usr/bin/env python3
"""Side-by-side scoring of any case: Protocol SIFT vs DeepSIFT.

Scores two findings.json files against a case's ground-truth file and prints the
actual numbers (must-identify coverage, hallucinations, accuracy). For the
DeepSIFT run it also re-checks grounding against the cited raw evidence.
Case-agnostic — point it at whichever ground-truth/findings files you want.

Usage:
    python3 benchmark/compare.py \
        --protocol-sift <protocol_sift_findings.json> \
        --deepsift      analysis/findings.json \
        --ground-truth  benchmark/ground_truth/<case>_ground_truth.json \
        --html          reports/<case>_accuracy_report.html    # optional
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from benchmark.scorer import BenchmarkScorer  # noqa: E402


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, OSError, ValueError) as e:
        print(f"  ! could not load {path}: {e}")
        return {}


def _grounding(findings: dict) -> str:
    """Re-verify grounding for a run that carries audit_ids (DeepSIFT only)."""
    ids = findings.get("audit_ids") or []
    if not ids:
        return "n/a (no audit trail — prompt-only baseline)"
    try:
        from mcp_server.parsers.grounding_verifier import GroundingVerifier
        r = GroundingVerifier().verify(findings, ids)
        return (f"{r['grounding_score']}%  "
                f"({r['verified_count']}/{r['total_claims_checked']} observable verified, "
                f"{r.get('derived_count', 0)} MITRE derived)  verdict={r['verdict']}")
    except Exception as e:  # noqa: BLE001
        return f"n/a ({type(e).__name__})"


def _row(label: str, a, b) -> None:
    print(f"  {label:<26} {str(a):<28} {str(b)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol-sift", default="benchmark/baselines/protocol_sift_rocba_findings.json")
    ap.add_argument("--deepsift", default="analysis/findings.json")
    ap.add_argument("--ground-truth", default="benchmark/ground_truth/rocba_ground_truth.json")
    ap.add_argument("--html", default="")
    ap.add_argument("--title", default="", help="Case label for the report header "
                    "(falls back to the ground-truth case_name, then 'BENCHMARK').")
    args = ap.parse_args()

    scorer = BenchmarkScorer(args.ground_truth)
    gt = json.load(open(args.ground_truth, encoding="utf-8"))
    must_total = len(gt.get("scoring_criteria", {}).get("must_identify", []))

    psift = _load(args.protocol_sift)
    dsift = _load(args.deepsift)
    ps = scorer.score(psift) if psift else None
    ds = scorer.score(dsift) if dsift else None

    title = args.title or gt.get("case_name") or "BENCHMARK"
    print("\n" + "=" * 84)
    print(f"  {title} — Protocol SIFT  vs  DeepSIFT".center(84))
    print("=" * 84)
    _row("metric", "PROTOCOL SIFT", "DEEPSIFT")
    print("  " + "-" * 80)
    if ps and ds:
        _row(f"must-identify (/{must_total})", ps["must_identify_coverage"], ds["must_identify_coverage"])
        _row("accuracy_score (0-1)", ps["accuracy_score"], ds["accuracy_score"])
        _row("hallucinations", ps["hallucinations"], ds["hallucinations"])
        _row("hallucination_rate", ps["hallucination_rate"], ds["hallucination_rate"])
        _row("grounding", _grounding(psift), "")
        _row("", "", _grounding(dsift))
        print("  " + "-" * 80)
        print("  matched criteria:")
        print(f"    Protocol SIFT: {ps['matched_criteria'] or '[]'}")
        print(f"    DeepSIFT     : {ds['matched_criteria'] or '[]'}")
        if ds["hallucination_details"] or ps["hallucination_details"]:
            print("  hallucination details:")
            print(f"    Protocol SIFT: {ps['hallucination_details']}")
            print(f"    DeepSIFT     : {ds['hallucination_details']}")
        winner = "DeepSIFT" if ds["true_positives"] > ps["true_positives"] else (
                 "Protocol SIFT" if ps["true_positives"] > ds["true_positives"] else "tie")
        print("  " + "-" * 80)
        print(f"  must-identify winner: {winner}")
    else:
        print("  ! one or both findings files missing — nothing to compare")
    print("=" * 84 + "\n")

    if args.html:
        from benchmark.reports.html_report import generate_from_files
        generate_from_files(args.protocol_sift, args.deepsift, args.ground_truth, args.html)
        print(f"  HTML report written to {args.html}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
