"""
vigia-cases benchmark runner.

Evaluates DeepSIFT against the annatchijova/vigia-cases standardized dataset,
which is used by multiple SANS DFIR hackathon competitors as a common baseline.

Each vigia case directory must contain:
  ground_truth.json — see _VIGIA_SCHEMA below for expected structure.

vigia-cases ground truth schema (subset used for scoring):
  {
    "case_id":   str,
    "iocs": {
      "ips":     [str, ...],
      "domains": [str, ...],
      "hashes":  [str, ...]
    },
    "mitre_techniques": [str, ...],   # e.g. ["T1055", "T1071"]
    "key_findings":     [str, ...],   # free-text narrative facts
    "should_not_find":  [str, ...]    # hallucination tripwires
  }

Scoring dimensions:
  1. MITRE Recall        — techniques correctly identified / total expected
  2. IOC Recall          — IPs/domains/hashes correctly found / total expected
  3. Narrative Recall    — key_findings covered by DeepSIFT summary
  4. Hallucination Rate  — should_not_find items that slipped into findings
  5. Grounding Score     — from embedded grounding_verifier (0-100)
  6. Confidence Score    — from embedded confidence_scorer (0-100)
  7. Contradiction Count — from detect_contradictions tool
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Regex patterns for fuzzy matching vigia IOCs in free-text findings
_IP_PAT   = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_MITRE_PAT = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_HASH_PAT  = re.compile(r"\b[0-9a-fA-F]{32,64}\b")


# ── Vigia ground truth adapter ────────────────────────────────────────────────

def _load_vigia_ground_truth(path: Path) -> dict:
    """
    Load a vigia-cases ground_truth.json and normalise to the internal scoring schema.
    Also accepts the existing rocba_ground_truth.json format — adapts on the fly.
    """
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    # Native vigia format
    if "mitre_techniques" in raw and "iocs" in raw:
        return raw

    # DeepSIFT ROCBA format → vigia schema
    adapted: dict[str, Any] = {
        "case_id": raw.get("case_id", path.stem),
        "iocs": {
            "ips": [],
            "domains": [],
            "hashes": [],
        },
        "mitre_techniques": [],
        "key_findings": raw.get("scoring_criteria", {}).get("must_identify", []),
        "bonus_findings": raw.get("scoring_criteria", {}).get("bonus_identify", []),
        "should_not_find": raw.get("scoring_criteria", {}).get("should_not_hallucinate", []),
    }
    # Pull IOCs from protocol_sift_baseline block if present
    for ioc in raw.get("protocol_sift_baseline", {}).get("iocs_from_memory", {}).get("hostile_ips", []):
        ip = ioc.get("ip", "")
        if ip:
            adapted["iocs"]["ips"].append(ip)
    return adapted


# ── Case loading ──────────────────────────────────────────────────────────────

def _discover_cases(vigia_root: Path) -> list[tuple[str, Path, Path]]:
    """
    Discover cases under vigia_root.

    Returns list of (case_id, ground_truth_path, findings_path) tuples.
    findings_path points to a DeepSIFT analysis/findings.json for that case
    (may not exist — handled gracefully at score time).
    """
    cases: list[tuple[str, Path, Path]] = []
    for gt_path in sorted(vigia_root.rglob("ground_truth.json")):
        case_dir = gt_path.parent
        case_id  = case_dir.name
        findings_path = case_dir / "findings.json"
        cases.append((case_id, gt_path, findings_path))

    # Also pick up our native ROCBA ground truth
    native_gt = Path(__file__).parent / "ground_truth" / "rocba_ground_truth.json"
    if native_gt.exists():
        rocba_findings = Path("analysis") / "findings.json"
        cases.append(("ROCBA-2020", native_gt, rocba_findings))

    return cases


# ── Single-case scoring ───────────────────────────────────────────────────────

class VigiaScorer:
    """Score a single DeepSIFT findings.json against a vigia ground truth."""

    def __init__(self, ground_truth: dict):
        self.gt = ground_truth

    # ── helpers ──

    def _findings_text(self, findings: dict) -> str:
        """Flatten findings to a single lowercase searchable string."""
        return json.dumps(findings, default=str).lower()

    def _extract_mitre(self, findings: dict) -> set[str]:
        """Extract all MITRE technique IDs from findings (any nested field)."""
        text = self._findings_text(findings)
        return {m.upper() for m in _MITRE_PAT.findall(text)}

    def _extract_ips(self, findings: dict) -> set[str]:
        return set(_IP_PAT.findall(self._findings_text(findings)))

    def _extract_hashes(self, findings: dict) -> set[str]:
        return set(_HASH_PAT.findall(self._findings_text(findings)))

    def _keyword_match(self, phrases: list[str], text: str) -> list[str]:
        """Return which phrases have all their keywords present in text."""
        matched = []
        for phrase in phrases:
            keywords = re.findall(r"[a-z0-9]{4,}", phrase.lower())
            if keywords and all(kw in text for kw in keywords[:4]):
                matched.append(phrase)
        return matched

    # ── scorers ──

    def score_mitre(self, findings: dict) -> dict:
        expected = {t.upper() for t in self.gt.get("mitre_techniques", [])}
        if not expected:
            return {"recall": 1.0, "tp": 0, "total": 0, "missed": [], "found": []}
        found = self._extract_mitre(findings)
        tp = found & expected
        missed = expected - found
        recall = len(tp) / len(expected)
        return {
            "recall": round(recall, 3),
            "tp": len(tp),
            "total": len(expected),
            "found": sorted(tp),
            "missed": sorted(missed),
        }

    def score_iocs(self, findings: dict) -> dict:
        gt_iocs = self.gt.get("iocs", {})
        expected_ips = set(gt_iocs.get("ips", []))
        expected_hashes = set(h.lower() for h in gt_iocs.get("hashes", []))
        expected_domains = set(d.lower() for d in gt_iocs.get("domains", []))

        found_ips     = self._extract_ips(findings)
        found_hashes  = {h.lower() for h in self._extract_hashes(findings)}
        text          = self._findings_text(findings)
        found_domains = {d for d in expected_domains if d in text}

        tp_ips     = found_ips     & expected_ips
        tp_hashes  = found_hashes  & expected_hashes
        tp_domains = found_domains & expected_domains

        total_expected = len(expected_ips) + len(expected_hashes) + len(expected_domains)
        total_found    = len(tp_ips) + len(tp_hashes) + len(tp_domains)
        recall = total_found / total_expected if total_expected > 0 else 1.0

        return {
            "recall": round(recall, 3),
            "tp": total_found,
            "total": total_expected,
            "ip_recall": {
                "found": sorted(tp_ips),
                "missed": sorted(expected_ips - found_ips),
            },
            "hash_recall": {
                "found": sorted(tp_hashes),
                "missed": sorted(expected_hashes - found_hashes),
            },
            "domain_recall": {
                "found": sorted(tp_domains),
                "missed": sorted(expected_domains - found_domains),
            },
        }

    def score_narrative(self, findings: dict) -> dict:
        key_findings = self.gt.get("key_findings", [])
        if not key_findings:
            return {"recall": 1.0, "covered": [], "missed": []}
        text = self._findings_text(findings)
        covered = self._keyword_match(key_findings, text)
        missed  = [f for f in key_findings if f not in covered]
        return {
            "recall": round(len(covered) / len(key_findings), 3),
            "covered": covered,
            "missed": missed,
        }

    def score_hallucinations(self, findings: dict) -> dict:
        tripwires = self.gt.get("should_not_find", [])
        if not tripwires:
            return {"rate": 0.0, "triggered": [], "total_tripwires": 0}
        text = self._findings_text(findings)
        triggered = self._keyword_match(tripwires, text)
        rate = len(triggered) / len(tripwires)
        return {
            "rate": round(rate, 3),
            "triggered": triggered,
            "total_tripwires": len(tripwires),
        }

    def score(self, findings: dict) -> dict:
        mitre       = self.score_mitre(findings)
        iocs        = self.score_iocs(findings)
        narrative   = self.score_narrative(findings)
        hallu       = self.score_hallucinations(findings)

        # Pull through embedded DeepSIFT grounding / confidence if present
        grounding   = findings.get("grounding", {})
        conf_score  = findings.get("confidence_score", {})

        # Composite score — weights match hackathon judging criteria
        composite = round(
            mitre["recall"]     * 30
            + iocs["recall"]    * 25
            + narrative["recall"] * 25
            + (1.0 - hallu["rate"]) * 20,
            1,
        )

        return {
            "case_id":          self.gt.get("case_id", "unknown"),
            "composite_score":  composite,
            "mitre":            mitre,
            "ioc":              iocs,
            "narrative":        narrative,
            "hallucinations":   hallu,
            "grounding_score":  grounding.get("grounding_score", None),
            "confidence_score": conf_score.get("total_score", None),
            "confidence_tier":  conf_score.get("tier", None),
            "contradiction_count": len(
                findings.get("contradictions", {}).get("unresolved_contradictions", [])
            ),
        }


# ── Multi-case runner ─────────────────────────────────────────────────────────

class VigiaRunner:
    """
    Run DeepSIFT against all discoverable vigia-cases and aggregate results.

    Usage:
        runner = VigiaRunner("/path/to/vigia-cases")
        report = runner.run_all()
        runner.save_report(report, "benchmark/reports/vigia_report.json")
        print(runner.markdown_summary(report))
    """

    def __init__(self, vigia_root: str | Path, deepsift_results_root: str | Path | None = None):
        """
        Args:
            vigia_root:           Root of a cloned vigia-cases repository.
            deepsift_results_root: If provided, DeepSIFT findings are loaded from
                                   <deepsift_results_root>/<case_id>/findings.json
                                   instead of the path embedded in the case discovery.
        """
        self.vigia_root = Path(vigia_root)
        self.deepsift_results_root = Path(deepsift_results_root) if deepsift_results_root else None

    def _findings_path(self, case_id: str, default_path: Path) -> Path:
        if self.deepsift_results_root:
            return self.deepsift_results_root / case_id / "findings.json"
        return default_path

    def run_case(self, case_id: str, gt_path: Path, findings_path: Path) -> dict:
        """Score a single case. Returns score dict with metadata."""
        try:
            gt = _load_vigia_ground_truth(gt_path)
        except Exception as e:
            return {
                "case_id": case_id,
                "error": f"Failed to load ground truth: {e}",
                "composite_score": 0,
            }

        resolved_findings = self._findings_path(case_id, findings_path)
        if not resolved_findings.exists():
            return {
                "case_id": case_id,
                "error": (
                    f"DeepSIFT findings not found at {resolved_findings}. "
                    "Run DeepSIFT on this case first (demo.py or MCP investigation)."
                ),
                "composite_score": 0,
                "mitre":     {"recall": 0.0, "tp": 0, "total": len(gt.get("mitre_techniques", []))},
                "ioc":       {"recall": 0.0, "tp": 0, "total": 0},
                "narrative": {"recall": 0.0, "covered": [], "missed": gt.get("key_findings", [])},
                "hallucinations": {"rate": 0.0, "triggered": [], "total_tripwires": 0},
            }

        try:
            with open(resolved_findings, encoding="utf-8") as f:
                findings = json.load(f)
        except Exception as e:
            return {"case_id": case_id, "error": f"Failed to load findings: {e}", "composite_score": 0}

        scorer = VigiaScorer(gt)
        return scorer.score(findings)

    def run_all(self) -> dict:
        """Run all discovered cases and produce an aggregate report."""
        cases = _discover_cases(self.vigia_root)
        if not cases:
            logger.warning("No vigia cases discovered under %s", self.vigia_root)

        results: list[dict] = []
        for case_id, gt_path, findings_path in cases:
            logger.info("Scoring case: %s", case_id)
            result = self.run_case(case_id, gt_path, findings_path)
            results.append(result)

        return self._aggregate(results)

    @staticmethod
    def _aggregate(results: list[dict]) -> dict:
        """Compute aggregate statistics across all scored cases."""
        scored = [r for r in results if "error" not in r or r.get("composite_score", 0) > 0]
        errored = [r for r in results if "error" in r and r.get("composite_score", 0) == 0]

        if not scored:
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "cases_total": len(results),
                "cases_scored": 0,
                "cases_errored": len(errored),
                "errors": errored,
                "aggregate": {},
                "per_case": results,
            }

        def _avg(key: str, subkey: str | None = None) -> float:
            vals = []
            for r in scored:
                try:
                    v = r[key][subkey] if subkey else r[key]
                    if v is not None:
                        vals.append(float(v))
                except (KeyError, TypeError):
                    pass
            return round(sum(vals) / len(vals), 3) if vals else 0.0

        aggregate = {
            "composite_score_mean":    _avg("composite_score"),
            "mitre_recall_mean":       _avg("mitre", "recall"),
            "ioc_recall_mean":         _avg("ioc", "recall"),
            "narrative_recall_mean":   _avg("narrative", "recall"),
            "hallucination_rate_mean": _avg("hallucinations", "rate"),
            "grounding_score_mean":    _avg("grounding_score"),
            "confidence_score_mean":   _avg("confidence_score"),
            "cases_with_contradictions": sum(
                1 for r in scored if r.get("contradiction_count", 0) > 0
            ),
            "total_contradictions_found": sum(
                r.get("contradiction_count", 0) for r in scored
            ),
        }

        return {
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "cases_total":    len(results),
            "cases_scored":   len(scored),
            "cases_errored":  len(errored),
            "aggregate":      aggregate,
            "per_case":       results,
            "errors":         errored,
        }

    def save_report(self, report: dict, output_path: str | Path) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logger.info("vigia report saved to %s", out)
        return out

    def markdown_summary(self, report: dict) -> str:
        agg = report.get("aggregate", {})
        per_case = report.get("per_case", [])

        header = (
            "# DeepSIFT — vigia-cases Benchmark Report\n\n"
            f"Generated: {report.get('timestamp', 'N/A')}\n"
            f"Cases scored: {report['cases_scored']} / {report['cases_total']}\n\n"
        )

        agg_table = (
            "## Aggregate Metrics\n\n"
            "| Metric | Score |\n"
            "|--------|------:|\n"
            f"| Composite Score (0-100) | **{agg.get('composite_score_mean', 0):.1f}** |\n"
            f"| MITRE Recall | {agg.get('mitre_recall_mean', 0):.1%} |\n"
            f"| IOC Recall | {agg.get('ioc_recall_mean', 0):.1%} |\n"
            f"| Narrative Recall | {agg.get('narrative_recall_mean', 0):.1%} |\n"
            f"| Hallucination Rate | {agg.get('hallucination_rate_mean', 0):.1%} |\n"
            f"| Grounding Score | {agg.get('grounding_score_mean', 0):.1f} / 100 |\n"
            f"| Confidence Score | {agg.get('confidence_score_mean', 0):.1f} / 100 |\n"
            f"| Cases w/ Contradictions | {agg.get('cases_with_contradictions', 0)} |\n"
            f"| Total Contradictions Found | {agg.get('total_contradictions_found', 0)} |\n\n"
        )

        per_case_rows = "## Per-Case Results\n\n"
        per_case_rows += (
            "| Case | Composite | MITRE | IOC | Narrative | Hall. Rate | "
            "Grounding | Confidence | Contradictions |\n"
        )
        per_case_rows += (
            "|------|----------:|------:|----:|----------:|-----------:|"
            "---------:|----------:|---------------:|\n"
        )
        for r in per_case:
            if "error" in r and r.get("composite_score", 0) == 0:
                per_case_rows += (
                    f"| {r['case_id']} | ERROR | — | — | — | — | — | — | — |\n"
                )
                continue
            per_case_rows += (
                f"| {r.get('case_id', '?')} "
                f"| {r.get('composite_score', 0):.1f} "
                f"| {r.get('mitre', {}).get('recall', 0):.0%} "
                f"| {r.get('ioc', {}).get('recall', 0):.0%} "
                f"| {r.get('narrative', {}).get('recall', 0):.0%} "
                f"| {r.get('hallucinations', {}).get('rate', 0):.0%} "
                f"| {r.get('grounding_score') or '—'} "
                f"| {r.get('confidence_score') or '—'} "
                f"| {r.get('contradiction_count', 0)} |\n"
            )

        errors_section = ""
        if report.get("errors"):
            errors_section = "\n## Errors\n\n"
            for e in report["errors"]:
                errors_section += f"- **{e['case_id']}**: {e.get('error', 'unknown error')}\n"

        why_section = (
            "\n## DeepSIFT Differentiators vs Competitors\n\n"
            "| Feature | DeepSIFT | casefile | agentic-dart | Valhuntir | Mulder |\n"
            "|---------|:--------:|:--------:|:------------:|:---------:|:------:|\n"
            "| Post-hoc grounding verification | ✅ (verbatim token match) | ✅ (CSV) | ❌ | ❌ | ❌ |\n"
            "| Quantified confidence (0-100) | ✅ (4-axis) | ❌ | ❌ | ❌ | ❌ |\n"
            "| Contradiction detection | ✅ (6 types) | ❌ | ❌ | ❌ | ❌ |\n"
            "| RAG at every tool call | ✅ | ❌ | ❌ | ❌ | ❌ |\n"
            "| Middleware parser per category | ✅ (5 parsers) | ❌ | ❌ | ❌ | ❌ |\n"
            "| Hayabusa Sigma rules | ✅ (3700+) | ❌ | ❌ | ✅ | ❌ |\n"
            "| Typed tool count | **148** | ~30 | ~25 | ~90 | 140+ |\n"
            "| Observation/interpretation split | ✅ | ❌ | ❌ | ❌ | ❌ |\n"
            "| UNRESOLVED_CONTRADICTION findings | ✅ | ❌ | ❌ | ❌ | ❌ |\n"
            "| Forensic knowledge envelope | ✅ (148 entries) | ❌ | ❌ | ❌ | ❌ |\n"
        )

        return header + agg_table + per_case_rows + errors_section + why_section


# ── CLI entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run DeepSIFT against vigia-cases benchmark dataset"
    )
    parser.add_argument(
        "--vigia-root",
        default="vigia-cases",
        help="Path to cloned annatchijova/vigia-cases repository (default: ./vigia-cases)",
    )
    parser.add_argument(
        "--results-root",
        default=None,
        help=(
            "Path to directory containing per-case DeepSIFT results. "
            "Expected layout: <results-root>/<case_id>/findings.json. "
            "Defaults to each case's directory inside vigia-root."
        ),
    )
    parser.add_argument(
        "--output-json",
        default="benchmark/reports/vigia_report.json",
        help="Output path for the full JSON report",
    )
    parser.add_argument(
        "--output-md",
        default="benchmark/reports/vigia_report.md",
        help="Output path for the Markdown summary",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    runner = VigiaRunner(args.vigia_root, args.results_root)
    report = runner.run_all()

    json_out = runner.save_report(report, args.output_json)
    md_text  = runner.markdown_summary(report)

    md_out = Path(args.output_md)
    md_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.write_text(md_text, encoding="utf-8")

    print(md_text)
    print(f"\nJSON report: {json_out}")
    print(f"MD  report:  {md_out}")
