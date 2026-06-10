"""Score system findings against ground truth to produce hallucination and accuracy metrics."""
from __future__ import annotations
import json
import re
from pathlib import Path


class BenchmarkScorer:
    def __init__(self, ground_truth_path: str):
        with open(ground_truth_path, encoding="utf-8") as f:
            self.ground_truth = json.load(f)

    def score(self, findings: dict) -> dict:
        """
        Score a findings dict (from finish_analysis / findings.json) against ground truth.

        Returns:
            true_positives: Criteria correctly identified
            false_positives: Claims made without evidence basis
            missed_artifacts: Ground truth items not found
            hallucinations: Claims explicitly contradicted by ground truth
            accuracy_score: TP / (TP + FP + missed) as float 0-1
            hallucination_rate: hallucinations / total_claims as float 0-1
        """
        must_identify = self.ground_truth.get("scoring_criteria", {}).get("must_identify", [])
        should_not_hallucinate = self.ground_truth.get("scoring_criteria", {}).get("should_not_hallucinate", [])

        summary_text = str(findings).lower()

        tp = self._count_matches(must_identify, summary_text)
        missed = len(must_identify) - tp
        hallucinations = self._detect_hallucinations(findings, should_not_hallucinate)
        fp = len(hallucinations)

        total_claims = len(must_identify) + fp
        accuracy = tp / total_claims if total_claims > 0 else 0.0

        all_claims = self._extract_all_claims(findings)
        hall_rate = fp / len(all_claims) if all_claims else 0.0

        return {
            "true_positives": tp,
            "false_positives": fp,
            "missed_artifacts": missed,
            "hallucinations": fp,
            "hallucination_details": hallucinations,
            "accuracy_score": round(accuracy, 3),
            "hallucination_rate": round(hall_rate, 3),
            "must_identify_coverage": f"{tp}/{len(must_identify)}",
        }

    def _count_matches(self, criteria: list[str], text: str) -> int:
        count = 0
        for criterion in criteria:
            keywords = criterion.lower().split()
            if all(kw in text for kw in keywords):
                count += 1
        return count

    def _detect_hallucinations(self, findings: dict, anti_hallucination_rules: list[str]) -> list[str]:
        """Flag findings that match known-bad hallucination patterns."""
        detected = []
        findings_text = str(findings).lower()
        for rule in anti_hallucination_rules:
            keywords = rule.lower().split()
            if all(kw in findings_text for kw in keywords[:3]):
                detected.append(rule)
        return detected

    def _extract_all_claims(self, findings: dict) -> list[str]:
        claims = []
        for key in ["suspicious_processes", "network_iocs", "mitre_techniques", "timeline"]:
            v = findings.get(key, [])
            if isinstance(v, list):
                claims.extend(str(item) for item in v)
        if findings.get("summary"):
            sentences = re.split(r"[.!?]", findings["summary"])
            claims.extend(s.strip() for s in sentences if s.strip())
        return claims

    def compare(self, baseline_score: dict, our_score: dict) -> dict:
        """Compute improvement metrics between two scored runs."""
        return {
            "tp_improvement": our_score["true_positives"] - baseline_score["true_positives"],
            "fp_reduction": baseline_score["false_positives"] - our_score["false_positives"],
            "hallucination_reduction": baseline_score["hallucinations"] - our_score["hallucinations"],
            "hallucination_rate_reduction": round(
                baseline_score["hallucination_rate"] - our_score["hallucination_rate"], 3
            ),
            "accuracy_improvement": round(
                our_score["accuracy_score"] - baseline_score["accuracy_score"], 3
            ),
        }
