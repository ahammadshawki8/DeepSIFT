"""Score system findings against ground truth to produce hallucination and accuracy metrics."""
from __future__ import annotations
import json
import re
from pathlib import Path


class BenchmarkScorer:
    def __init__(self, ground_truth_path: str):
        with open(ground_truth_path, encoding="utf-8") as f:
            self.ground_truth = json.load(f)
        self._last_findings: dict = {}

    @staticmethod
    def _hit(indicator: str, haystack: str) -> bool:
        """True if a single indicator matches the haystack.

        Two indicator forms, chosen per-indicator so any case (not just ROCBA) can
        express evidence in a representation-independent way:
          * 're:<pattern>'  — regular-expression match (case-insensitive). Use this
            when the SAME artifact can be written several ways, e.g. a Windows event
            written as '4624' OR '[Event 4624]' OR 'event id 4624', or a cloud host
            as 'onedrive.live.com' OR '<tenant>.sharepoint.com'. The matcher should
            recognise the evidence, not one tool's formatting.
          * literal          — case-insensitive substring test (back-compat default).
        A bad regex degrades gracefully to a literal substring test of the pattern.
        """
        ind = str(indicator)
        if ind.startswith("re:"):
            pat = ind[3:]
            try:
                return re.search(pat, haystack, re.IGNORECASE) is not None
            except re.error:
                return pat.lower() in haystack
        return ind.lower() in haystack

    @staticmethod
    def _leaf_strings(obj) -> list[str]:
        """Flatten a findings dict into individual lowercase leaf strings, so a
        criterion needing co-occurrence is tested within ONE artifact entry."""
        out: list[str] = []

        def walk(o):
            if isinstance(o, str):
                out.append(o.lower())
            elif isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, (list, tuple)):
                for v in o:
                    walk(v)
            elif o is not None:
                out.append(str(o).lower())
        walk(obj)
        return out

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

        self._last_findings = findings
        summary_text = str(findings).lower()

        tp, matched = self._count_matches(must_identify, summary_text)
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
            "matched_criteria": matched,
            "accuracy_score": round(accuracy, 3),
            "hallucination_rate": round(hall_rate, 3),
            "must_identify_coverage": f"{tp}/{len(must_identify)}",
        }

    def _count_matches(self, criteria: list, text: str) -> tuple[int, list[str]]:
        """Count satisfied must-identify criteria.

        Supports two criterion forms:
          * dict {"name", "groups": [[syn, ...], ...]} — satisfied when EACH group
            has at least one synonym present (indicator-based; the sound method).
          * str (legacy) — satisfied only if every whitespace-token appears. This
            requires verbatim presence of an entire descriptive sentence and so
            scores even a perfect analysis at 0; kept only for back-compat.
        """
        leaves = self._leaf_strings(self._last_findings) if self._last_findings else []
        count = 0
        matched: list[str] = []
        for criterion in criteria:
            if isinstance(criterion, dict):
                groups = criterion.get("groups", [])
                if criterion.get("co_occur"):
                    # Every group's synonym set must hit within ONE finding entry,
                    # so e.g. an incident DATE and an event/URL token must appear
                    # together — not be matched from two unrelated fields.
                    ok = bool(groups) and any(
                        all(any(self._hit(syn, leaf) for syn in group) for group in groups)
                        for leaf in leaves
                    )
                else:
                    ok = bool(groups) and all(
                        any(self._hit(syn, text) for syn in group) for group in groups
                    )
                label = criterion.get("name", str(criterion))
            else:
                keywords = str(criterion).lower().split()
                ok = all(kw in text for kw in keywords)
                label = criterion
            if ok:
                count += 1
                matched.append(label)
        return count, matched

    def _detect_hallucinations(self, findings: dict, anti_hallucination_rules: list) -> list[str]:
        """Flag findings that genuinely commit a forbidden (hallucinated) claim.

        Only PRECISE rules fire, so an accurate analysis is never falsely accused:
          * dict rule {"name", "groups", "co_occur"} — fires when each group's
            synonyms are present (optionally co-occurring in one finding entry).
          * str rule — descriptive guidance only; does NOT auto-fire (matching the
            first few words of a prose sentence produced false positives, e.g. any
            report mentioning 'network connections' tripped 'connections not observed').
        Real verbatim-grounding enforcement lives in parsers/grounding_verifier.py.
        """
        detected = []
        leaves = self._leaf_strings(findings)
        text = str(findings).lower()
        for rule in anti_hallucination_rules:
            if not isinstance(rule, dict):
                continue
            groups = rule.get("groups", [])
            if not groups:
                continue
            if rule.get("co_occur"):
                hit = any(
                    all(any(self._hit(s, leaf) for s in g) for g in groups)
                    for leaf in leaves
                )
            else:
                hit = all(any(self._hit(s, text) for s in g) for g in groups)
            if hit:
                detected.append(rule.get("name", str(rule)))
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
