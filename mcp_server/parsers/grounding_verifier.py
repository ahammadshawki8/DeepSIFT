"""
Grounding Verifier — Priority 1 anti-hallucination mechanism.

Checks every claim in a findings report against the raw tool outputs that were
cited via audit_ids. Claims that cannot be traced to raw evidence are flagged
UNVERIFIED. A grounding_score of 100 means every claim is evidence-backed.

This directly answers casefile's verbatim CSV verification approach — claims
are checked against the actual bytes the tools returned, not just the parsed
summary the LLM read.
"""
from __future__ import annotations
import json
import re
from pathlib import Path


# Patterns that extract specific atomic facts from claim strings
_IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_PID_PATTERN = re.compile(r"\b\d{4,6}\b")
_MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_HASH_PATTERN = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_PE_PATTERN = re.compile(r"\b\w+\.(?:exe|dll|sys|bat|ps1|vbs|cmd|com|scr|hta)\b", re.IGNORECASE)


class GroundingVerifier:
    """
    Verifies that every factual claim in a findings report can be traced back
    to the raw tool outputs referenced by the investigation's audit_ids.
    """

    def __init__(self, analysis_dir: Path | None = None):
        if analysis_dir is None:
            from mcp_server.config import ANALYSIS_DIR
            analysis_dir = ANALYSIS_DIR
        self.audit_log_path = analysis_dir / "forensic_audit.log"

    # ── Public interface ───────────────────────────────────────────────────────

    def verify(self, findings: dict, audit_ids: list[str]) -> dict:
        """
        Verify all claims in `findings` against the raw outputs for `audit_ids`.

        Returns a verification report with grounding_score (0–100), per-claim
        VERIFIED/UNVERIFIED status, and a pass/fail verdict.
        """
        raw_corpus = self._build_corpus(audit_ids)
        verified: list[dict] = []
        unverified: list[dict] = []

        def _check(claim: str, claim_type: str) -> None:
            tokens = self._extract_tokens(claim, claim_type)
            if not tokens:
                # Cannot extract verifiable tokens — skip rather than mark unverified
                return
            for token in tokens:
                if self._token_in_corpus(token, raw_corpus):
                    verified.append({"claim": claim, "matched_token": token,
                                     "type": claim_type, "status": "VERIFIED"})
                    return
            unverified.append({"claim": claim, "tokens_checked": tokens,
                                "type": claim_type, "status": "UNVERIFIED"})

        # Check every verifiable category
        for proc in findings.get("suspicious_processes", []):
            _check(str(proc), "process")

        for ioc in findings.get("network_iocs", []):
            _check(str(ioc), "network_ioc")

        for tech in findings.get("mitre_techniques", []):
            _check(str(tech), "mitre_technique")

        # Check observation text for specific process/IP/file mentions
        for text_field in ("observation", "interpretation"):
            text = findings.get(text_field, "")
            if text:
                for m in _PE_PATTERN.finditer(text):
                    _check(m.group(), "pe_file_in_text")
                for m in _IP_PATTERN.finditer(text):
                    _check(m.group(), "ip_in_text")

        total = len(verified) + len(unverified)
        score = round((len(verified) / total * 100), 1) if total else 100.0
        # 100 = fully grounded; no claims = trivially grounded

        return {
            "grounding_score": score,
            "total_claims_checked": total,
            "verified_count": len(verified),
            "unverified_count": len(unverified),
            "verdict": "PASS" if len(unverified) == 0 else "FAIL",
            "unverified_claims": unverified,
            "verified_claims": verified[:30],  # cap for readability
            "corpus_sources": len(audit_ids),
            "interpretation": (
                f"Grounding score {score}% — {len(verified)}/{total} claims "
                f"traced to raw evidence. "
                + (
                    "All claims are evidence-backed."
                    if len(unverified) == 0
                    else f"{len(unverified)} claim(s) could not be traced — "
                         "review or remove before finalising the report."
                )
            ),
        }

    def verify_single_claim(self, claim: str, claim_type: str, audit_ids: list[str]) -> dict:
        """Check a single claim string against cited tool outputs."""
        raw_corpus = self._build_corpus(audit_ids)
        tokens = self._extract_tokens(claim, claim_type)
        for token in tokens:
            if self._token_in_corpus(token, raw_corpus):
                return {"claim": claim, "status": "VERIFIED", "matched_token": token}
        return {"claim": claim, "status": "UNVERIFIED", "tokens_checked": tokens}

    # ── Private helpers ────────────────────────────────────────────────────────

    def _build_corpus(self, audit_ids: list[str]) -> str:
        """Load and concatenate all raw tool outputs for the given audit_ids."""
        if not self.audit_log_path.exists():
            return ""

        # Build audit_id → raw_output_file mapping
        id_to_file: dict[str, str] = {}
        for line in self.audit_log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                entry = json.loads(line)
                aid = entry.get("audit_id", "")
                if aid in audit_ids:
                    id_to_file[aid] = entry.get("raw_output_file", "")
            except (json.JSONDecodeError, KeyError):
                continue

        corpus_parts: list[str] = []
        for aid in audit_ids:
            raw_file = id_to_file.get(aid, "")
            if raw_file and Path(raw_file).exists():
                try:
                    corpus_parts.append(
                        Path(raw_file).read_text(encoding="utf-8", errors="replace")
                    )
                except OSError:
                    pass

        return "\n".join(corpus_parts)

    def _extract_tokens(self, claim: str, claim_type: str) -> list[str]:
        """
        Extract the most specific verifiable atoms from a claim string.

        For IPs: use the IP address itself.
        For processes: use the executable name without path.
        For MITRE: use the technique ID.
        For general text: use the best matching pattern.
        """
        if claim_type == "network_ioc":
            # Extract IP address if present, else use full string
            ips = _IP_PATTERN.findall(claim)
            if ips:
                return ips
            return [claim.strip()] if claim.strip() else []

        if claim_type in ("process", "pe_file_in_text"):
            tokens: list[str] = []
            # Extract .exe/.dll name
            pe_names = _PE_PATTERN.findall(claim)
            tokens.extend(pe_names)
            # Extract PID if present
            pids = _PID_PATTERN.findall(claim)
            tokens.extend(pids)
            return tokens or [claim.strip()]

        if claim_type == "mitre_technique":
            mitre_ids = _MITRE_PATTERN.findall(claim)
            return mitre_ids or [claim.strip()]

        if claim_type == "ip_in_text":
            return _IP_PATTERN.findall(claim) or [claim.strip()]

        # Generic: try patterns in order
        for pat in (_MITRE_PATTERN, _IP_PATTERN, _PE_PATTERN, _HASH_PATTERN):
            hits = pat.findall(claim)
            if hits:
                return hits

        return [claim.strip()] if claim.strip() else []

    def _token_in_corpus(self, token: str, corpus: str) -> bool:
        """Case-insensitive substring check."""
        if not token or not corpus:
            return False
        return token.lower() in corpus.lower()
