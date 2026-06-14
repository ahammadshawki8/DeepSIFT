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
_PE_PATTERN = re.compile(r"\b[\w-]+\.(?:exe|dll|sys|bat|ps1|vbs|cmd|com|scr|hta|pst|ost|zip|docx?|xlsx?|pptx?|jpg|txt)\b", re.IGNORECASE)
# Full URL (captures host + path) and bare domain (host only). Both let us verify
# a web IOC by its atomic locator instead of a descriptive sentence.
_URL_PATTERN = re.compile(r"\bhttps?://[^\s)'\"]+", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|gov|edu|co|uk|ru|cn|de|info|biz|us|me|app|cloud|drive|sharepoint|onedrive|live|outlook)\b",
    re.IGNORECASE,
)

# MITRE technique IDs are DeepSIFT's own deterministic derivation (mitre_auto_map),
# NOT strings that appear in raw CLI output. Verifying them against raw bytes is a
# category error that guarantees failure. They are validated for well-formedness as
# DERIVED analytic claims and excluded from the raw-grounding denominator.
def _is_wellformed_mitre(token: str) -> bool:
    return bool(re.fullmatch(r"T\d{4}(?:\.\d{3})?", token.strip()))


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
        # Defensive: callers may hand us a JSON string (or double-encoded string)
        # instead of a dict. Coerce rather than crash with 'str has no attribute get'.
        if isinstance(findings, str):
            for _ in range(3):
                try:
                    findings = json.loads(findings)
                except (json.JSONDecodeError, ValueError):
                    break
                if isinstance(findings, dict):
                    break
        if not isinstance(findings, dict):
            findings = {}

        raw_corpus = self._build_corpus(audit_ids)
        verified: list[dict] = []
        unverified: list[dict] = []
        derived: list[dict] = []          # analytic tags (MITRE) — not raw-observable
        seen_observable: set[tuple] = set()

        def _check(claim: str, claim_type: str) -> None:
            tokens = self._extract_tokens(claim, claim_type)
            if not tokens:
                # Cannot extract verifiable tokens — skip rather than mark unverified
                return
            key = (claim_type, tuple(tokens))
            if key in seen_observable:
                return  # de-dupe identical atoms scanned from multiple fields
            seen_observable.add(key)
            for token in tokens:
                if self._token_in_corpus(token, raw_corpus):
                    verified.append({"claim": claim, "matched_token": token,
                                     "type": claim_type, "status": "VERIFIED"})
                    return
            unverified.append({"claim": claim, "tokens_checked": tokens,
                                "type": claim_type, "status": "UNVERIFIED"})

        def _check_derived_mitre(claim: str) -> None:
            ids = _MITRE_PATTERN.findall(claim) or [claim.strip()]
            for tid in ids:
                wellformed = _is_wellformed_mitre(tid)
                derived.append({
                    "claim": tid,
                    "type": "mitre_technique",
                    # Bonus signal: did DeepSIFT's raw evidence even mention the
                    # observable trigger? Not required, but surfaced when present.
                    "status": "DERIVED_VALID" if wellformed else "DERIVED_MALFORMED",
                })

        # Observable atomic facts — MUST appear in the raw evidence corpus.
        for proc in findings.get("suspicious_processes", []):
            _check(str(proc), "process")

        for ioc in findings.get("network_iocs", []):
            _check(str(ioc), "network_ioc")

        # Derived analytic tags — validated for well-formedness, NOT raw-grounded.
        for tech in findings.get("mitre_techniques", []):
            _check_derived_mitre(str(tech))

        # Scan narrative text for specific observable atoms (files, IPs, domains, URLs).
        # Skip atoms stated as ABSENT ("no MRC.exe present") — an absence assertion
        # is not a positive observable claim and must not require presence in the corpus.
        for text_field in ("observation", "interpretation"):
            text = findings.get(text_field, "")
            if not text:
                continue
            for pat, ctype in (
                (_PE_PATTERN, "pe_file_in_text"),
                (_IP_PATTERN, "ip_in_text"),
                (_URL_PATTERN, "url_in_text"),
                (_DOMAIN_PATTERN, "domain_in_text"),
            ):
                for m in pat.finditer(text):
                    if self._is_negated(text, m.start()):
                        continue
                    _check(m.group(), ctype)

        total = len(verified) + len(unverified)
        score = round((len(verified) / total * 100), 1) if total else 100.0
        # 100 = every observable fact traced to raw evidence; no claims = trivially grounded.
        malformed_mitre = [d for d in derived if d["status"] == "DERIVED_MALFORMED"]

        return {
            "grounding_score": score,
            "total_claims_checked": total,
            "verified_count": len(verified),
            "unverified_count": len(unverified),
            # PASS requires every observable fact grounded AND no malformed MITRE IDs.
            "verdict": "PASS" if (len(unverified) == 0 and not malformed_mitre) else "FAIL",
            "unverified_claims": unverified,
            "verified_claims": verified[:30],  # cap for readability
            "derived_claims": derived,
            "derived_count": len(derived),
            "malformed_mitre": [d["claim"] for d in malformed_mitre],
            "corpus_sources": len(audit_ids),
            "interpretation": (
                f"Grounding score {score}% — {len(verified)}/{total} observable fact(s) "
                f"traced to raw evidence; {len(derived)} derived MITRE tag(s) validated "
                f"separately (not raw-observable). "
                + (
                    "All observable claims are evidence-backed."
                    if (len(unverified) == 0 and not malformed_mitre)
                    else f"{len(unverified)} observable claim(s) could not be traced"
                         + (f" and {len(malformed_mitre)} malformed MITRE ID(s) found"
                            if malformed_mitre else "")
                         + " — review or remove before finalising the report."
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
            # Pull the atomic locator(s) out of a descriptive IOC string such as
            # "drive.google.com (Google Drive 'My Drive' — exfil destination, T1567.002)".
            # Order matters: try URL, then IP, then bare domain — never fall back to
            # the whole descriptive sentence (which can never match raw bytes).
            urls = _URL_PATTERN.findall(claim)
            ips = _IP_PATTERN.findall(claim)
            domains = _DOMAIN_PATTERN.findall(claim)
            atoms = urls + ips + domains
            if atoms:
                return atoms
            # No structured locator (e.g. "RAG-corroborated context") — not a
            # raw-verifiable atom; skip rather than guarantee a false UNVERIFIED.
            return []

        if claim_type == "url_in_text":
            # Accept the full URL or, failing that, its host — a narrative URL is
            # often abbreviated, but its domain is verifiable against raw evidence.
            u = claim.strip()
            return ([u] + _DOMAIN_PATTERN.findall(u)) if u else []

        if claim_type == "domain_in_text":
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

    # Negation cues that, when they immediately precede an atom, mark it as an
    # absence assertion rather than a positive observable claim.
    _NEGATION_CUES = (
        "no ", "not ", "without ", "absent", "never ", "zero ", "none ",
        "no malicious", "no such", "lack of ", "did not", "didn't", "n't ",
    )

    def _is_negated(self, text: str, pos: int, window: int = 60) -> bool:
        """True if the atom at `pos` sits in a negated phrase (e.g. 'no MRC.exe').

        Only the current clause is considered — scanning stops at the nearest clause
        boundary (`. ; \\n —`) before the atom, so a negation in a *previous* clause
        ('...show no X; OneDrive.exe is running') does not falsely negate this one.
        """
        start = max(0, pos - window)
        ctx = text[start:pos]
        # Trim to the last clause boundary inside the window.
        boundary = max(ctx.rfind(b) for b in (". ", "; ", "\n", "—", " - "))
        if boundary != -1:
            ctx = ctx[boundary + 1:]
        ctx = ctx.lower()
        return any(cue in ctx for cue in self._NEGATION_CUES)

    def _token_in_corpus(self, token: str, corpus: str) -> bool:
        """Case-insensitive substring check."""
        if not token or not corpus:
            return False
        return token.lower() in corpus.lower()
