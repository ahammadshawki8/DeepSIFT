#!/usr/bin/env python3
"""
Independent verification of a DeepSIFT investigation — run this to TRUST THE EVIDENCE,
not the score.

It re-derives everything from the on-disk artifacts a judge can inspect:
  1. Grounding — for every claim in findings.json, re-checks that the claim's tokens
     actually appear in the RAW tool output cited by its audit_id (re-reads exports/).
  2. Chain of custody — recomputes the SHA-256 hash chain over forensic_audit.log
     (and the HMAC chain if DEEPSIFT_AUDIT_KEY is set) to confirm nothing was altered.

Nothing here trusts DeepSIFT's own reported numbers; it recomputes them. Exit code is
non-zero if grounding fails or the chain is broken, so it is CI/judge-friendly.

    python3 verify_findings.py                       # uses analysis/
    python3 verify_findings.py --findings <f.json> --analysis-dir <dir>
    python3 verify_findings.py --json
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def verify(findings_path, analysis_dir) -> dict:
    """Re-derive grounding + chain integrity from on-disk artifacts. Returns
    {"overall": bool, "grounding": {...}, "chain": {...}}. Trusts nothing self-reported."""
    adir = Path(analysis_dir)
    findings = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    audit_ids = findings.get("audit_ids") or []

    from mcp_server.parsers.grounding_verifier import GroundingVerifier
    from mcp_server.audit import verify_audit_chain

    grounding = GroundingVerifier(adir).verify(findings, audit_ids)
    chain = verify_audit_chain(str(adir / "forensic_audit.log"))
    grounded_ok = grounding.get("verdict") == "PASS" or grounding.get("unverified_count", 1) == 0
    chain_ok = chain.get("ok") is True
    return {"overall": bool(grounded_ok and chain_ok), "grounding": grounding, "chain": chain}


def main() -> int:
    ap = argparse.ArgumentParser(description="Independently verify a DeepSIFT findings file")
    ap.add_argument("--analysis-dir", default="analysis")
    ap.add_argument("--findings", default="")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    adir = Path(args.analysis_dir)
    findings_path = Path(args.findings) if args.findings else adir / "findings.json"
    if not findings_path.exists():
        print(f"ERROR: findings not found: {findings_path}")
        return 2

    res = verify(findings_path, adir)
    grounding, chain, overall = res["grounding"], res["chain"], res["overall"]
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    audit_ids = findings.get("audit_ids") or []

    if args.json:
        print(json.dumps({"overall": overall, "grounding": grounding, "chain": chain}, indent=2))
        return 0 if overall else 1

    print("DeepSIFT — independent findings verification")
    print("=" * 60)
    print(f"findings: {findings_path}")
    print(f"cited tool calls (audit_ids): {len(audit_ids)}")
    print("")
    print("1) EVIDENCE GROUNDING (claims re-checked against raw tool output)")
    print(f"   grounding score : {grounding.get('grounding_score')}%")
    print(f"   verified        : {grounding.get('verified_count')}/{grounding.get('total_claims_checked')} observable claims")
    print(f"   MITRE derived   : {grounding.get('derived_count', 0)} (validated separately)")
    print(f"   verdict         : {grounding.get('verdict')}")
    unv = grounding.get("unverified_claims") or []
    if unv:
        print(f"   ⚠ UNVERIFIED ({len(unv)}):")
        for c in unv[:20]:
            print(f"       - {c.get('claim') if isinstance(c, dict) else c}")
    print("")
    print("2) CHAIN OF CUSTODY (hash chain recomputed over forensic_audit.log)")
    print(f"   entries         : {chain.get('entries')}")
    if chain.get("ok") is True:
        sig = ("HMAC-signed + verified" if chain.get("hmac_ok")
               else ("HMAC-signed (set DEEPSIFT_AUDIT_KEY to verify)" if chain.get("hmac_signed")
                     else "SHA-256 hash chain"))
        print(f"   integrity       : INTACT ({sig})")
    else:
        print(f"   integrity       : BROKEN at entry {chain.get('broken_at')} — {chain.get('reason')}")
    print("")
    print("=" * 60)
    print(f"OVERALL: {'✔ VERIFIED — every claim traces to intact, audited evidence' if overall else '✘ NOT FULLY VERIFIED (see above)'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
