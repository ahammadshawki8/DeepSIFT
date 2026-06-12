#!/usr/bin/env python3
"""
DeepSIFT examiner review — human-in-the-loop sign-off (chain of custody).

Findings produced by the agent are NOT final until a human examiner reviews each one
and signs a case manifest. The signature binds the findings file, the tamper-evident
audit chain, and the examiner's decisions together (mcp_server/custody.py).

Examples
--------
  # interactive review, prompt for passphrase
  python3 examiner_review.py --findings analysis/findings_agentic.json --examiner "J. Doe"

  # scripted (CI / batch): approve all after review, passphrase from env
  DEEPSIFT_EXAMINER_PASSPHRASE=... python3 examiner_review.py \
      --findings analysis/findings.json --examiner "J. Doe" --approve-all

  # verify a previously signed manifest (detects any tampering)
  python3 examiner_review.py verify --manifest analysis/case_manifest.signed.json
"""
import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from mcp_server.custody import build_manifest, write_signed_manifest, verify_signed_manifest

_REVIEWABLE = [
    ("suspicious_processes", "process"),
    ("network_iocs", "network IOC"),
    ("files_accessed", "file access / exfiltration"),
    ("cloud_services_used", "cloud usage"),
    ("downloads", "download"),
    ("mitre_techniques", "MITRE technique"),
    ("attack_chain", "attack-chain step"),
]


def _load_items(findings: dict) -> list[dict]:
    items = []
    for key, label in _REVIEWABLE:
        for v in findings.get(key, []) or []:
            items.append({"category": label, "item": str(v)})
    return items


def _get_passphrase(args) -> str:
    p = args.passphrase or os.getenv("DEEPSIFT_EXAMINER_PASSPHRASE")
    if not p:
        p = getpass.getpass("Examiner passphrase (used to sign — not stored): ")
    if not p:
        print("ERROR: a passphrase is required to sign the case manifest."); sys.exit(2)
    return p


def cmd_review(args):
    fp = Path(args.findings)
    if not fp.exists():
        print(f"ERROR: findings not found: {fp}"); sys.exit(1)
    findings = json.loads(fp.read_text())
    items = _load_items(findings)
    if not items:
        print("No reviewable findings in file."); sys.exit(1)

    print(f"\nExaminer review — {len(items)} findings from {fp}\n" + "=" * 60)
    decisions = []
    if args.decisions:
        decided = {d["item"]: d for d in json.loads(Path(args.decisions).read_text())}
        for it in items:
            d = decided.get(it["item"], {})
            decisions.append({**it, "decision": d.get("decision", "rejected"),
                              "reason": d.get("reason", "no decision supplied -> rejected")})
    elif args.approve_all:
        for it in items:
            decisions.append({**it, "decision": "approved",
                              "reason": "examiner reviewed and approved"})
    else:
        for i, it in enumerate(items, 1):
            print(f"\n[{i}/{len(items)}] ({it['category']}) {it['item']}")
            ans = input("  approve / reject / skip [a/r/s]: ").strip().lower()
            decision = {"a": "approved", "r": "rejected"}.get(ans, "rejected")
            reason = input("  reason: ").strip() or "(none)"
            decisions.append({**it, "decision": decision, "reason": reason})

    passphrase = _get_passphrase(args)
    manifest = build_manifest(str(fp), args.examiner, decisions)
    out = args.out or str(fp.parent / "case_manifest.signed.json")
    write_signed_manifest(manifest, passphrase, out)

    t = manifest["totals"]
    print("\n" + "=" * 60)
    print(f"Examiner:        {args.examiner}")
    print(f"Decisions:       {t['approved']} approved, {t['rejected']} rejected ({t['total']} total)")
    print(f"Audit chain:     {'INTACT' if manifest['audit_chain']['verified'] else 'BROKEN'} "
          f"({manifest['audit_chain']['entries']} entries)")
    print(f"Findings SHA256: {manifest['findings_sha256'][:16]}...")
    print(f"Signed manifest: {out}")
    print("=" * 60)


def cmd_verify(args):
    passphrase = _get_passphrase(args)
    r = verify_signed_manifest(args.manifest, passphrase)
    print(json.dumps(r, indent=2))
    sys.exit(0 if r["overall"] else 3)


def main():
    ap = argparse.ArgumentParser(description="DeepSIFT examiner review / sign-off")
    sub = ap.add_subparsers(dest="cmd")

    rv = sub.add_parser("review", help="review findings and sign (default)")
    vf = sub.add_parser("verify", help="verify a signed manifest")
    for p in (ap, rv):
        p.add_argument("--findings", default="analysis/findings.json")
        p.add_argument("--examiner", default=os.getenv("USER", "examiner"))
        p.add_argument("--approve-all", action="store_true")
        p.add_argument("--decisions", default="")
        p.add_argument("--passphrase", default="")
        p.add_argument("--out", default="")
    vf.add_argument("--manifest", required=True)
    vf.add_argument("--passphrase", default="")

    args = ap.parse_args()
    if args.cmd == "verify":
        cmd_verify(args)
    else:
        cmd_review(args)


if __name__ == "__main__":
    main()
