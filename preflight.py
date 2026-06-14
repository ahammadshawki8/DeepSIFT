#!/usr/bin/env python3
"""
DeepSIFT preflight — verify which forensic tools are operational in THIS environment.

Run this first (especially before a demo/judging) to see exactly what is installed and
what each missing binary would affect. Tools backed by a missing binary degrade to a
clear "unavailable" status; they never crash an investigation.

    python3 preflight.py            # human-readable table
    python3 preflight.py --json     # machine-readable report
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp_server.preflight import check_dependencies, format_report  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="DeepSIFT environment preflight check")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    args = ap.parse_args()
    rep = check_dependencies()
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(format_report(rep))
    # Non-zero exit if nothing is operational at all (useful for CI/setup scripts).
    return 0 if rep["dependency_groups_available"] > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
