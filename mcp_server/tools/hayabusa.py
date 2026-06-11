"""
Hayabusa Sigma rule engine — Priority 3.

Hayabusa applies 3,700+ community-vetted Sigma rules to Windows Event Logs
and returns structured detections with severity levels and MITRE ATT&CK tags.

This single tool multiplies DeepSIFT's event-log detection surface by orders of
magnitude compared to the 30 event IDs filtered by parse_event_logs. It closes
the gap against Valhuntir, Mulder, and VERDICT which all use Hayabusa or Sigma.

Installation on SIFT:
    sudo apt install hayabusa     # or download from
    https://github.com/Yamato-Security/hayabusa/releases

Environment variable: HAYABUSA_CMD (default: hayabusa)
"""
from __future__ import annotations
import csv as _csv
import json
import subprocess
from io import StringIO
from pathlib import Path

from mcp_server.config import EXPORTS_DIR, MAX_TOOL_TIMEOUT
from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter
from mcp_server.parsers.forensic_knowledge import wrap_response
from mcp_server.parsers.mitre_auto_map import map_finding_to_techniques
import os

HAYABUSA_CMD = os.getenv("HAYABUSA_CMD", "hayabusa").split()

# Severity ordering for sorting
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}


def _run_hayabusa(cmd: list[str]) -> tuple[str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_TOOL_TIMEOUT * 3)
        log_tool_execution("parse_hayabusa", cmd, result.stdout, error=result.stderr)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        msg = "hayabusa timed out — try reducing the evtx_dir size"
        log_tool_execution("parse_hayabusa", cmd, "", error=msg)
        return "", msg
    except FileNotFoundError:
        msg = (
            "hayabusa not found. Install from "
            "https://github.com/Yamato-Security/hayabusa/releases "
            "and set HAYABUSA_CMD in .env"
        )
        log_tool_execution("parse_hayabusa", cmd, "", error=msg)
        return "", msg


def _parse_hayabusa_csv(csv_text: str) -> list[dict]:
    """Parse Hayabusa CSV timeline output into structured dicts."""
    alerts: list[dict] = []
    try:
        reader = _csv.DictReader(StringIO(csv_text))
        for row in reader:
            # Normalise column names — Hayabusa versions vary
            def g(*keys: str) -> str:
                for k in keys:
                    for rk, rv in row.items():
                        if rk.lower().strip() == k.lower():
                            return rv or ""
                return ""

            severity = g("level", "severity").lower()
            alerts.append({
                "timestamp":      g("datetime", "timestamp", "time"),
                "computer":       g("computer", "hostname"),
                "channel":        g("channel"),
                "event_id":       g("eventid", "event id", "event_id"),
                "severity":       severity,
                "rule_title":     g("ruletitle", "rule title", "rule_title", "title"),
                "rule_id":        g("ruleid", "rule id"),
                "mitre_tactics":  g("mitreattack", "mitre attack", "tactics"),
                "mitre_techs":    g("mitretechniques", "mitre techniques", "techniques"),
                "details":        g("details", "description")[:300],
            })
    except Exception:
        pass
    return alerts


def _summarise_by_severity(alerts: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for a in alerts:
        s = a.get("severity", "unknown")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _extract_mitre_from_alerts(alerts: list[dict]) -> list[dict]:
    """Collect unique MITRE technique IDs from Hayabusa output."""
    seen: set[str] = set()
    techniques: list[dict] = []
    import re
    t_pat = re.compile(r"T\d{4}(?:\.\d{3})?")
    for alert in alerts:
        raw = alert.get("mitre_techs", "") + " " + alert.get("mitre_tactics", "")
        for tid in t_pat.findall(raw):
            if tid not in seen:
                seen.add(tid)
                techniques.append({
                    "technique_id": tid,
                    "source_rule": alert.get("rule_title", ""),
                    "severity": alert.get("severity", ""),
                })
    return techniques


def register_hayabusa_tools(mcp, rag=None):

    @mcp.tool()
    def parse_hayabusa(evtx_dir: str, min_severity: str = "medium") -> str:
        """
        Run Hayabusa against a directory of .evtx files using 3,700+ Sigma rules.

        Returns structured detections with severity, MITRE ATT&CK technique IDs,
        rule names, and timestamps — ordered critical-first.

        Hayabusa covers detection logic that would otherwise require manual review
        of thousands of event log entries. It surfaces:
        - Credential access (LSASS dumping, pass-the-hash, kerberoasting)
        - Lateral movement (PsExec, WMI, remote PowerShell)
        - Persistence (scheduled tasks, services, registry autoruns)
        - Defense evasion (log clearing, UAC bypass, AMSI bypass)
        - Execution (LOLBins, encoded PowerShell, suspicious child processes)

        Args:
            evtx_dir:     Path to directory containing .evtx files.
            min_severity: Minimum severity level to include.
                          Options: critical, high, medium, low, informational.
                          Default: medium (reduces noise).
        """
        output_file = str(EXPORTS_DIR / "hayabusa_output.csv")
        Path(EXPORTS_DIR).mkdir(parents=True, exist_ok=True)

        cmd = HAYABUSA_CMD + [
            "csv-timeline",
            "-d", evtx_dir,
            "-o", output_file,
            "--min-level", min_severity,
            "--no-wizard",
            "--quiet",
        ]
        stdout, stderr = _run_hayabusa(cmd)
        audit_id = get_last_audit_id()
        increment_tool_counter()

        # Try reading the output file; fall back to stdout
        csv_content = ""
        try:
            csv_content = Path(output_file).read_text(encoding="utf-8-sig", errors="replace")
        except (FileNotFoundError, OSError):
            csv_content = stdout

        if not csv_content.strip():
            error_msg = stderr or "No detections returned. Verify evtx_dir path and Hayabusa installation."
            return json.dumps({
                "error": error_msg,
                "audit_id": audit_id,
                "hint": "Run: hayabusa csv-timeline -d <evtx_dir> -o test.csv --no-wizard",
            })

        alerts = _parse_hayabusa_csv(csv_content)

        # Filter by minimum severity
        severity_order = _SEVERITY_ORDER.get(min_severity.lower(), 2)
        alerts = [
            a for a in alerts
            if _SEVERITY_ORDER.get(a.get("severity", "info"), 4) <= severity_order
        ]

        # Sort: critical first
        alerts.sort(key=lambda a: _SEVERITY_ORDER.get(a.get("severity", "info"), 4))

        severity_summary = _summarise_by_severity(alerts)
        mitre_techniques = _extract_mitre_from_alerts(alerts)

        # RAG enrichment for high-severity detections
        if rag:
            critical_high = [a for a in alerts if a.get("severity") in ("critical", "high")][:3]
            for alert in critical_high:
                try:
                    alert["threat_intel"] = rag.query(
                        f"sigma detection {alert.get('rule_title', '')} {alert.get('mitre_techs', '')}"
                    )
                except Exception:
                    pass

        data = {
            "total_detections": len(alerts),
            "severity_summary": severity_summary,
            "mitre_techniques": mitre_techniques,
            "sigma_rules_applied": "3,700+",
            "critical_and_high_alerts": [
                a for a in alerts if a.get("severity") in ("critical", "high")
            ][:50],
            "all_alerts": alerts[:300],
        }
        return wrap_response("parse_hayabusa", data, audit_id)

    @mcp.tool()
    def list_hayabusa_rules() -> str:
        """
        List all Hayabusa Sigma rules grouped by MITRE tactic.
        Useful for understanding detection coverage before running parse_hayabusa.
        """
        cmd = HAYABUSA_CMD + ["list-profiles"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return json.dumps({
                "output": result.stdout[:2000],
                "note": "Run parse_hayabusa to apply all rules against evtx files.",
            })
        except Exception as e:
            return json.dumps({"error": str(e), "note": "Hayabusa may not be installed."})
