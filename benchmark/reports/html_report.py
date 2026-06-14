"""
Rich HTML comparison report: Protocol SIFT vs DeepSIFT.

Generates a standalone HTML file with visual diff showing:
- Side-by-side findings comparison
- Color-coded true positives / false positives / missed / hallucinations
- MITRE ATT&CK badges per finding
- Scoring summary with improvement metrics
- Audit trail section
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path


def _badge(tid: str, name: str) -> str:
    """Render a MITRE ATT&CK technique badge."""
    tid = str(tid)
    url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"
    return (
        f'<a href="{url}" target="_blank" class="badge">'
        f'<span class="tid">{tid}</span> {name}</a>'
    )


# technique_id -> human name, harvested from the same rule table the auto-mapper uses,
# so a findings list of bare IDs (['T1039', ...]) still renders named badges instead of
# the unhelpful "T1039 T1039".
# Common technique names not necessarily present in the auto-mapper rule table, so a
# findings list of bare IDs still renders a readable label rather than "T#### T####".
_COMMON_TECHNIQUE_NAMES = {
    "T1005": "Data from Local System",
    "T1039": "Data from Network Shared Drive",
    "T1074.001": "Local Data Staging",
    "T1135": "Network Share Discovery",
    "T1560.001": "Archive via Utility",
    "T1567.002": "Exfiltration to Cloud Storage",
    "T1052.001": "Exfiltration over USB",
    "T1090.003": "Multi-hop Proxy",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1083": "File and Directory Discovery",
    "T1036": "Masquerading",
}


def _build_technique_names() -> dict[str, str]:
    names: dict[str, str] = dict(_COMMON_TECHNIQUE_NAMES)
    try:
        import mcp_server.parsers.mitre_auto_map as mm
        for attr in dir(mm):
            val = getattr(mm, attr)
            if isinstance(val, list):
                for row in val:
                    if isinstance(row, tuple) and len(row) == 3 and str(row[1]).startswith("T"):
                        names.setdefault(str(row[1]), str(row[2]))
    except Exception:
        pass
    return names


_TECHNIQUE_NAMES = _build_technique_names()


def _mitre_pair(item) -> tuple[str, str]:
    """Normalise a mitre_techniques entry into (technique_id, display_name).

    Entries arrive in two shapes across the two systems: a bare string
    ('T1567.002' or 'T1567.002 — Exfiltration to Cloud Storage'), or a dict with
    varying keys ({'id'/'technique_id'/'tid'/'technique': ..., 'name'/'description': ...}).
    """
    if isinstance(item, dict):
        tid = (item.get("id") or item.get("technique_id") or item.get("tid")
               or item.get("technique") or "")
        name = item.get("name") or item.get("description") or ""
        if not tid:  # no explicit id field — fall back to any T#### in the values
            import re
            m = re.search(r"T\d{4}(?:\.\d{3})?", str(item))
            tid = m.group() if m else str(item)
        return str(tid), str(name or _TECHNIQUE_NAMES.get(str(tid), tid))
    s = str(item).strip()
    # Bare "T1039" / "T1039 — Name": split id from any trailing name, else look it up.
    import re
    m = re.match(r"(T\d{4}(?:\.\d{3})?)\s*[—:-]?\s*(.*)$", s)
    if m:
        tid, rest = m.group(1), m.group(2).strip()
        return tid, rest or _TECHNIQUE_NAMES.get(tid, tid)
    return s, s


def _score_bar(score: float, label: str, color: str) -> str:
    pct = round(score * 100)
    return (
        f'<div class="score-label">{label}</div>'
        f'<div class="score-bar-wrap">'
        f'  <div class="score-bar" style="width:{pct}%;background:{color}"></div>'
        f'  <span class="score-pct">{pct}%</span>'
        f'</div>'
    )


def generate_comparison_html(
    baseline_findings: dict,
    deepsift_findings: dict,
    baseline_score: dict,
    deepsift_score: dict,
    ground_truth: dict,
    output_path: str = "docs/accuracy_report.html",
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    case_name = ground_truth.get("case_name", ground_truth.get("case_id", "Unknown Case"))

    must_identify = ground_truth.get("scoring_criteria", {}).get("must_identify", [])
    should_not = ground_truth.get("scoring_criteria", {}).get("should_not_hallucinate", [])

    b_tp = baseline_score.get("true_positives", 0)
    b_fp = baseline_score.get("false_positives", 0)
    b_miss = baseline_score.get("missed_artifacts", len(must_identify))
    b_hall = baseline_score.get("hallucinations", 0)
    b_acc = baseline_score.get("accuracy_score", 0.0)

    d_tp = deepsift_score.get("true_positives", 0)
    d_fp = deepsift_score.get("false_positives", 0)
    d_miss = deepsift_score.get("missed_artifacts", len(must_identify))
    d_hall = deepsift_score.get("hallucinations", 0)
    d_acc = deepsift_score.get("accuracy_score", 0.0)

    b_summary = baseline_findings.get("summary", "No summary available")
    d_summary = deepsift_findings.get("summary", "No summary available")

    b_procs = baseline_findings.get("suspicious_processes", [])
    d_procs = deepsift_findings.get("suspicious_processes", [])
    b_iocs = baseline_findings.get("network_iocs", [])
    d_iocs = deepsift_findings.get("network_iocs", [])
    b_mitre = baseline_findings.get("mitre_techniques", [])
    d_mitre = deepsift_findings.get("mitre_techniques", [])

    mitre_badges_b = " ".join(_badge(*_mitre_pair(t)) for t in b_mitre) if b_mitre else "<em>None</em>"
    mitre_badges_d = " ".join(_badge(*_mitre_pair(t)) for t in d_mitre) if d_mitre else "<em>None</em>"

    # Required findings table rows. Criteria may be dicts ({"name","groups"}) or
    # legacy strings; reuse the scorer's authoritative match results rather than
    # re-deriving them here (keeps the table consistent with the headline numbers).
    def _label(c):
        return c.get("name", str(c)) if isinstance(c, dict) else str(c)

    b_matched = set(baseline_score.get("matched_criteria", []))
    d_matched = set(deepsift_score.get("matched_criteria", []))
    criteria_rows = ""
    for criterion in must_identify:
        label = _label(criterion)
        b_cell = '<td class="found">✔ Found</td>' if label in b_matched else '<td class="missed">✘ Missed</td>'
        d_cell = '<td class="found">✔ Found</td>' if label in d_matched else '<td class="missed">✘ Missed</td>'
        criteria_rows += f"<tr><td>{label}</td>{b_cell}{d_cell}</tr>"

    # Should-not-hallucinate table rows (a rule "fires" only if the scorer detected it).
    b_hall_names = set(baseline_score.get("hallucination_details", []))
    d_hall_names = set(deepsift_score.get("hallucination_details", []))
    hall_rows = ""
    for rule in should_not:
        label = _label(rule)
        b_cell = '<td class="hallucinated">⚠ Hallucinated</td>' if label in b_hall_names else '<td class="clean">✔ Clean</td>'
        d_cell = '<td class="hallucinated">⚠ Hallucinated</td>' if label in d_hall_names else '<td class="clean">✔ Clean</td>'
        hall_rows += f"<tr><td>{label}</td>{b_cell}{d_cell}</tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeepSIFT Accuracy Report — {case_name}</title>
<style>
  :root {{
    --green: #27ae60; --red: #e74c3c; --orange: #e67e22;
    --blue: #2980b9; --dark: #2c3e50; --light: #ecf0f1; --mid: #95a5a6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f5f6fa; color: #333; }}
  header {{ background: var(--dark); color: white; padding: 32px 40px; }}
  header h1 {{ font-size: 2rem; margin-bottom: 6px; }}
  header p {{ color: #bdc3c7; font-size: 0.9rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
  h2 {{ color: var(--dark); border-left: 4px solid var(--blue); padding-left: 12px;
        margin: 32px 0 16px; font-size: 1.3rem; }}
  /* Score cards */
  .scorecard-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 32px; }}
  .scorecard {{ background: white; border-radius: 8px; padding: 24px; box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
  .scorecard h3 {{ font-size: 1.1rem; color: var(--dark); margin-bottom: 16px; }}
  .scorecard.baseline {{ border-top: 4px solid var(--orange); }}
  .scorecard.deepsift  {{ border-top: 4px solid var(--green); }}
  .metric-row {{ display: flex; justify-content: space-between; padding: 8px 0;
                 border-bottom: 1px solid #f0f0f0; font-size: 0.95rem; }}
  .metric-row:last-child {{ border-bottom: none; }}
  .metric-val {{ font-weight: bold; }}
  .val-good {{ color: var(--green); }}
  .val-bad  {{ color: var(--red); }}
  /* Improvement banner */
  .banner {{ background: var(--green); color: white; border-radius: 8px; padding: 20px 28px;
             margin-bottom: 32px; display: flex; gap: 40px; flex-wrap: wrap; }}
  .banner-item {{ text-align: center; }}
  .banner-item .big {{ font-size: 2rem; font-weight: bold; }}
  .banner-item .lbl {{ font-size: 0.8rem; opacity: 0.9; }}
  /* Score bars */
  .score-label {{ font-size: 0.85rem; color: #666; margin-top: 8px; }}
  .score-bar-wrap {{ display: flex; align-items: center; gap: 8px; }}
  .score-bar {{ height: 18px; border-radius: 4px; transition: width .3s; }}
  .score-pct {{ font-weight: bold; font-size: 0.9rem; }}
  /* Side-by-side */
  .split {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }}
  .panel {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
  .panel h4 {{ font-size: 1rem; margin-bottom: 12px; color: var(--dark); }}
  .panel.baseline h4 {{ color: var(--orange); }}
  .panel.deepsift h4  {{ color: var(--green); }}
  .summary-text {{ font-size: 0.9rem; line-height: 1.5; color: #555; }}
  /* Lists */
  .ioc-list {{ list-style: none; }}
  .ioc-list li {{ background: #f8f9fa; border-radius: 4px; padding: 4px 8px;
                  margin: 4px 0; font-size: 0.85rem; font-family: monospace; }}
  /* Badges */
  .badge {{ display: inline-block; background: #2980b9; color: white; border-radius: 4px;
            padding: 2px 7px; font-size: 0.75rem; text-decoration: none; margin: 2px; }}
  .badge:hover {{ background: #1a6ea8; }}
  .tid {{ font-weight: bold; }}
  /* Tables */
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; background: white;
           border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.08);
           margin-bottom: 24px; }}
  th {{ background: var(--dark); color: white; padding: 12px 16px; text-align: left; }}
  td {{ padding: 10px 16px; border-bottom: 1px solid #f0f0f0; }}
  tr:last-child td {{ border-bottom: none; }}
  .found {{ color: var(--green); font-weight: bold; }}
  .missed {{ color: var(--red); font-weight: bold; }}
  .clean {{ color: var(--green); }}
  .hallucinated {{ color: var(--red); font-weight: bold; }}
  /* Why section */
  .why-grid {{ display: grid; grid-template-columns: repeat(auto-fill,minmax(260px,1fr));
               gap: 16px; margin-bottom: 32px; }}
  .why-card {{ background: white; border-radius: 8px; padding: 20px;
               box-shadow: 0 2px 8px rgba(0,0,0,.08); border-left: 4px solid var(--blue); }}
  .why-card h4 {{ color: var(--dark); font-size: 0.95rem; margin-bottom: 8px; }}
  .why-card p {{ font-size: 0.85rem; color: #666; line-height: 1.4; }}
  footer {{ text-align: center; color: #aaa; padding: 32px; font-size: 0.8rem; }}
</style>
</head>
<body>
<header>
  <h1>DeepSIFT Accuracy Report</h1>
  <p>Protocol SIFT vs DeepSIFT — {case_name} &nbsp;|&nbsp; Generated: {ts}</p>
</header>
<div class="container">

  <h2>Score Summary</h2>
  <div class="scorecard-grid">
    <div class="scorecard baseline">
      <h3>Protocol SIFT (Baseline)</h3>
      <div class="metric-row"><span>Must-Identify Found</span>
        <span class="metric-val val-bad">{b_tp} / {len(must_identify)}</span></div>
      <div class="metric-row"><span>Missed Artifacts</span>
        <span class="metric-val val-bad">{b_miss}</span></div>
      <div class="metric-row"><span>Hallucinations</span>
        <span class="metric-val {'val-bad' if b_hall else 'val-good'}">{b_hall}</span></div>
      <div class="metric-row"><span>False Positives</span>
        <span class="metric-val {'val-bad' if b_fp else 'val-good'}">{b_fp}</span></div>
      <div class="metric-row"><span>Accuracy Score</span>
        <span class="metric-val val-bad">{b_acc:.0%}</span></div>
      {_score_bar(b_acc, "Accuracy", "#e67e22")}
    </div>
    <div class="scorecard deepsift">
      <h3>DeepSIFT (Our System)</h3>
      <div class="metric-row"><span>Must-Identify Found</span>
        <span class="metric-val {'val-good' if d_tp >= b_tp else 'val-bad'}">{d_tp} / {len(must_identify)}</span></div>
      <div class="metric-row"><span>Missed Artifacts</span>
        <span class="metric-val {'val-good' if d_miss <= b_miss else 'val-bad'}">{d_miss}</span></div>
      <div class="metric-row"><span>Hallucinations</span>
        <span class="metric-val {'val-good' if d_hall == 0 else 'val-bad'}">{d_hall}</span></div>
      <div class="metric-row"><span>False Positives</span>
        <span class="metric-val {'val-good' if d_fp <= b_fp else 'val-bad'}">{d_fp}</span></div>
      <div class="metric-row"><span>Accuracy Score</span>
        <span class="metric-val {'val-good' if d_acc >= b_acc else 'val-bad'}">{d_acc:.0%}</span></div>
      {_score_bar(d_acc, "Accuracy", "#27ae60")}
    </div>
  </div>

  <h2>Side-by-Side Findings</h2>
  <div class="split">
    <div class="panel baseline">
      <h4>Protocol SIFT Summary</h4>
      <p class="summary-text">{b_summary}</p>
    </div>
    <div class="panel deepsift">
      <h4>DeepSIFT Summary</h4>
      <p class="summary-text">{d_summary}</p>
    </div>
  </div>

  <div class="split">
    <div class="panel baseline">
      <h4>Suspicious Processes ({len(b_procs)})</h4>
      <ul class="ioc-list">
        {"".join(f"<li>{p}</li>" for p in b_procs) or "<li><em>None reported</em></li>"}
      </ul>
    </div>
    <div class="panel deepsift">
      <h4>Suspicious Processes ({len(d_procs)})</h4>
      <ul class="ioc-list">
        {"".join(f"<li>{p}</li>" for p in d_procs) or "<li><em>None reported</em></li>"}
      </ul>
    </div>
  </div>

  <div class="split">
    <div class="panel baseline">
      <h4>Network IOCs ({len(b_iocs)})</h4>
      <ul class="ioc-list">
        {"".join(f"<li>{ip}</li>" for ip in b_iocs) or "<li><em>None reported</em></li>"}
      </ul>
    </div>
    <div class="panel deepsift">
      <h4>Network IOCs ({len(d_iocs)})</h4>
      <ul class="ioc-list">
        {"".join(f"<li>{ip}</li>" for ip in d_iocs) or "<li><em>None reported</em></li>"}
      </ul>
    </div>
  </div>

  <div class="split">
    <div class="panel baseline">
      <h4>MITRE ATT&CK Techniques</h4>
      <div>{mitre_badges_b}</div>
    </div>
    <div class="panel deepsift">
      <h4>MITRE ATT&CK Techniques</h4>
      <div>{mitre_badges_d}</div>
    </div>
  </div>

  <h2>Required Findings Coverage</h2>
  <table>
    <thead>
      <tr><th>Required Finding</th><th>Protocol SIFT</th><th>DeepSIFT</th></tr>
    </thead>
    <tbody>{criteria_rows}</tbody>
  </table>

  <h2>Hallucination Check</h2>
  <table>
    <thead>
      <tr><th>Should NOT Claim</th><th>Protocol SIFT</th><th>DeepSIFT</th></tr>
    </thead>
    <tbody>{hall_rows}</tbody>
  </table>

  <h2>Why DeepSIFT Reduces Hallucinations</h2>
  <div class="why-grid">
    <div class="why-card">
      <h4>Structured Parsing</h4>
      <p>Raw Volatility/log2timeline output (10k+ lines) is converted to typed JSON by Python parsers before the LLM sees a single byte. The LLM reasons about structured data, not raw text.</p>
    </div>
    <div class="why-card">
      <h4>Typed MCP Functions</h4>
      <p>31 separate typed functions — one per tool action. The agent cannot call an invalid plugin name or guess parameters. Architectural enforcement, not prompt-based.</p>
    </div>
    <div class="why-card">
      <h4>Python-Side Anomaly Detection</h4>
      <p>The Hunt Evil baseline (31 Windows processes) runs in Python code. Masquerade detection uses Levenshtein distance ≤ 2. Claude sees pre-computed suspicious flags, never raw pslist rows.</p>
    </div>
    <div class="why-card">
      <h4>MITRE ATT&CK Auto-Mapping</h4>
      <p>Every suspicious finding is automatically tagged with ATT&CK technique IDs by rule-based Python code. No LLM inference required for technique identification.</p>
    </div>
    <div class="why-card">
      <h4>RAG Threat Intel Injection</h4>
      <p>MITRE ATT&CK techniques, IOC feeds, and past case findings are semantically searched and injected per finding. Claude's analysis is grounded in curated knowledge, not training-time memory.</p>
    </div>
    <div class="why-card">
      <h4>Evidence Protection</h4>
      <p>The MCP server exposes zero write operations on /cases/, /mnt/, or /media/ paths. Chain-of-custody is SHA-256-logged per tool call. Evidence integrity is architectural, not prompt-based.</p>
    </div>
    <div class="why-card">
      <h4>Disk Artifact Tools</h4>
      <p>10 Windows Artifact tools (event logs, shimcache, amcache, MFT, prefetch, LNK, jump lists, recycle bin, registry, IP reputation) fill the gap Protocol SIFT leaves entirely unanalyzed.</p>
    </div>
    <div class="why-card">
      <h4>Hidden Process Detection</h4>
      <p>scan_hidden_processes automatically diffs pslist vs psscan to find DKOM-hidden processes — a manual step in Protocol SIFT that is easy to overlook or misread from raw output.</p>
    </div>
  </div>

</div>
<footer>DeepSIFT — Find Evil! Hackathon, SANS DFIR &nbsp;|&nbsp; {case_name} &nbsp;|&nbsp; {ts}</footer>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html, encoding="utf-8")
    return html


def generate_from_files(
    baseline_findings_path: str,
    deepsift_findings_path: str,
    ground_truth_path: str = "benchmark/ground_truth/rocba_ground_truth.json",
    output_path: str = "docs/accuracy_report.html",
) -> str:
    """Load findings from JSON files and generate the HTML report."""
    from benchmark.scorer import BenchmarkScorer

    scorer = BenchmarkScorer(ground_truth_path)
    with open(ground_truth_path, encoding="utf-8") as f:
        gt = json.load(f)

    def _load(path: str) -> dict:
        if not path:
            return {}
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, OSError, ValueError):
            return {}

    b_findings = _load(baseline_findings_path)
    d_findings = _load(deepsift_findings_path)

    b_score = scorer.score(b_findings) if b_findings else _empty_score(gt)
    d_score = scorer.score(d_findings) if d_findings else _empty_score(gt)

    return generate_comparison_html(b_findings, d_findings, b_score, d_score, gt, output_path)


def _empty_score(gt: dict) -> dict:
    must = gt.get("scoring_criteria", {}).get("must_identify", [])
    return {
        "true_positives": 0, "false_positives": 0,
        "missed_artifacts": len(must), "hallucinations": 0,
        "hallucination_details": [], "accuracy_score": 0.0,
        "hallucination_rate": 0.0, "must_identify_coverage": f"0/{len(must)}",
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate HTML comparison report")
    parser.add_argument("--baseline", required=True, help="Protocol SIFT findings.json")
    parser.add_argument("--ours", required=True, help="DeepSIFT findings.json")
    parser.add_argument("--ground-truth", default="benchmark/ground_truth/rocba_ground_truth.json")
    parser.add_argument("--output", default="docs/accuracy_report.html")
    args = parser.parse_args()

    generate_from_files(args.baseline, args.ours, args.ground_truth, args.output)
    print(f"Report written to {args.output}")
