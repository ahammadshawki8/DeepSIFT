"""Generate a rich comparison report from benchmark results (PDF via weasyprint)."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone


def generate_html_report(baseline_score: dict, our_score: dict, comparison: dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>DeepSIFT Accuracy Report</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; color: #222; }}
  h1 {{ color: #c0392b; }}
  h2 {{ color: #2c3e50; border-bottom: 2px solid #e74c3c; padding-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
  th {{ background: #2c3e50; color: white; padding: 10px; }}
  td {{ border: 1px solid #ddd; padding: 8px; text-align: center; }}
  .good {{ color: #27ae60; font-weight: bold; }}
  .bad {{ color: #e74c3c; font-weight: bold; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; }}
  .badge-green {{ background: #27ae60; color: white; }}
  .badge-red {{ background: #e74c3c; color: white; }}
</style>
</head>
<body>
<h1>DeepSIFT — Accuracy & Hallucination Reduction Report</h1>
<p>Generated: {ts}</p>

<h2>Side-by-Side Comparison</h2>
<table>
<tr><th>Metric</th><th>Protocol SIFT (Baseline)</th><th>DeepSIFT</th><th>Change</th></tr>
<tr><td>True Positives</td>
    <td>{baseline_score['true_positives']}</td>
    <td class="good">{our_score['true_positives']}</td>
    <td class="good">+{comparison['tp_improvement']}</td></tr>
<tr><td>False Positives</td>
    <td class="bad">{baseline_score['false_positives']}</td>
    <td class="good">{our_score['false_positives']}</td>
    <td class="good">-{comparison['fp_reduction']}</td></tr>
<tr><td>Hallucinations</td>
    <td class="bad">{baseline_score['hallucinations']}</td>
    <td class="good">{our_score['hallucinations']}</td>
    <td class="good">-{comparison['hallucination_reduction']}</td></tr>
<tr><td>Hallucination Rate</td>
    <td class="bad">{baseline_score['hallucination_rate']:.1%}</td>
    <td class="good">{our_score['hallucination_rate']:.1%}</td>
    <td class="good">-{comparison['hallucination_rate_reduction']:.1%}</td></tr>
<tr><td>Accuracy Score</td>
    <td>{baseline_score['accuracy_score']:.1%}</td>
    <td class="good">{our_score['accuracy_score']:.1%}</td>
    <td class="good">+{comparison['accuracy_improvement']:.1%}</td></tr>
</table>

<h2>Why DeepSIFT Reduces Hallucinations</h2>
<ul>
  <li><strong>Structured parsing</strong> — Raw tool output converted to typed JSON before LLM sees it</li>
  <li><strong>Typed MCP functions</strong> — Agent cannot call invalid plugins; each action is a distinct function</li>
  <li><strong>RAG threat intel</strong> — MITRE ATT&CK and threat actor profiles injected per finding</li>
  <li><strong>Python-side anomaly detection</strong> — Hunt Evil baseline comparison in code, not LLM inference</li>
  <li><strong>Architectural evidence protection</strong> — No write operations exposed on evidence paths</li>
</ul>
</body>
</html>"""


def save_pdf(baseline_score: dict, our_score: dict, comparison: dict, output_path: str) -> None:
    """Generate PDF report using weasyprint."""
    try:
        from weasyprint import HTML
    except ImportError:
        print("weasyprint not installed. Install with: pip install weasyprint")
        return

    html = generate_html_report(baseline_score, our_score, comparison)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html).write_pdf(output_path)
    print(f"PDF report saved to {output_path}")
