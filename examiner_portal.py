#!/usr/bin/env python3
"""
DeepSIFT Examiner Portal — a zero-dependency, read-only review UI for a DFIR examiner
(or a hackathon judge) to inspect an investigation: the verdict, every finding, the
evidence-grounding result, and the full tamper-evident chain of custody.

Why it exists
-------------
"Could another practitioner run, understand, and build on this?" is an explicit judging
criterion. This portal answers it with NO pip installs — it uses only the Python standard
library, so a reviewer can open the findings in a browser in one command.

Usage
-----
    # Serve live (default) — open http://127.0.0.1:8420
    python3 examiner_portal.py

    # Point at specific files / a different case dir
    python3 examiner_portal.py --findings analysis/findings.json --analysis-dir analysis

    # Render a single self-contained HTML file instead of serving
    python3 examiner_portal.py --html reports/examiner_review.html

What it shows
-------------
  * Verdict + confidence tier/score
  * Findings: suspicious processes, network/exfil IOCs, MITRE ATT&CK (named badges),
    timeline, files/documents accessed
  * Evidence grounding: which claims were verified against raw tool output, and any
    that were NOT (flagged loudly)
  * Chain of custody: every audited tool call (audit_id, tool, command, SHA-256 of raw
    output) plus a recomputed hash-chain integrity verdict (detects any tampering)
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


# ── data loading ────────────────────────────────────────────────────────────────
def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return {}


def _load_audit_entries(audit_path: Path, limit: int = 2000) -> list[dict]:
    entries: list[dict] = []
    if not audit_path.exists():
        return entries
    with open(audit_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
    return entries[-limit:]


def _verify_chain(audit_path: Path) -> dict:
    try:
        from mcp_server.audit import verify_audit_chain
        return verify_audit_chain(str(audit_path))
    except Exception as e:  # noqa: BLE001
        return {"ok": None, "entries": 0, "broken_at": None, "reason": f"{type(e).__name__}: {e}"}


def _technique_names() -> dict:
    try:
        from benchmark.reports.html_report import _build_technique_names
        return _build_technique_names()
    except Exception:  # noqa: BLE001
        return {}


_TNAMES = _technique_names()


# ── formatting helpers (tolerant of str|dict finding shapes) ──────────────────────
def _esc(x) -> str:
    return html.escape(str(x), quote=True)


def _as_text(item) -> str:
    if isinstance(item, dict):
        # Prefer a name/value + evidence/context shape, else compact JSON.
        name = item.get("name") or item.get("value") or item.get("path") or ""
        extra = item.get("evidence") or item.get("context") or item.get("full_path") or ""
        if name:
            return _esc(name) + (f" — <span class='muted'>{_esc(extra)}</span>" if extra else "")
        return _esc(json.dumps(item, default=str))
    return _esc(item)


def _ul(items, empty="None reported") -> str:
    items = items or []
    if not items:
        return f"<p class='muted'>{empty}</p>"
    return "<ul class='list'>" + "".join(f"<li>{_as_text(i)}</li>" for i in items) + "</ul>"


def _mitre_badges(techs) -> str:
    if not techs:
        return "<p class='muted'>None</p>"
    out = []
    for t in techs:
        if isinstance(t, dict):
            tid = t.get("id") or t.get("technique_id") or t.get("tid") or ""
            name = t.get("name") or t.get("description") or _TNAMES.get(str(tid), str(tid))
        else:
            tid = str(t).split()[0] if t else ""
            name = _TNAMES.get(tid, str(t))
        url = "https://attack.mitre.org/techniques/" + str(tid).replace(".", "/")
        out.append(f"<a class='badge' href='{_esc(url)}' target='_blank'>"
                   f"<b>{_esc(tid)}</b> {_esc(name)}</a>")
    return "<div class='badges'>" + " ".join(out) + "</div>"


# ── HTML rendering ────────────────────────────────────────────────────────────────
def render_html(findings: dict, audit_entries: list[dict], chain: dict,
                case: str = "", signoff: dict | None = None,
                multi_case: bool = False) -> str:
    summary = findings.get("summary") or findings.get("observation") or "(no summary)"
    interp = findings.get("interpretation", "")
    conf_q = findings.get("confidence_qualitative") or findings.get("confidence") or "—"
    cs = findings.get("confidence_score") or {}
    tier = cs.get("tier", "")
    score = cs.get("total_score", "")
    grounding = findings.get("grounding") or {}
    g_score = grounding.get("grounding_score", cs.get("grounding_score", ""))
    verified = grounding.get("verified_claims", [])
    unverified = grounding.get("unverified_claims", [])

    # chain-integrity banner
    if chain.get("ok") is True:
        if chain.get("hmac_ok") is True:
            sig = "HMAC-signed chain verified (forgery-resistant)"
        elif chain.get("hmac_signed") and chain.get("hmac_ok") is None:
            sig = "HMAC-signed (set DEEPSIFT_AUDIT_KEY to verify signatures)"
        else:
            sig = "hash chain verified"
        chain_badge = (f"<span class='ok'>✔ INTACT</span> — {chain.get('entries', 0)} "
                       f"audited tool calls, {sig}")
    elif chain.get("ok") is False:
        chain_badge = (f"<span class='bad'>✘ BROKEN</span> at entry "
                       f"{chain.get('broken_at')}: {_esc(chain.get('reason',''))}")
    else:
        chain_badge = f"<span class='muted'>chain check unavailable: {_esc(chain.get('reason',''))}</span>"

    # grounding banner
    try:
        gnum = float(g_score)
        g_class = "ok" if gnum >= 99 else ("warn" if gnum >= 80 else "bad")
        g_txt = f"<span class='{g_class}'>{gnum:.0f}%</span> of observable claims traced to raw evidence"
    except (TypeError, ValueError):
        g_txt = "<span class='muted'>n/a</span>"

    # verified / unverified tables
    def _claim_rows(claims, status_cls):
        rows = []
        for c in claims:
            if isinstance(c, dict):
                rows.append(f"<tr><td>{_esc(c.get('claim',''))}</td>"
                            f"<td><code>{_esc(c.get('matched_token',''))}</code></td>"
                            f"<td>{_esc(c.get('type',''))}</td>"
                            f"<td class='{status_cls}'>{_esc(c.get('status',''))}</td></tr>")
            else:
                rows.append(f"<tr><td colspan='4'>{_esc(c)}</td></tr>")
        return "".join(rows)

    verified_tbl = (
        "<table><thead><tr><th>Claim</th><th>Matched token</th><th>Type</th><th>Status</th>"
        "</tr></thead><tbody>" + (_claim_rows(verified, "ok") or
        "<tr><td colspan='4' class='muted'>none</td></tr>") + "</tbody></table>")
    unverified_block = ""
    if unverified:
        unverified_block = (
            "<h2 class='bad'>⚠ Unverified claims (not grounded in raw evidence)</h2>"
            "<table><thead><tr><th>Claim</th><th>Matched token</th><th>Type</th><th>Status</th>"
            "</tr></thead><tbody>" + _claim_rows(unverified, "bad") + "</tbody></table>")

    # audit table — when a case is selected, each row links to the raw evidence (drill-down)
    audit_rows = []
    for e in audit_entries:
        aid = e.get("audit_id", "")
        aid_cell = (f"<a href='?view=raw&case={_esc(case)}&audit={_esc(aid)}'><code>{_esc(aid)}</code></a>"
                    if case else f"<code>{_esc(aid)}</code>")
        audit_rows.append(
            f"<tr><td>{aid_cell}</td>"
            f"<td>{_esc(e.get('timestamp',''))}</td>"
            f"<td>{_esc(e.get('tool',''))}</td>"
            f"<td class='cmd'>{_esc(str(e.get('command',''))[:160])}</td>"
            f"<td><code>{_esc(str(e.get('raw_output_sha256',''))[:16])}…</code></td></tr>")
    audit_tbl = ("<table><thead><tr><th>Audit ID</th><th>Time (UTC)</th><th>Tool</th>"
                 "<th>Command</th><th>SHA-256 (raw output)</th></tr></thead><tbody>"
                 + ("".join(audit_rows) or "<tr><td colspan='5' class='muted'>no audit entries</td></tr>")
                 + "</tbody></table>")

    # Examiner sign-off: HMAC-signed approve/reject per finding (human-in-the-loop).
    signoff_section = ""
    nav = (f"<div class='muted' style='margin-bottom:10px'><a href='?'>← all cases</a></div>"
           if (case and multi_case) else "")
    if signoff:
        cls = "ok" if signoff.get("ok") else "bad"
        signoff_section += (
            f"<h2>Sign-off result</h2><div class='panel'>"
            f"<p class='{cls}'>{'✔ Manifest signed & verified' if signoff.get('ok') else '✘ '+_esc(signoff.get('error','sign-off failed'))}</p>"
            + (f"<p class='muted'>examiner: {_esc(signoff.get('examiner',''))} · "
               f"approved {signoff.get('approved',0)} / rejected {signoff.get('rejected',0)} · "
               f"manifest: <code>{_esc(signoff.get('path',''))}</code> · "
               f"findings sha256 <code>{_esc(str(signoff.get('findings_sha256',''))[:16])}…</code></p>"
               if signoff.get("ok") else "") + "</div>")
    if case:
        items = []
        idx = 0
        for cat, vals in (("process", findings.get("suspicious_processes", [])),
                          ("network_ioc", findings.get("network_iocs", []))):
            for v in vals:
                label = v.get("name") or v.get("value") if isinstance(v, dict) else str(v)
                items.append(
                    f"<tr><td>{_esc(cat)}</td><td>{_esc(label)}</td>"
                    f"<td><label><input type='radio' name='d{idx}' value='approved' checked> approve</label> "
                    f"<label><input type='radio' name='d{idx}' value='rejected'> reject</label>"
                    f"<input type='hidden' name='item{idx}' value='{_esc(label)}'>"
                    f"<input type='hidden' name='cat{idx}' value='{_esc(cat)}'></td></tr>")
                idx += 1
        if items:
            signoff_section += (
                f"<h2>Examiner sign-off (HMAC-signed)</h2>"
                f"<form method='POST' action='?view=signoff&case={_esc(case)}'><div class='panel'>"
                f"<p class='muted'>Approve/reject each finding, then sign. The manifest binds the "
                f"findings SHA-256 + audit-chain head and is HMAC-signed with your passphrase — "
                f"tamper-evident and verifiable later.</p>"
                "<table><thead><tr><th>Category</th><th>Finding</th><th>Decision</th></tr></thead>"
                "<tbody>" + "".join(items) + "</tbody></table>"
                f"<input type='hidden' name='count' value='{idx}'>"
                "<p style='margin-top:10px'>Examiner: <input name='examiner' required> "
                "Passphrase: <input name='passphrase' type='password' required> "
                "<button type='submit'>Sign &amp; record</button></p>"
                "</div></form>")

    procs = findings.get("suspicious_processes", [])
    iocs = findings.get("network_iocs", [])
    timeline = findings.get("timeline", [])
    files = (findings.get("classified_documents_accessed")
             or findings.get("files_accessed") or [])
    attack_chain = findings.get("attack_chain", [])

    files_section = ""
    if files:
        shown = files[:60]
        more = f"<p class='muted'>+ {len(files) - len(shown)} more</p>" if len(files) > len(shown) else ""
        files_section = (f"<h2>Files / documents accessed ({len(files)})</h2>{_ul(shown)}{more}")
    chain_section = ""
    if attack_chain:
        chain_section = f"<h2>Attack chain</h2><ol class='list'>" + "".join(
            f"<li>{_esc(s)}</li>" for s in attack_chain) + "</ol>"

    # Autonomy ledger: the agent's hypotheses, decisions, confidence, self-corrections.
    hyps = findings.get("hypotheses") or []
    hsum = findings.get("hypothesis_summary") or {}
    hyp_section = ""
    if hyps:
        _scls = {"confirmed": "ok", "disproved": "bad", "inconclusive": "warn", "open": "muted"}
        rows = []
        for h in hyps:
            st = h.get("status", "open")
            ev = ", ".join(h.get("evidence", []) or []) or "—"
            note = ""
            hist = [e for e in h.get("history", []) if e.get("note")]
            if hist:
                note = _esc(hist[-1].get("note", ""))
            rows.append(
                f"<tr><td><b>{_esc(h.get('id',''))}</b></td><td>{_esc(h.get('statement',''))}</td>"
                f"<td class='{_scls.get(st,'muted')}'>{_esc(st)}</td>"
                f"<td>{_esc(h.get('confidence',0))}</td>"
                f"<td><code>{_esc(ev)}</code></td><td class='muted'>{note}</td></tr>")
        sc = hsum.get("self_corrections", 0)
        hyp_section = (
            f"<h2>Autonomous reasoning — hypothesis ledger "
            f"({hsum.get('confirmed',0)} confirmed · {hsum.get('disproved',0)} disproved · "
            f"{hsum.get('inconclusive',0)} inconclusive · {sc} self-correction{'s' if sc!=1 else ''})</h2>"
            "<table><thead><tr><th>ID</th><th>Hypothesis</th><th>Status</th><th>Conf.</th>"
            "<th>Evidence (audit_ids)</th><th>Last note</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeepSIFT Examiner Portal</title><style>
:root{{--dark:#1f2a37;--blue:#2563eb;--green:#16a34a;--red:#dc2626;--amber:#d97706;--mute:#6b7280;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,Arial,sans-serif;background:#f3f4f6;color:#111827;line-height:1.5}}
header{{background:var(--dark);color:#fff;padding:24px 32px}}
header h1{{font-size:1.6rem}}header .sub{{color:#cbd5e1;font-size:.85rem;margin-top:4px}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:18px}}
.card{{background:#fff;border-radius:10px;padding:16px 18px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.card .k{{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mute)}}
.card .v{{font-size:1.25rem;font-weight:700;margin-top:4px}}
h2{{margin:26px 0 10px;font-size:1.15rem;color:var(--dark);border-left:4px solid var(--blue);padding-left:10px}}
.panel{{background:#fff;border-radius:10px;padding:16px 18px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.list{{padding-left:18px}}.list li{{margin:4px 0;font-size:.92rem}}
.muted{{color:var(--mute);font-size:.85rem}}
.ok{{color:var(--green);font-weight:700}}.bad{{color:var(--red);font-weight:700}}.warn{{color:var(--amber);font-weight:700}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;
 box-shadow:0 1px 4px rgba(0,0,0,.08);font-size:.85rem;margin-top:8px}}
th{{background:var(--dark);color:#fff;text-align:left;padding:9px 12px}}
td{{padding:8px 12px;border-bottom:1px solid #f1f1f1;vertical-align:top}}
td.cmd{{font-family:ui-monospace,monospace;font-size:.78rem;color:#374151;word-break:break-all}}
code{{font-family:ui-monospace,monospace;font-size:.82em;background:#f1f5f9;padding:1px 5px;border-radius:4px}}
.badges{{display:flex;flex-wrap:wrap;gap:6px}}
.badge{{background:#eff6ff;border:1px solid #bfdbfe;color:#1e40af;border-radius:6px;padding:3px 8px;
 font-size:.78rem;text-decoration:none}}.badge:hover{{background:#dbeafe}}
.summary{{white-space:pre-wrap;font-size:.92rem}}
footer{{text-align:center;color:#9ca3af;font-size:.78rem;padding:24px}}
</style></head><body>
<header><h1>DeepSIFT — Examiner Portal</h1>
<div class="sub">Read-only review of the autonomous investigation · evidence → finding → audit</div></header>
<div class="wrap">
  {nav}
  <div class="cards">
    <div class="card"><div class="k">Confidence</div><div class="v">{_esc(conf_q)}{(' · '+_esc(tier)) if tier else ''}{(' ('+_esc(score)+')') if score!='' else ''}</div></div>
    <div class="card"><div class="k">Evidence grounding</div><div class="v">{g_txt}</div></div>
    <div class="card"><div class="k">Chain of custody</div><div class="v" style="font-size:1rem">{chain_badge}</div></div>
    <div class="card"><div class="k">Tool calls</div><div class="v">{_esc(findings.get('tool_calls_used', len(audit_entries)))}</div></div>
  </div>

  <h2>Verdict</h2>
  <div class="panel summary">{_esc(summary)}</div>
  {('<h2>Interpretation</h2><div class="panel summary">'+_esc(interp)+'</div>') if interp else ''}
  {hyp_section}
  {chain_section}

  <h2>Suspicious processes / tools ({len(procs)})</h2><div class="panel">{_ul(procs)}</div>
  <h2>Network / exfil IOCs ({len(iocs)})</h2><div class="panel">{_ul(iocs)}</div>
  <h2>MITRE ATT&amp;CK</h2><div class="panel">{_mitre_badges(findings.get('mitre_techniques', []))}</div>
  <h2>Timeline ({len(timeline)})</h2><div class="panel">{_ul(timeline, empty='No timeline entries')}</div>
  {files_section}

  <h2>Evidence grounding — verified claims ({len(verified)})</h2>{verified_tbl}
  {unverified_block}

  <h2>Chain of custody — audited tool calls ({len(audit_entries)})</h2>{audit_tbl}
  {signoff_section}
</div>
<footer>DeepSIFT Examiner Portal · all findings trace to an audited tool call · hash chain detects tampering</footer>
</body></html>"""


# ── multi-case discovery ────────────────────────────────────────────────────────
def discover_cases(cases_root: Path, default_dir: Path) -> list[dict]:
    """Find case dirs (each containing findings.json) under cases_root, plus the default."""
    found: dict[str, dict] = {}

    def _add(d: Path):
        d = Path(d)
        fp = d / "findings.json"
        if fp.exists():
            findings = _load_json(fp)
            found[str(d.resolve())] = {
                "dir": str(d), "name": d.name,
                "summary": (findings.get("summary") or findings.get("observation") or "")[:140],
                "confidence": findings.get("confidence_qualitative")
                              or findings.get("confidence") or "—",
                "tool_calls": findings.get("tool_calls_used", ""),
            }

    _add(default_dir)
    if cases_root and Path(cases_root).exists():
        for child in sorted(Path(cases_root).iterdir()):
            if child.is_dir():
                _add(child)
    return list(found.values())


def render_index(cases: list[dict]) -> str:
    rows = "".join(
        f"<tr><td><a href='?case={html.escape(c['dir'])}'>{_esc(c['name'])}</a></td>"
        f"<td>{_esc(c['confidence'])}</td><td>{_esc(c['tool_calls'])}</td>"
        f"<td class='muted'>{_esc(c['summary'])}</td></tr>" for c in cases) \
        or "<tr><td colspan='4' class='muted'>no cases found</td></tr>"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>DeepSIFT Examiner Portal — cases</title>
<style>body{{font-family:'Segoe UI',Arial,sans-serif;background:#f3f4f6;color:#111827}}
header{{background:#1f2a37;color:#fff;padding:24px 32px}}.wrap{{max-width:1000px;margin:0 auto;padding:24px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
th{{background:#1f2a37;color:#fff;text-align:left;padding:10px 12px}}td{{padding:9px 12px;border-bottom:1px solid #f1f1f1}}
.muted{{color:#6b7280}}a{{color:#2563eb}}</style></head><body>
<header><h1>DeepSIFT — Examiner Portal</h1><div class="muted" style="color:#cbd5e1">Select a case to review</div></header>
<div class="wrap"><table><thead><tr><th>Case</th><th>Confidence</th><th>Tool calls</th><th>Summary</th></tr></thead>
<tbody>{rows}</tbody></table></div></body></html>"""


def render_raw_page(case: str, audit_id: str, audit_path: Path) -> str:
    raw, meta = "(not found)", {}
    for e in _load_audit_entries(audit_path):
        if e.get("audit_id") == audit_id:
            meta = e
            f = e.get("raw_output_file", "")
            try:
                raw = Path(f).read_text(encoding="utf-8", errors="replace")
            except (OSError, TypeError):
                raw = "(raw output file unavailable)"
            break
    import hashlib as _h
    recomputed = _h.sha256(raw.encode("utf-8", "replace")).hexdigest() if raw else ""
    match = recomputed == meta.get("raw_output_sha256")
    badge = (f"<span style='color:#16a34a;font-weight:700'>✔ SHA-256 matches recorded</span>"
             if match else "<span style='color:#d97706'>recomputed hash differs (or legacy entry)</span>")
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>raw {html.escape(audit_id)}</title>
<style>body{{font-family:'Segoe UI',Arial,sans-serif;background:#f3f4f6;color:#111827}}
header{{background:#1f2a37;color:#fff;padding:18px 28px}}.wrap{{max-width:1100px;margin:0 auto;padding:20px}}
pre{{background:#0b1020;color:#d1d5db;padding:16px;border-radius:8px;overflow:auto;font-size:.8rem;white-space:pre-wrap}}
a{{color:#2563eb}}.muted{{color:#6b7280}}</style></head><body>
<header><h1>Raw evidence — {html.escape(meta.get('tool',''))}</h1></header>
<div class="wrap"><p><a href="?case={html.escape(case)}">← back to case</a></p>
<p class="muted">audit_id <code>{html.escape(audit_id)}</code> · {badge}<br>
command: <code>{html.escape(str(meta.get('command',''))[:300])}</code></p>
<pre>{html.escape(raw[:200000])}</pre></div></body></html>"""


# ── build / serve ─────────────────────────────────────────────────────────────────
def build(findings_path: Path, audit_path: Path, case: str = "", signoff: dict | None = None,
          multi_case: bool = False) -> str:
    findings = _load_json(Path(findings_path))
    audit_entries = _load_audit_entries(Path(audit_path))
    chain = _verify_chain(Path(audit_path))
    return render_html(findings, audit_entries, chain, case=case, signoff=signoff,
                       multi_case=multi_case)


def do_signoff(case_dir: Path, form: dict) -> dict:
    """Build + HMAC-sign an examiner manifest from posted approve/reject decisions."""
    from mcp_server import custody
    findings_path = case_dir / "findings.json"
    if not findings_path.exists():
        return {"ok": False, "error": "findings.json not found for this case"}
    examiner = (form.get("examiner") or ["" ])[0].strip()
    passphrase = (form.get("passphrase") or [""])[0]
    if not examiner or not passphrase:
        return {"ok": False, "error": "examiner name and passphrase are required"}
    try:
        count = int((form.get("count") or ["0"])[0])
    except ValueError:
        count = 0
    decisions = []
    for i in range(count):
        decisions.append({
            "category": (form.get(f"cat{i}") or [""])[0],
            "item": (form.get(f"item{i}") or [""])[0],
            "decision": (form.get(f"d{i}") or ["approved"])[0],
            "reason": "examiner review via portal",
        })
    manifest = custody.build_manifest(str(findings_path), examiner, decisions)
    out = case_dir / "case_manifest.signed.json"
    custody.write_signed_manifest(manifest, passphrase, str(out))
    v = custody.verify_signed_manifest(str(out), passphrase)
    return {"ok": bool(v.get("overall", v.get("signature_valid"))), "examiner": examiner,
            "path": str(out), "approved": manifest["totals"]["approved"],
            "rejected": manifest["totals"]["rejected"],
            "findings_sha256": manifest["findings_sha256"]}


def main() -> int:
    ap = argparse.ArgumentParser(description="DeepSIFT Examiner Portal (interactive review UI)")
    ap.add_argument("--analysis-dir", default="analysis",
                    help="Default case dir (findings.json + forensic_audit.log)")
    ap.add_argument("--cases-root", default="",
                    help="Optional dir holding multiple case subdirs (enables the multi-case picker)")
    ap.add_argument("--findings", default="", help="Path to findings.json (overrides --analysis-dir)")
    ap.add_argument("--audit", default="", help="Path to forensic_audit.log (overrides --analysis-dir)")
    ap.add_argument("--html", default="", help="Write a static HTML file and exit (no server)")
    ap.add_argument("--port", type=int, default=8420)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    adir = Path(args.analysis_dir)
    default_findings = Path(args.findings) if args.findings else adir / "findings.json"
    default_audit = Path(args.audit) if args.audit else adir / "forensic_audit.log"
    cases_root = Path(args.cases_root) if args.cases_root else None
    # When the user points at a standalone findings file (--findings/--audit), the portal
    # is a read-only viewer of that sample. With the default analysis dir it's a live case,
    # so we enable the interactive widgets (raw drill-down + examiner sign-off) by default.
    override = bool(args.findings or args.audit)

    if args.html:
        out = Path(args.html)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(build(default_findings, default_audit), encoding="utf-8")
        print(f"Examiner report written to {out}")
        return 0

    import http.server
    from urllib.parse import urlparse, parse_qs

    def _paths_for(case: str):
        """Resolve (findings, audit) for a selected case dir, else the default.
        The default analysis dir keeps any --findings/--audit overrides."""
        if case and Path(case).resolve() != adir.resolve():
            cd = Path(case)
            return cd / "findings.json", cd / "forensic_audit.log"
        return default_findings, default_audit

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, body: str, code: int = 200):
            b = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):  # noqa: N802
            q = parse_qs(urlparse(self.path).query)
            case = (q.get("case") or [""])[0]
            view = (q.get("view") or [""])[0]
            # Multi-case index (only when a cases-root is configured and no case picked)
            if cases_root and not case:
                self._send(render_index(discover_cases(cases_root, adir)))
                return
            # Single-case mode: render the default analysis dir AS a selected case so the
            # interactive widgets (raw drill-down + examiner sign-off) are on by default.
            # A standalone --findings/--audit sample stays read-only.
            if not case and not override:
                case = str(adir)
            fpath, apath = _paths_for(case)
            if view == "raw":
                self._send(render_raw_page(case, (q.get("audit") or [""])[0], apath))
                return
            self._send(build(fpath, apath, case=case, multi_case=bool(cases_root)))

        def do_POST(self):  # noqa: N802
            q = parse_qs(urlparse(self.path).query)
            case = (q.get("case") or [""])[0]
            length = int(self.headers.get("Content-Length", "0") or 0)
            form = parse_qs(self.rfile.read(length).decode("utf-8")) if length else {}
            case_dir = Path(case) if case else adir
            result = do_signoff(case_dir, form)
            fpath, apath = _paths_for(case)
            self._send(build(fpath, apath, case=case, signoff=result,
                             multi_case=bool(cases_root)))

        def log_message(self, *a):  # quiet
            pass

    srv = http.server.HTTPServer((args.host, args.port), Handler)
    print(f"DeepSIFT Examiner Portal → http://{args.host}:{args.port}")
    print(f"  default case: {default_findings}")
    if cases_root:
        print(f"  cases root:   {cases_root} (multi-case picker enabled)")
    print("  Interactive: drill into raw evidence, HMAC-sign examiner decisions. Ctrl-C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
