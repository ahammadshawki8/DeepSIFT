"""Tests for the read-only Examiner Portal: it renders findings + grounding and
surfaces the chain-of-custody integrity verdict (including tamper detection)."""
import json
from pathlib import Path

import examiner_portal as ep


_FINDINGS = {
    "summary": "Subject exfiltrated classified data via USB.",
    "interpretation": "Staged then copied to removable media.",
    "confidence_qualitative": "high",
    "confidence_score": {"tier": "HIGH_CONFIDENCE", "total_score": 73.9},
    "suspicious_processes": ["veracrypt.exe — 6 runs", {"name": "7zFM.exe", "evidence": "ran 20:26"}],
    "network_iocs": [{"type": "smb_share", "value": "\\\\10.0.0.5\\Share", "context": "source"}],
    "mitre_techniques": ["T1052.001", "T1567.002"],
    "timeline": ["2016-06-30 01:56 — VeraCrypt last run"],
    "grounding": {
        "grounding_score": 100.0,
        "verified_claims": [{"claim": "veracrypt.exe", "matched_token": "veracrypt.exe",
                             "type": "process", "status": "VERIFIED"}],
        "unverified_claims": [],
    },
    "tool_calls_used": 9,
}


def test_render_html_contains_core_sections():
    h = ep.render_html(_FINDINGS, audit_entries=[], chain={"ok": True, "entries": 9})
    assert "Verdict" in h
    assert "veracrypt.exe" in h
    assert "T1052.001" in h                      # MITRE badge present
    assert "Exfiltration over" in h              # technique name resolved (best-effort)
    assert "INTACT" in h                         # chain banner
    assert "observable claims traced" in h       # grounding banner


def test_interactive_signoff_and_raw_drilldown(tmp_path, monkeypatch):
    """Examiner sign-off produces a verifiable HMAC manifest; raw drill-down confirms
    the recorded SHA-256 of the cited evidence."""
    monkeypatch.setenv("ANALYSIS_DIR", str(tmp_path))
    monkeypatch.setenv("EXPORTS_DIR", str(tmp_path / "exports"))
    import importlib
    import mcp_server.config as cfg
    import mcp_server.audit as audit
    importlib.reload(cfg)
    importlib.reload(audit)
    importlib.reload(ep)

    audit.begin_case_audit()
    e = audit.log_tool_execution("parse_userassist", ["RECmd"], "ValueData VeraCrypt.exe run 6")
    (tmp_path / "findings.json").write_text(json.dumps({
        "summary": "x", "suspicious_processes": ["VeraCrypt.exe"],
        "network_iocs": ["1.2.3.4"], "audit_ids": [e["audit_id"]]}), encoding="utf-8")

    form = {"examiner": ["Judge"], "passphrase": ["pw"], "count": ["2"],
            "cat0": ["process"], "item0": ["VeraCrypt.exe"], "d0": ["approved"],
            "cat1": ["network_ioc"], "item1": ["1.2.3.4"], "d1": ["rejected"]}
    res = ep.do_signoff(tmp_path, form)
    assert res["ok"] is True and res["approved"] == 1 and res["rejected"] == 1
    assert (tmp_path / "case_manifest.signed.json").exists()
    # missing passphrase is rejected
    assert ep.do_signoff(tmp_path, {"examiner": ["J"], "count": ["0"]})["ok"] is False

    raw = ep.render_raw_page("", e["audit_id"], tmp_path / "forensic_audit.log")
    assert "matches recorded" in raw and "VeraCrypt.exe" in raw

    cases = ep.discover_cases(None, tmp_path)
    assert len(cases) == 1


def test_chain_intact_and_tamper_detection(tmp_path, monkeypatch):
    # Build a real, valid hash chain using the audit logger, then tamper it.
    monkeypatch.setenv("ANALYSIS_DIR", str(tmp_path))
    monkeypatch.setenv("EXPORTS_DIR", str(tmp_path / "exports"))
    import importlib
    import mcp_server.config as cfg
    import mcp_server.audit as audit
    importlib.reload(cfg)
    importlib.reload(audit)

    audit.begin_case_audit()
    for i in range(3):
        audit.log_tool_execution(f"tool_{i}", [f"cmd{i}"], f"raw output {i}")
    log = tmp_path / "forensic_audit.log"
    assert log.exists()

    intact = ep._verify_chain(log)
    assert intact["ok"] is True and intact["entries"] == 3

    # Tamper with the middle entry's command — chain must break.
    lines = log.read_text().splitlines()
    e = json.loads(lines[1]); e["command"] = "EVIL-INSERTED"; lines[1] = json.dumps(e)
    log.write_text("\n".join(lines) + "\n")

    broken = ep._verify_chain(log)
    assert broken["ok"] is False
    html = ep.build(tmp_path / "findings.json", log)   # findings missing → empty case, still renders
    assert "✘ BROKEN" in html
