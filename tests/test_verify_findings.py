"""Independent verification: a self-consistent case verifies PASS; tampering fails it.
This is the judge-facing 'trust the evidence, not the score' path."""
import importlib
import json

import verify_findings


def _fresh_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("ANALYSIS_DIR", str(tmp_path))
    monkeypatch.setenv("EXPORTS_DIR", str(tmp_path / "exports"))
    import mcp_server.config as cfg
    import mcp_server.audit as audit
    importlib.reload(cfg)
    importlib.reload(audit)
    return audit


def test_self_consistent_case_verifies(tmp_path, monkeypatch):
    audit = _fresh_audit(tmp_path, monkeypatch)
    audit.begin_case_audit()
    # A real tool call whose raw output contains the claim token.
    e = audit.log_tool_execution("parse_userassist",
                                 ["RECmd", "-f", "NTUSER.DAT"],
                                 "ValueData: C:\\Users\\PC User\\Downloads\\VeraCrypt.exe run count 6")
    findings = {
        "observation": "UserAssist shows VeraCrypt.exe executed.",
        "interpretation": "Encryption tool used before exfil.",
        "suspicious_processes": ["VeraCrypt.exe"],
        "network_iocs": [],
        "mitre_techniques": ["T1560.001"],
        "audit_ids": [e["audit_id"]],
    }
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps(findings), encoding="utf-8")

    res = verify_findings.verify(fp, tmp_path)
    assert res["overall"] is True
    assert res["grounding"]["verified_count"] >= 1
    assert res["chain"]["ok"] is True


def test_tampered_audit_log_fails_verification(tmp_path, monkeypatch):
    audit = _fresh_audit(tmp_path, monkeypatch)
    audit.begin_case_audit()
    e = audit.log_tool_execution("parse_lnk_files", ["LECmd"], "target VeraCrypt.exe")
    audit.log_tool_execution("parse_event_logs", ["EvtxECmd"], "event 4624 logon")
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"suspicious_processes": ["VeraCrypt.exe"],
                              "audit_ids": [e["audit_id"]]}), encoding="utf-8")

    log = tmp_path / "forensic_audit.log"
    lines = log.read_text().splitlines()
    row = json.loads(lines[0]); row["command"] = "TAMPERED"; lines[0] = json.dumps(row)
    log.write_text("\n".join(lines) + "\n")

    res = verify_findings.verify(fp, tmp_path)
    assert res["overall"] is False
    assert res["chain"]["ok"] is False
