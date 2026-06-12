"""Chain-of-custody + examiner sign-off tests (real crypto, stdlib)."""
import json
from mcp_server import custody, audit


def test_sign_and_verify_roundtrip():
    payload = {"a": 1, "b": ["x", "y"], "c": {"d": 2}}
    sig = custody.sign_payload(payload, "correct horse battery staple")
    assert custody.verify_signature(payload, sig, "correct horse battery staple")
    # wrong passphrase fails
    assert not custody.verify_signature(payload, sig, "wrong passphrase")
    # tampered payload fails
    assert not custody.verify_signature({**payload, "a": 2}, sig, "correct horse battery staple")


def test_signed_manifest_detects_findings_tamper(tmp_path):
    f = tmp_path / "findings.json"
    f.write_text(json.dumps({"suspicious_processes": ["MRC.exe"], "network_iocs": ["1.2.3.4"]}))
    decisions = [{"category": "process", "item": "MRC.exe", "decision": "approved", "reason": "tool"}]
    manifest = custody.build_manifest(str(f), "Tester", decisions)
    out = tmp_path / "m.signed.json"
    custody.write_signed_manifest(manifest, "pw123", str(out))

    assert custody.verify_signed_manifest(str(out), "pw123")["signature_valid"]
    assert custody.verify_signed_manifest(str(out), "pw123")["findings_unchanged"]
    # tamper with findings AFTER signing -> detected
    f.write_text(json.dumps({"suspicious_processes": ["EVIL.exe"]}))
    r = custody.verify_signed_manifest(str(out), "pw123")
    assert r["findings_unchanged"] is False
    assert r["overall"] is False


def test_audit_hash_chain_detects_tamper(tmp_path, monkeypatch):
    # point audit dirs at tmp
    monkeypatch.setattr(audit, "_get_dirs", lambda: (tmp_path, tmp_path))
    audit.log_tool_execution("toolA", ["volA"], "outputA")
    audit.log_tool_execution("toolB", ["volB"], "outputB")
    audit.log_tool_execution("toolC", ["volC"], "outputC")
    assert audit.verify_audit_chain(str(tmp_path / "forensic_audit.log"))["ok"]

    # tamper: modify the middle entry's recorded output hash
    log = tmp_path / "forensic_audit.log"
    lines = log.read_text().splitlines()
    e = json.loads(lines[1]); e["raw_output_sha256"] = "deadbeef"
    lines[1] = json.dumps(e); log.write_text("\n".join(lines) + "\n")
    res = audit.verify_audit_chain(str(log))
    assert res["ok"] is False and res["broken_at"] == 1
