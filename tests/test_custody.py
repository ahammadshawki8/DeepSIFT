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


def test_audit_chain_detects_deleted_entry(tmp_path, monkeypatch):
    """Deleting a whole entry (no key) must break the chain via the prev_hash linkage,
    not just in-place content edits. Also: the verified head is the last entry's hash."""
    monkeypatch.setattr(audit, "_get_dirs", lambda: (tmp_path, tmp_path))
    for i in range(4):
        audit.log_tool_execution(f"tool{i}", [f"vol{i}"], f"out{i}")
    log = tmp_path / "forensic_audit.log"
    intact = audit.verify_audit_chain(str(log))
    assert intact["ok"] and intact["head"] != "0" * 64

    lines = log.read_text().splitlines()
    del lines[1]  # drop a middle entry
    log.write_text("\n".join(lines) + "\n")
    res = audit.verify_audit_chain(str(log))
    assert res["ok"] is False and "inserted/deleted" in res.get("reason", "")


def test_audit_hmac_resists_forgery(tmp_path, monkeypatch):
    """With an external key, an attacker who recomputes the SHA-256 hash chain still
    cannot forge a valid HMAC — the tamper is caught."""
    monkeypatch.setattr(audit, "_get_dirs", lambda: (tmp_path, tmp_path))
    monkeypatch.setenv("DEEPSIFT_AUDIT_KEY", "externally-held-secret")
    audit.begin_case_audit()
    for i in range(3):
        audit.log_tool_execution(f"tool{i}", [f"c{i}"], f"out{i}")
    log = tmp_path / "forensic_audit.log"
    ok = audit.verify_audit_chain(str(log))
    assert ok["ok"] and ok["hmac_signed"] and ok["hmac_ok"] is True

    # Attacker edits an entry and recomputes the hash chain forward (no key) ...
    lines = log.read_text().splitlines()
    e = json.loads(lines[1]); e["command"] = "EVIL"
    e["entry_hash"] = audit._entry_hash(e["prev_hash"], e); lines[1] = json.dumps(e)
    e2 = json.loads(lines[2]); e2["prev_hash"] = e["entry_hash"]
    e2["entry_hash"] = audit._entry_hash(e2["prev_hash"], e2); lines[2] = json.dumps(e2)
    log.write_text("\n".join(lines) + "\n")

    res = audit.verify_audit_chain(str(log))
    assert res["ok"] is False and "hmac" in res.get("reason", "").lower()
