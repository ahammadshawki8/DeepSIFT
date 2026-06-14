"""Regression tests for the grounding/chain-of-custody integrity fixes.

These pin the behaviour that the ROCBA run exposed:
  * EZ-tool audit records must contain the actual CSV evidence (not just the
    stdout banner), so chain-of-custody hashes and grounding see real data.
  * The grounding verifier must NOT treat derived MITRE technique IDs as raw
    observable claims (category error), must extract domains/URLs from
    descriptive IOC strings, and must not require atoms stated as absent.
"""
import json
from pathlib import Path

from mcp_server.parsers.grounding_verifier import GroundingVerifier
from mcp_server.tools.windows_artifacts import _collect_evidence_text, _MAX_AUDIT_EVIDENCE_BYTES


def _write_corpus(tmp_path: Path, audit_id: str, raw_text: str) -> GroundingVerifier:
    """Build a GroundingVerifier backed by a one-entry audit log in tmp_path."""
    raw_file = tmp_path / "raw.txt"
    raw_file.write_text(raw_text, encoding="utf-8")
    (tmp_path / "forensic_audit.log").write_text(
        json.dumps({"audit_id": audit_id, "raw_output_file": str(raw_file)}) + "\n",
        encoding="utf-8",
    )
    return GroundingVerifier(analysis_dir=tmp_path)


def test_mitre_ids_are_derived_not_raw_unverified(tmp_path):
    """A valid MITRE ID absent from raw bytes must not lower the grounding score."""
    gv = _write_corpus(tmp_path, "a1", "chrome history shows drive.google.com visits")
    findings = {
        "network_iocs": ["drive.google.com (Google Drive 'My Drive' — exfil, T1567.002)"],
        "mitre_techniques": ["T1567.002", "T1052.001"],
    }
    r = gv.verify(findings, ["a1"])
    # The domain is the only observable claim and it IS in the corpus.
    assert r["verified_count"] == 1
    assert r["unverified_count"] == 0
    assert r["grounding_score"] == 100.0
    # MITRE IDs are validated separately, not counted against raw grounding.
    assert r["derived_count"] == 2
    assert r["malformed_mitre"] == []
    assert r["verdict"] == "PASS"


def test_domain_extracted_from_descriptive_ioc(tmp_path):
    """A descriptive IOC string verifies on its domain atom, not the whole sentence."""
    gv = _write_corpus(tmp_path, "a1", "...url www.google.com/intl/drive/download ...")
    findings = {"network_iocs": [
        "www.google.com/intl/.../drive/download (Google Backup & Sync installer source)"
    ]}
    r = gv.verify(findings, ["a1"])
    assert r["verified_count"] == 1
    assert r["grounding_score"] == 100.0


def test_malformed_mitre_fails_verdict(tmp_path):
    gv = _write_corpus(tmp_path, "a1", "nothing here")
    r = gv.verify({"mitre_techniques": ["NOT-A-TID"]}, ["a1"])
    assert "NOT-A-TID" in r["malformed_mitre"]
    assert r["verdict"] == "FAIL"


def test_absence_assertion_not_required_in_corpus(tmp_path):
    """'no MRC.exe present' must not be flagged unverified just because MRC.exe is absent."""
    gv = _write_corpus(tmp_path, "a1", "OneDrive.exe is running")
    findings = {"observation": "memory shows no MRC.exe present; OneDrive.exe is running"}
    r = gv.verify(findings, ["a1"])
    checked = {tuple(u["tokens_checked"]) for u in r["unverified_claims"]}
    assert ("MRC.exe",) not in checked          # negated → skipped
    assert r["verified_count"] >= 1             # OneDrive.exe → verified


def test_collect_evidence_folds_csv(tmp_path):
    """_collect_evidence_text must return the CSV rows an EZ tool wrote."""
    (tmp_path / "out.csv").write_text(
        "Path,Executed\nC:\\Users\\fredr\\Downloads\\installbackupandsync.exe,Yes\n",
        encoding="utf-8",
    )
    ev = _collect_evidence_text(str(tmp_path))
    assert "installbackupandsync.exe" in ev


def test_collect_evidence_respects_cap(tmp_path):
    """A single oversized CSV is truncated, not folded whole."""
    big = "x" * (_MAX_AUDIT_EVIDENCE_BYTES + 5000)
    (tmp_path / "big.csv").write_text(big, encoding="utf-8")
    ev = _collect_evidence_text(str(tmp_path))
    assert len(ev) <= _MAX_AUDIT_EVIDENCE_BYTES + 200  # header + truncation marker
    assert "truncated" in ev
