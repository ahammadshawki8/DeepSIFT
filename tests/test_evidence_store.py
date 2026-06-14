"""Indexed evidence store: ingest the full row set, query a token-bounded subset.
This is the stdlib answer to scaling beyond the parsers' capped summaries."""
import csv
import importlib


def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("ANALYSIS_DIR", str(tmp_path))
    monkeypatch.setenv("EXPORTS_DIR", str(tmp_path / "exports"))
    import mcp_server.config as cfg
    import mcp_server.evidence_store as es
    importlib.reload(cfg)
    importlib.reload(es)
    return es.EvidenceStore()


def test_ingest_rows_and_query_subset(tmp_path, monkeypatch):
    s = _store(tmp_path, monkeypatch)
    rows = [{"AbsolutePath": f"C:\\dir{i}"} for i in range(500)]
    rows.append({"AbsolutePath": "\\\\192.168.1.5\\StarkResearch\\Level 7 Classified"})
    n = s.ingest_rows("shellbags", rows)
    assert n == 501
    # full set is indexed, but a query returns only the matching subset (token-bounded)
    assert s.count("StarkResearch") == 1
    hits = s.query("StarkResearch", limit=10)
    assert len(hits) == 1 and "StarkResearch" in hits[0]["row"]["AbsolutePath"]
    # limit is honored even when many rows match
    assert len(s.query("dir", source="shellbags", limit=25)) == 25
    assert s.stats()["total_rows"] == 501


def test_ingest_csv_dir(tmp_path, monkeypatch):
    s = _store(tmp_path, monkeypatch)
    d = tmp_path / "exports" / "mft"
    d.mkdir(parents=True)
    with open(d / "MFT.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["FileName", "ParentPath"])
        w.writeheader()
        w.writerow({"FileName": "vacation photos.7z", "ParentPath": "Downloads"})
        w.writerow({"FileName": "notes.txt", "ParentPath": "Desktop"})
    assert s.ingest_path("mft", d) == 2
    hits = s.query("vacation photos", source="mft")
    assert len(hits) == 1 and hits[0]["row"]["FileName"] == "vacation photos.7z"
