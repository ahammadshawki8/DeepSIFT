"""
Indexed evidence store — a dependency-light (stdlib sqlite3) answer to "how does this
scale to a full-disk case without blowing the LLM context budget?"

Parsers hand the LLM a CAPPED summary (e.g. all_entries[:200]); but the EZ tools write
the COMPLETE artifact set to exports/<artifact>/*.csv. This module ingests those full
rows into a queryable SQLite DB so an agent can pull only the rows it needs
(`query_evidence("StarkResearch")`) instead of dumping a 100k-row MFT into the prompt.

No external services, no extra installs — just sqlite3 from the standard library.
"""
from __future__ import annotations

import csv as _csv
import json
import sqlite3
from pathlib import Path

from mcp_server.config import ANALYSIS_DIR


def _db_path(db_path: str | Path | None = None) -> Path:
    return Path(db_path) if db_path else (ANALYSIS_DIR / "evidence.db")


class EvidenceStore:
    """SQLite-backed full-artifact index. Rows are searchable by substring and by tool."""

    def __init__(self, db_path: str | Path | None = None):
        self.path = _db_path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,        -- tool / artifact name (e.g. 'shellbags')
                audit_id TEXT,      -- chain-of-custody link, when known
                text TEXT,          -- flattened searchable text of the row
                data TEXT           -- JSON of the original row
            )""")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON artifacts(source)")
        self.conn.commit()

    # ── ingest ────────────────────────────────────────────────────────────────
    def ingest_rows(self, source: str, rows: list[dict], audit_id: str = "") -> int:
        n = 0
        cur = self.conn.cursor()
        for r in rows:
            if not isinstance(r, dict):
                r = {"value": r}
            text = " ".join(str(v) for v in r.values() if v not in (None, ""))
            cur.execute("INSERT INTO artifacts(source, audit_id, text, data) VALUES (?,?,?,?)",
                        (source, audit_id, text, json.dumps(r, default=str)))
            n += 1
        self.conn.commit()
        return n

    def ingest_csv(self, source: str, csv_path: str | Path, audit_id: str = "") -> int:
        p = Path(csv_path)
        if not p.exists():
            return 0
        with open(p, encoding="utf-8-sig", errors="replace", newline="") as f:
            rows = list(_csv.DictReader(f))
        return self.ingest_rows(source, rows, audit_id)

    def ingest_path(self, source: str, path: str | Path, audit_id: str = "") -> int:
        """Ingest a CSV file or every *.csv in a directory."""
        p = Path(path)
        if p.is_dir():
            total = 0
            for csv_file in sorted(p.glob("*.csv")):
                total += self.ingest_csv(source or csv_file.stem, csv_file, audit_id)
            return total
        return self.ingest_csv(source or p.stem, p, audit_id)

    # ── query ─────────────────────────────────────────────────────────────────
    def query(self, text: str = "", source: str = "", limit: int = 50) -> list[dict]:
        sql = "SELECT source, audit_id, data FROM artifacts"
        clauses, params = [], []
        if text:
            clauses.append("text LIKE ?")
            params.append(f"%{text}%")
        if source:
            clauses.append("source = ?")
            params.append(source)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " LIMIT ?"
        params.append(int(limit))
        out = []
        for src, aid, data in self.conn.execute(sql, params):
            try:
                row = json.loads(data)
            except ValueError:
                row = {"data": data}
            out.append({"source": src, "audit_id": aid, "row": row})
        return out

    def count(self, text: str = "", source: str = "") -> int:
        sql = "SELECT COUNT(*) FROM artifacts"
        clauses, params = [], []
        if text:
            clauses.append("text LIKE ?"); params.append(f"%{text}%")
        if source:
            clauses.append("source = ?"); params.append(source)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return self.conn.execute(sql, params).fetchone()[0]

    def stats(self) -> dict:
        total = self.conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        by_source = dict(self.conn.execute(
            "SELECT source, COUNT(*) FROM artifacts GROUP BY source ORDER BY 2 DESC").fetchall())
        return {"total_rows": total, "by_source": by_source, "db_path": str(self.path)}

    def close(self):
        self.conn.close()
