"""
scam_shield.history

SQLite-backed history of every analysis and report pack generated.
Lives in ~/.scam-shield/history.sqlite by default.

Public API
----------
    History(db_path)        connection handle
    h.record(report, ...)   store a report (heuristic or FullReport)
    h.record_pack(pack, ...)  store a pack reference
    h.list_reports(...)     iterator over past reports (newest first)
    h.get_report(id)        fetch a report back
    h.stats()               summary counts by verdict / scam_type
    h.search(text)          full-text-ish search over report text
"""

from __future__ import annotations

import os
import json
import sqlite3
from datetime import datetime, timezone
from typing import List, Dict, Optional, Iterable, Any

from .detector import ScamReport, FullReport


DEFAULT_PATH = os.path.expanduser("~/.scam-shield/history.sqlite")


def _connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            channel TEXT,
            verdict TEXT NOT NULL,
            score INTEGER NOT NULL,
            scam_type TEXT,
            text TEXT NOT NULL,
            signals_json TEXT,
            entities_json TEXT,
            llm_json TEXT,
            notes TEXT,
            processed_by_agent INTEGER DEFAULT 0
        )
    """)
    # ---- migrations for older DBs ----
    # Add columns that may be missing from DBs created before the agent loop.
    cur = conn.execute("PRAGMA table_info(reports)")
    existing_cols = {row["name"] for row in cur.fetchall()}
    if "processed_by_agent" not in existing_cols:
        try:
            conn.execute("ALTER TABLE reports ADD COLUMN processed_by_agent INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # already added concurrently
    if "notes" not in existing_cols:
        try:
            conn.execute("ALTER TABLE reports ADD COLUMN notes TEXT")
        except sqlite3.OperationalError:
            pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS report_packs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER REFERENCES reports(id),
            case_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            out_dir TEXT,
            files_json TEXT
        )
    """)
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS reports_fts USING fts5(
            text, signals_text, entities_text,
            content='reports', content_rowid='id'
        )
    """)
    conn.commit()
    return conn


class History:
    def __init__(self, db_path: str = DEFAULT_PATH):
        self.db_path = db_path
        self.conn = _connect(db_path)

    # ----- writes -----
    def record(self, report, *, text: str = "", notes: str = "") -> int:
        """Record a ScamReport or FullReport. Returns the new row id."""
        if isinstance(report, FullReport):
            heur = report.heuristic
            llm = report.llm
            score = report.score
            verdict = report.verdict
            scam_type = report.scam_type
        else:
            heur = report
            llm = None
            score = heur.score
            verdict = heur.verdict
            scam_type = heur.scam_type

        now = datetime.now(timezone.utc).isoformat()
        signals_json = json.dumps(heur.signals, ensure_ascii=False)
        entities_json = json.dumps(heur.entities, ensure_ascii=False)
        llm_json = json.dumps(llm.to_dict(), ensure_ascii=False) if llm is not None else None

        cur = self.conn.execute(
            "INSERT INTO reports (created_at, channel, verdict, score, scam_type, "
            "text, signals_json, entities_json, llm_json, notes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (now, heur.channel, verdict, score, scam_type, text,
             signals_json, entities_json, llm_json, notes),
        )
        rid = cur.lastrowid
        # FTS index
        signals_text = " ".join(s.get("category", "") for s in heur.signals)
        ents = heur.entities
        entities_text = " ".join(
            (ents.get("phones") or []) +
            (ents.get("emails") or []) +
            (ents.get("urls")   or [])
        )
        try:
            self.conn.execute(
                "INSERT INTO reports_fts(rowid, text, signals_text, entities_text) "
                "VALUES (?,?,?,?)",
                (rid, text, signals_text, entities_text),
            )
        except sqlite3.OperationalError:
            pass  # FTS not available, skip
        self.conn.commit()
        return rid

    def mark_processed(self, report_id: int) -> None:
        """Mark a report as handled by the agent loop."""
        self.conn.execute(
            "UPDATE reports SET processed_by_agent=1 WHERE id=?",
            (report_id,),
        )
        self.conn.commit()

    def unprocessed_reports(self, *, channel: Optional[str] = None,
                             limit: int = 50) -> List[Dict]:
        """List reports the agent has not yet acted on."""
        sql = ("SELECT id, created_at, channel, verdict, score, scam_type, "
               "text, notes FROM reports WHERE processed_by_agent=0")
        args: List = []
        if channel:
            sql += " AND channel=?"
            args.append(channel)
        sql += " ORDER BY id ASC LIMIT ?"
        args.append(limit)
        cur = self.conn.execute(sql, args)
        return [dict(r) for r in cur.fetchall()]

    def record_pack(self, report_id: int, case_id: str, out_dir: str,
                    files: List[str]) -> int:
        cur = self.conn.execute(
            "INSERT INTO report_packs (report_id, case_id, created_at, out_dir, files_json) "
            "VALUES (?,?,?,?,?)",
            (report_id, case_id, datetime.now(timezone.utc).isoformat(),
             out_dir, json.dumps(files)),
        )
        self.conn.commit()
        return cur.lastrowid

    # ----- reads -----
    def list_reports(self, *, limit: int = 50, verdict: Optional[str] = None,
                     scam_type: Optional[str] = None,
                     since: Optional[str] = None) -> List[Dict]:
        sql = "SELECT id, created_at, channel, verdict, score, scam_type, notes FROM reports"
        clauses, args = [], []
        if verdict:    clauses.append("verdict=?");    args.append(verdict)
        if scam_type:  clauses.append("scam_type=?");  args.append(scam_type)
        if since:      clauses.append("created_at>=?"); args.append(since)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        cur = self.conn.execute(sql, args)
        return [dict(r) for r in cur.fetchall()]

    def reports_since(self, since_iso: str) -> List[Dict]:
        """Reports created strictly after the given ISO timestamp (oldest first)."""
        cur = self.conn.execute(
            "SELECT id, created_at, channel, verdict, score, scam_type "
            "FROM reports WHERE created_at >= ? ORDER BY id ASC",
            (since_iso,),
        )
        return [dict(r) for r in cur.fetchall()]

    def get_report(self, report_id: int) -> Optional[Dict]:
        cur = self.conn.execute(
            "SELECT * FROM reports WHERE id=?", (report_id,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["signals"] = json.loads(d.pop("signals_json") or "[]")
        d["entities"] = json.loads(d.pop("entities_json") or "{}")
        if d.get("llm_json"):
            d["llm"] = json.loads(d.pop("llm_json"))
        else:
            d.pop("llm_json", None)
        return d

    def search(self, query: str, *, limit: int = 25) -> List[Dict]:
        """Full-text search over report text + signal categories + entity values."""
        try:
            cur = self.conn.execute(
                "SELECT r.id, r.created_at, r.verdict, r.score, r.scam_type, "
                "       r.channel, snippet(reports_fts, 0, '[', ']', '...', 12) AS snippet "
                "FROM reports_fts JOIN reports r ON r.id = reports_fts.rowid "
                "WHERE reports_fts MATCH ? ORDER BY r.id DESC LIMIT ?",
                (query, limit),
            )
        except sqlite3.OperationalError:
            # FTS not available — fall back to LIKE
            cur = self.conn.execute(
                "SELECT id, created_at, verdict, score, scam_type, channel, "
                "       substr(text, 1, 200) AS snippet "
                "FROM reports WHERE text LIKE ? OR signals_json LIKE ? "
                "ORDER BY id DESC LIMIT ?",
                (f"%{query}%", f"%{query}%", limit),
            )
        return [dict(r) for r in cur.fetchall()]

    def stats(self) -> Dict:
        cur = self.conn.execute(
            "SELECT verdict, COUNT(*) AS n FROM reports GROUP BY verdict")
        by_verdict = {r["verdict"]: r["n"] for r in cur.fetchall()}
        cur = self.conn.execute(
            "SELECT scam_type, COUNT(*) AS n FROM reports GROUP BY scam_type "
            "ORDER BY n DESC")
        by_type = [{"scam_type": r["scam_type"], "n": r["n"]} for r in cur.fetchall()]
        total = self.conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        packs = self.conn.execute("SELECT COUNT(*) FROM report_packs").fetchone()[0]
        return {
            "total_reports": total,
            "total_packs": packs,
            "by_verdict": by_verdict,
            "by_scam_type": by_type,
        }

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
