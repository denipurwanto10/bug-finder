"""SQLite persistence: scans + findings, view/delete/compare/export."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from app.utils.models import Finding, ScanResult


class ScanDB:
    def __init__(self, path: str = "webguard.db"):
        self.path = path
        self.init_db()

    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scope TEXT DEFAULT '',
                    mode TEXT DEFAULT 'passive',
                    started_at TEXT DEFAULT '',
                    finished_at TEXT DEFAULT '',
                    security_score INTEGER DEFAULT 100,
                    stats TEXT DEFAULT '{}',
                    created_at TEXT DEFAULT ''
                )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    name TEXT, severity TEXT, confidence TEXT,
                    url TEXT, method TEXT, parameter TEXT,
                    evidence TEXT, request_summary TEXT, response_summary TEXT,
                    description TEXT, impact TEXT, remediation TEXT,
                    cwe TEXT, owasp TEXT, module TEXT, references_json TEXT DEFAULT '[]',
                    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )""")
            conn.execute("PRAGMA foreign_keys=ON")

    def save_scan(self, result: ScanResult) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (target, scope, mode, started_at, finished_at, security_score, stats, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (result.target, json.dumps(result.scope), result.mode, result.started_at,
                 result.finished_at, result.security_score,
                 json.dumps(result.stats.__dict__), datetime.now().isoformat(timespec="seconds")))
            scan_id = cur.lastrowid
            for f in result.findings:
                conn.execute(
                    "INSERT INTO findings (scan_id, name, severity, confidence, url, method, parameter,"
                    " evidence, request_summary, response_summary, description, impact, remediation,"
                    " cwe, owasp, module, references_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (scan_id, f.name, f.severity, f.confidence, f.url, f.method, f.parameter,
                     f.evidence, f.request_summary, f.response_summary, f.description, f.impact,
                     f.remediation, f.cwe, f.owasp, f.module, json.dumps(f.references)))
            conn.commit()
            return scan_id

    def list_scans(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS finding_count"
                " FROM scans s ORDER BY s.id DESC").fetchall()
            return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            frows = conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
            d["findings"] = [dict(r) for r in frows]
            return d

    def delete_scan(self, scan_id: int):
        with self._connect() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
            conn.commit()

    def compare_scans(self, a_id: int, b_id: int) -> dict:
        a = self.get_scan(a_id) or {"findings": []}
        b = self.get_scan(b_id) or {"findings": []}
        ka = {(f["name"], f["url"], f["parameter"]) for f in a["findings"]}
        kb = {(f["name"], f["url"], f["parameter"]) for f in b["findings"]}
        return {
            "a_id": a_id, "b_id": b_id,
            "a_count": len(ka), "b_count": len(kb),
            "fixed": sorted(ka - kb), "new": sorted(kb - ka),
            "common": sorted(ka & kb),
        }
