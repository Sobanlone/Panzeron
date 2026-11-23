"""SQLite persistence. Only masked values and salted hashes are stored; never raw sensitive data."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from .models import Finding, now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings(
  id TEXT PRIMARY KEY, module TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
  source TEXT NOT NULL, title TEXT NOT NULL, created_at TEXT NOT NULL, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_findings_status ON findings(status, module);
CREATE TABLE IF NOT EXISTS scans(
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
  started_at TEXT NOT NULL, finished_at TEXT, summary TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS exclusions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, pattern TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, UNIQUE(kind, pattern));
CREATE TABLE IF NOT EXISTS quarantine(
  id TEXT PRIMARY KEY, original_path TEXT NOT NULL, vault_path TEXT NOT NULL, sha256 TEXT NOT NULL,
  size INTEGER NOT NULL, finding_id TEXT, created_at TEXT NOT NULL, restored_at TEXT);
CREATE TABLE IF NOT EXISTS actions(
  id TEXT PRIMARY KEY, type TEXT NOT NULL, finding_id TEXT, status TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}', reversible INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, reversed_at TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, event TEXT NOT NULL,
  payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class Database:
    def __init__(self, path: Path | str):
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- findings -------------------------------------------------------------------------------
    def save_finding(self, f: Finding, preserve_status: bool = True) -> None:
        """Insert or update. Re-running a deterministic analysis keeps the user's resolved status."""
        if preserve_status:
            row = self.query("SELECT status FROM findings WHERE id=?", (f.id,))
            if row:
                f.status = row[0]["status"]
        self.execute(
            "INSERT OR REPLACE INTO findings(id,module,severity,status,source,title,created_at,body) VALUES(?,?,?,?,?,?,?,?)",
            (f.id, f.module.value, f.severity.value, f.status, f.source, f.title, f.created_at,
             json.dumps(f.to_dict())))

    def list_findings(self, status: str | None = None, module: str | None = None) -> list[Finding]:
        sql, args = "SELECT body, status FROM findings WHERE 1=1", []
        if status:
            sql += " AND status=?"; args.append(status)
        if module:
            sql += " AND module=?"; args.append(module)
        sql += " ORDER BY created_at DESC, id"
        out = []
        for r in self.query(sql, args):
            f = Finding.from_dict(json.loads(r["body"]))
            f.status = r["status"]
            out.append(f)
        return out

    def get_finding(self, fid: str) -> Finding | None:
        rows = self.query("SELECT body, status FROM findings WHERE id=?", (fid,))
        if not rows:
            return None
        f = Finding.from_dict(json.loads(rows[0]["body"]))
        f.status = rows[0]["status"]
        return f

    def set_finding_status(self, fid: str, status: str, fp: bool | None = None) -> bool:
        f = self.get_finding(fid)
        if not f:
            return False
        f.status = status
        if fp is not None:
            f.false_positive_reported = fp
        self.execute("UPDATE findings SET status=?, body=? WHERE id=?", (status, json.dumps(f.to_dict()), fid))
        return True

    _SEV_SQL = "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"

    def search_findings(self, q: str = "", severities: list[str] | None = None, modules: list[str] | None = None, status: str = "open",
                        sort: str = "severity", offset: int = 0, limit: int = 50) -> dict[str, Any]:
        """Server-side search for large result sets. `status`: open | closed (resolved + false positives) | all."""
        where, args = ["1=1"], []
        if status == "open":
            where.append("status='open'")
        elif status == "closed":
            where.append("status!='open'")
        if modules:
            where.append(f"module IN ({','.join('?' * len(modules))})"); args += modules
        if q.strip():
            like = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(title LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\')"); args += [like, like]
        base = " AND ".join(where)
        counts = {"severity": {}, "module": {}}
        for r in self.query(f"SELECT severity, COUNT(*) AS n FROM findings WHERE {base} GROUP BY severity", args):
            counts["severity"][r["severity"]] = r["n"]
        for r in self.query(f"SELECT module, COUNT(*) AS n FROM findings WHERE {base} GROUP BY module", args):
            counts["module"][r["module"]] = r["n"]
        if severities:
            where.append(f"severity IN ({','.join('?' * len(severities))})"); args += severities
        flt = " AND ".join(where)
        total = self.query(f"SELECT COUNT(*) AS n FROM findings WHERE {flt}", args)[0]["n"]
        order = {"severity": f"{self._SEV_SQL} DESC, created_at DESC, id", "newest": "created_at DESC, id", "oldest": "created_at ASC, id",
                 "source": "source COLLATE NOCASE ASC, id", "title": "title COLLATE NOCASE ASC, id"}.get(sort, f"{self._SEV_SQL} DESC, created_at DESC, id")
        rows = self.query(f"SELECT body, status FROM findings WHERE {flt} ORDER BY {order} LIMIT ? OFFSET ?", args + [max(1, min(int(limit), 200)), max(0, int(offset))])
        items = []
        for r in rows:
            f = Finding.from_dict(json.loads(r["body"])); f.status = r["status"]; items.append(f)
        return {"items": items, "total": total, "counts": counts}

    def ids_matching(self, q: str = "", severities: list[str] | None = None, modules: list[str] | None = None, status: str = "open", cap: int = 5000) -> list[str]:
        out, offset = [], 0
        while len(out) < cap:
            page = self.search_findings(q, severities, modules, status, "newest", offset, 200)
            out += [f.id for f in page["items"]]
            offset += 200
            if offset >= page["total"]:
                break
        return out[:cap]

    def delete_findings_for_module(self, module: str, keep_ids: set[str]) -> None:
        for r in self.query("SELECT id FROM findings WHERE module=?", (module,)):
            if r["id"] not in keep_ids:
                self.execute("DELETE FROM findings WHERE id=?", (r["id"],))

    def clear_findings(self) -> None:
        self.execute("DELETE FROM findings")

    # ---- settings -------------------------------------------------------------------------------
    def get_settings(self, defaults: dict[str, Any]) -> dict[str, Any]:
        out = dict(defaults)
        for r in self.query("SELECT key,value FROM settings"):
            if r["key"] in defaults:
                out[r["key"]] = json.loads(r["value"])
        return out

    def set_setting(self, key: str, value: Any) -> None:
        self.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, json.dumps(value)))

    # ---- exclusions -----------------------------------------------------------------------------
    def add_exclusion(self, kind: str, pattern: str, note: str = "") -> None:
        self.execute("INSERT OR IGNORE INTO exclusions(kind,pattern,note,created_at) VALUES(?,?,?,?)",
                     (kind, pattern, note, now_iso()))

    def list_exclusions(self) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM exclusions ORDER BY id DESC")

    def remove_exclusion(self, eid: int) -> None:
        self.execute("DELETE FROM exclusions WHERE id=?", (eid,))
