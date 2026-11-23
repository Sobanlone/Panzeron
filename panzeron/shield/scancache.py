"""Remembers files that were fully scanned and found clean, so repeat scans skip unchanged files (a big speed-up on a whole computer).

A file is skipped only if its path, size AND modification time are unchanged AND the detection engine, rules, hash lists and trust
manifest are unchanged (the fingerprint). Files with findings are never cached, and Deep mode bypasses the cache.
"""
from __future__ import annotations

import threading
from typing import Any

from ..core.db import Database
from ..core.models import now_iso

ENGINE_VERSION = "2"


class ScanCache:
    def __init__(self, db: Database, fingerprint: str):
        self.db, self.fp = db, f"{ENGINE_VERSION}|{fingerprint}"
        db.execute("CREATE TABLE IF NOT EXISTS scancache(path TEXT PRIMARY KEY, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, fp TEXT NOT NULL, at TEXT NOT NULL)")
        self._new: list[tuple[str, int, int, str, str]] = []
        self._lock = threading.Lock()

    def hit(self, path: str, size: int, mtime_ns: int) -> bool:
        rows = self.db.query("SELECT size, mtime_ns, fp FROM scancache WHERE path=?", (path,))
        return bool(rows and rows[0]["size"] == size and rows[0]["mtime_ns"] == mtime_ns and rows[0]["fp"] == self.fp)

    def add(self, path: str, size: int, mtime_ns: int) -> None:
        with self._lock:
            self._new.append((path, size, mtime_ns, self.fp, now_iso()))

    def flush(self) -> int:
        with self._lock:
            rows, self._new = self._new, []
        if rows:
            with self.db.lock:
                self.db._conn.executemany("INSERT OR REPLACE INTO scancache(path,size,mtime_ns,fp,at) VALUES(?,?,?,?,?)", rows)
                self.db._conn.commit()
        return len(rows)

    def clear(self) -> None:
        self.db.execute("DELETE FROM scancache")

    def stats(self) -> dict[str, Any]:
        n = self.db.query("SELECT COUNT(*) AS n FROM scancache")[0]["n"]
        return {"remembered_clean_files": n}
