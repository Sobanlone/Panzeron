"""Known-bad hash lists you import (e.g. exports from MalwareBazaar or your IT team). Stored locally; used by the scanner."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..core.db import Database
from ..core.models import now_iso

HASH_RX = re.compile(r"\b([a-fA-F0-9]{64})\b")
MAX_ENTRIES = 1_000_000
MAX_FILE = 200 * 1024 * 1024


def parse(text: str) -> list[tuple[str, str]]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", "//")):
            continue
        m = HASH_RX.search(s)
        if not m:
            continue
        rest = (s[:m.start()] + " " + s[m.end():]).strip(" ,;\t\"'")
        out[m.group(1).lower()] = (rest[:80] or "imported hash")
        if len(out) >= MAX_ENTRIES:
            break
    return list(out.items())


class HashLists:
    def __init__(self, db: Database):
        self.db = db
        db.execute("CREATE TABLE IF NOT EXISTS hashlist(sha256 TEXT PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL, added_at TEXT NOT NULL)")

    def import_file(self, path: str) -> dict[str, Any]:
        p = Path(path.strip().strip('"'))
        if not p.is_file():
            raise ValueError("File not found")
        if p.stat().st_size > MAX_FILE:
            raise ValueError("Hash list is larger than 200 MB")
        rows = parse(p.read_text(encoding="utf-8", errors="replace"))
        if not rows:
            raise ValueError("No SHA-256 hashes (64 hexadecimal characters) were found in that file")
        now = now_iso()
        with self.db.lock:
            self.db._conn.executemany("INSERT OR REPLACE INTO hashlist(sha256,name,source,added_at) VALUES(?,?,?,?)", [(h, n, p.name, now) for h, n in rows])
            self.db._conn.commit()
        return {"imported": len(rows), "source": p.name, **self.summary()}

    def as_dict(self) -> dict[str, str]:
        return {r["sha256"]: r["name"] for r in self.db.query("SELECT sha256,name FROM hashlist")}

    def summary(self) -> dict[str, Any]:
        rows = self.db.query("SELECT source, COUNT(*) AS n FROM hashlist GROUP BY source ORDER BY n DESC")
        return {"total": sum(r["n"] for r in rows), "sources": rows}

    def clear(self) -> None:
        self.db.execute("DELETE FROM hashlist")
