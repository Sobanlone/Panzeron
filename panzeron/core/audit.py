"""Tamper-evident audit log: each row's hash covers the previous row's hash (a hash chain)."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .db import Database
from .models import now_iso

GENESIS = "0" * 64


def _digest(prev: str, ts: str, actor: str, event: str, payload: str) -> str:
    return hashlib.sha256("\x1f".join([prev, ts, actor, event, payload]).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, db: Database):
        self.db = db
        self._memo: tuple[int, str] = (0, GENESIS)   # (last verified seq, its hash)
        self._memo_bad: dict[str, Any] | None = None

    def append(self, actor: str, event: str, payload: dict[str, Any] | None = None) -> int:
        payload_s = json.dumps(payload or {}, sort_keys=True, default=str)
        with self.db.lock:
            last = self.db.query("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            prev = last[0]["hash"] if last else GENESIS
            ts = now_iso()
            h = _digest(prev, ts, actor, event, payload_s)
            cur = self.db.execute(
                "INSERT INTO audit_log(ts,actor,event,payload,prev_hash,hash) VALUES(?,?,?,?,?,?)",
                (ts, actor, event, payload_s, prev, h))
            return int(cur.lastrowid)

    def entries(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,))
        for r in rows:
            r["payload"] = json.loads(r["payload"])
        return rows

    def verify(self) -> dict[str, Any]:
        """Recompute the whole chain. Returns ok plus the first broken sequence number, if any."""
        prev = GENESIS
        count = 0
        for r in self.db.query("SELECT * FROM audit_log ORDER BY seq ASC"):
            count += 1
            expected = _digest(prev, r["ts"], r["actor"], r["event"], r["payload"])
            if r["prev_hash"] != prev or r["hash"] != expected:
                return {"ok": False, "entries": count, "first_broken_seq": r["seq"]}
            prev = r["hash"]
        return {"ok": True, "entries": count, "first_broken_seq": None}

    def verify_incremental(self) -> dict[str, Any]:
        """Cheap check for frequent polling: verifies only rows added since the last call. The full verify() (used by the
        History page and tests) still re-checks every row, so edits to OLD rows are caught there."""
        if self._memo_bad:
            return self._memo_bad
        seq0, prev = self._memo
        count = seq0
        for r in self.db.query("SELECT * FROM audit_log WHERE seq>? ORDER BY seq ASC", (seq0,)):
            count += 1
            if r["prev_hash"] != prev or r["hash"] != _digest(prev, r["ts"], r["actor"], r["event"], r["payload"]):
                self._memo_bad = {"ok": False, "entries": count, "first_broken_seq": r["seq"]}
                return self._memo_bad
            prev, seq0 = r["hash"], r["seq"]
        self._memo = (seq0, prev)
        total = self.db.query("SELECT COUNT(*) AS n FROM audit_log")[0]["n"]
        return {"ok": True, "entries": total, "first_broken_seq": None}
