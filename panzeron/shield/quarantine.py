"""Quarantine: a verified MOVE into a vault, always reversible, never deletes the user's only copy.

Order of operations for safety: copy -> verify SHA-256 -> only then remove the original.
Restore refuses to overwrite an existing file.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from ..core.db import Database
from ..core.models import new_id, now_iso


class QuarantineError(Exception):
    pass


class ConfirmationRequired(QuarantineError):
    pass


class ConsentRequired(ConfirmationRequired):
    """Raised when an operation reaches beyond what the user explicitly chose; carries what will be read, for the permission sheet."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


_PROTECTED_WIN = ("c:/windows", "c:/program files", "c:/program files (x86)")


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class QuarantineVault:
    def __init__(self, db: Database, vault_dir: Path, protected_roots: list[Path] | None = None):
        self.db = db
        self.protected = [Path(r).resolve() for r in (protected_roots or [])]
        self.vault = Path(vault_dir)
        self.vault.mkdir(parents=True, exist_ok=True)

    def is_protected(self, p: Path) -> bool:
        """Files that belong to Panzeron itself can never be quarantined (it would break the program)."""
        try:
            rp = p.resolve()
        except OSError:
            return False
        return any(rp == r or r in rp.parents for r in self.protected)

    def _check_path(self, p: Path) -> None:
        if self.is_protected(p):
            raise QuarantineError("refusing to quarantine: this file is part of Panzeron itself")
        if not p.is_file():
            raise QuarantineError("target is not a regular file")
        rp = str(p.resolve()).replace("\\", "/").lower()
        if sys.platform == "win32" and any(rp.startswith(x) for x in _PROTECTED_WIN):
            raise QuarantineError("refusing to quarantine files inside protected Windows system folders")
        if self.vault.resolve() in p.resolve().parents:
            raise QuarantineError("file is already in the quarantine vault")

    def quarantine(self, path: str, finding_id: str | None, confirm: bool) -> dict[str, Any]:
        if not confirm:
            raise ConfirmationRequired("quarantine requires explicit user confirmation")
        p = Path(path)
        self._check_path(p)
        qid = new_id("q")
        dest = self.vault / f"{qid}.quar"
        sha = _sha256(p)
        size = p.stat().st_size
        shutil.copy2(p, dest)
        if _sha256(dest) != sha:
            dest.unlink(missing_ok=True)
            raise QuarantineError("verification failed after copy; original left untouched")
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        p.unlink()  # reached only after the vault copy is verified
        self.db.execute("INSERT INTO quarantine(id,original_path,vault_path,sha256,size,finding_id,created_at) "
                        "VALUES(?,?,?,?,?,?,?)", (qid, str(p), str(dest), sha, size, finding_id, now_iso()))
        return {"id": qid, "original_path": str(p), "sha256": sha, "size": size}

    def restore(self, qid: str, confirm: bool, restore_to: str | None = None) -> dict[str, Any]:
        if not confirm:
            raise ConfirmationRequired("restore requires explicit user confirmation")
        rows = self.db.query("SELECT * FROM quarantine WHERE id=?", (qid,))
        if not rows:
            raise QuarantineError("unknown quarantine item")
        row = rows[0]
        if row["restored_at"]:
            raise QuarantineError("item was already restored")
        vault_file = Path(row["vault_path"])
        if not vault_file.exists():
            raise QuarantineError("vault file is missing")
        if _sha256(vault_file) != row["sha256"]:
            raise QuarantineError("vault file failed integrity check; refusing to restore")
        dest = Path(restore_to or row["original_path"])
        if dest.exists():
            raise QuarantineError(f"destination already exists, refusing to overwrite: {dest}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(vault_file, dest)
        if _sha256(dest) != row["sha256"]:
            dest.unlink(missing_ok=True)
            raise QuarantineError("verification failed after restore copy; vault copy kept")
        vault_file.unlink()
        self.db.execute("UPDATE quarantine SET restored_at=? WHERE id=?", (now_iso(), qid))
        return {"id": qid, "restored_to": str(dest), "sha256": row["sha256"]}

    def list(self) -> list[dict[str, Any]]:
        return self.db.query("SELECT * FROM quarantine ORDER BY created_at DESC")
