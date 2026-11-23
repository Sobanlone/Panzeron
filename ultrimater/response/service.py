"""Ultrimater RESPONSE: the only place where state-changing actions happen.

Rules: every action is listed with what it will do, requires explicit confirmation if it touches a file,
is recorded in the action history and the hash-chained audit log, and originals are never deleted or modified
(quarantine is a verified move into a vault with a restore path; redaction / EXIF stripping write COPIES).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ..core.audit import AuditLog
from ..core.db import Database
from ..core.models import Finding, Module, new_id, now_iso
from ..shield.quarantine import ConfirmationRequired, QuarantineError, QuarantineVault, _sha256
from ..vision.analyze import redact_to_copy, strip_exif_copy


class ActionError(Exception):
    pass


class ResponseService:
    def __init__(self, db: Database, audit: AuditLog, vault: QuarantineVault, outputs: Path, salt: bytes,
                 tesseract_path: Callable[[], str], reanalyze: Callable[[Finding], list[Finding]]):
        self.db, self.audit, self.vault, self.outputs, self.salt = db, audit, vault, outputs, salt
        self.tesseract_path, self.reanalyze = tesseract_path, reanalyze

    # ---- what can be done ---------------------------------------------------------------------------------
    def available_actions(self, f: Finding) -> list[dict[str, Any]]:
        acts: list[dict[str, Any]] = []
        sp = Path(f.source_path) if f.source_path else None
        exists = bool(sp and sp.is_file())
        if f.status == "open":
            if f.module == Module.SHIELD and exists and self.vault.is_protected(sp):
                pass     # Ultrimater's own files: only 'resolve' / 'false positive' are offered, never quarantine or exclusion
            elif f.module == Module.SHIELD and exists:
                acts.append(self._a("quarantine_file", "Quarantine file",
                                    "Moves the file into Ultrimater's vault after verifying a hash-checked copy. You can restore it at any time from the Fix & review.",
                                    destructive=True, reversible=True))
                acts.append(self._a("trust_hash", "Trust this exact file",
                                    "Remembers this file's SHA-256 so exactly this content is never flagged again, even if renamed or copied. A changed file is checked again. Use it only for files you know are safe.",
                                    destructive=False, reversible=True, confirm=True))
                acts.append(self._a("add_exclusion", "Exclude this file from future scans",
                                    "Adds a user-controlled path exclusion. Shield will skip this file until you remove the exclusion in Settings.",
                                    destructive=False, reversible=True, confirm=True))
            if f.category in ("meta.exif_gps", "meta.exif_device") and exists:
                acts.append(self._a("strip_metadata_copy", "Create metadata-free copy",
                                    f"Writes a new copy without EXIF metadata into {self.outputs}. The original is not changed.",
                                    destructive=False, reversible=True, confirm=False))
            if f.module == Module.VISION and f.category.startswith("pii.") and exists:
                acts.append(self._a("redact_copy", "Create redacted copy",
                                    f"Writes a copy with sensitive values blacked out into {self.outputs}. The original is not changed. Image redaction relies on OCR and may miss text.",
                                    destructive=False, reversible=True, confirm=False))
            if f.module in (Module.SHIELD, Module.VISION) and exists:
                acts.append(self._a("reassess", "Re-assess now", "Re-runs the analysis on the file as it is now and resolves this finding if it is no longer detected.",
                                    destructive=False, reversible=True, confirm=False))
            acts.append(self._a("report_false_positive", "Report as false positive",
                                "Marks this finding as a false positive in your history. It will not appear in open findings or the exposure graph.",
                                destructive=False, reversible=True, confirm=False))
            acts.append(self._a("mark_resolved", "Mark as resolved", "Records that you have dealt with this finding.",
                                destructive=False, reversible=True, confirm=False))
        else:
            acts.append(self._a("reopen", "Reopen", "Moves this finding back to open.", destructive=False, reversible=True, confirm=False))
        return acts

    @staticmethod
    def _a(type_: str, label: str, desc: str, destructive: bool, reversible: bool, confirm: bool | None = None) -> dict[str, Any]:
        return {"type": type_, "label": label, "description": desc, "destructive": destructive,
                "reversible": reversible, "requires_confirmation": destructive if confirm is None else confirm}

    # ---- doing it -----------------------------------------------------------------------------------------
    def execute(self, action_type: str, finding_id: str, confirm: bool, actor: str = "user") -> dict[str, Any]:
        f = self.db.get_finding(finding_id)
        if not f:
            raise ActionError("unknown finding")
        spec = next((a for a in self.available_actions(f) if a["type"] == action_type), None)
        if not spec:
            raise ActionError(f"action '{action_type}' is not available for this finding")
        if spec["requires_confirmation"] and not confirm:
            raise ConfirmationRequired(spec["description"])
        aid = new_id("act")
        detail: dict[str, Any] = {}
        try:
            if action_type == "quarantine_file":
                detail = self.vault.quarantine(f.source_path, f.id, confirm=True)
                self.db.set_finding_status(f.id, "resolved")
            elif action_type == "trust_hash":
                sha = _sha256(Path(f.source_path))
                self.db.add_exclusion("hash", sha, f"trusted by you from finding {f.id}")
                self.db.set_finding_status(f.id, "resolved")
                detail = {"trusted_sha256": sha}
            elif action_type == "add_exclusion":
                self.db.add_exclusion("path", f.source_path, f"added from finding {f.id}")
                self.db.set_finding_status(f.id, "resolved")
                detail = {"excluded": f.source_path}
            elif action_type == "strip_metadata_copy":
                detail = {"copy": str(strip_exif_copy(Path(f.source_path), self.outputs))}
            elif action_type == "redact_copy":
                detail = {"copy": str(redact_to_copy(Path(f.source_path), self.outputs, self.salt, self.tesseract_path()))}
            elif action_type == "report_false_positive":
                self.db.set_finding_status(f.id, "false_positive", fp=True)
            elif action_type == "mark_resolved":
                self.db.set_finding_status(f.id, "resolved")
            elif action_type == "reopen":
                self.db.set_finding_status(f.id, "open", fp=False)
            elif action_type == "reassess":
                detail = self._reassess(f)
            else:  # pragma: no cover - guarded by available_actions
                raise ActionError("unsupported action")
        except (QuarantineError, ValueError, OSError, RuntimeError) as e:
            self._record(aid, action_type, f.id, "failed", {"error": str(e)}, spec["reversible"])
            self.audit.append(actor, f"action.{action_type}.failed", {"finding": f.id, "error": str(e)})
            raise ActionError(str(e)) from e
        self._record(aid, action_type, f.id, "executed", detail, spec["reversible"])
        self.audit.append(actor, f"action.{action_type}", {"finding": f.id, **detail})
        return {"action_id": aid, "status": "executed", "detail": detail}

    def _reassess(self, f: Finding) -> dict[str, Any]:
        new = self.reanalyze(f)
        still = [n for n in new if n.category == f.category]
        for n in new:
            if not any(o.category == n.category and o.source == n.source for o in self.db.list_findings(module=n.module.value)):
                self.db.save_finding(n)
        if still:
            return {"result": "still_detected", "message": "The finding is still present in the file as it is now."}
        self.db.set_finding_status(f.id, "resolved")
        return {"result": "no_longer_detected", "message": "No longer detected; finding marked resolved."}

    def restore_quarantined(self, qid: str, confirm: bool, actor: str = "user") -> dict[str, Any]:
        res = self.vault.restore(qid, confirm)
        row = self.db.query("SELECT finding_id FROM quarantine WHERE id=?", (qid,))
        fid = row[0]["finding_id"] if row else None
        if fid:
            self.db.set_finding_status(fid, "open")
        aid = new_id("act")
        self._record(aid, "restore_quarantined", fid, "executed", res, True)
        self.audit.append(actor, "action.restore_quarantined", {"quarantine_id": qid, **res})
        return res

    def _record(self, aid: str, type_: str, fid: str | None, status: str, detail: dict[str, Any], reversible: bool) -> None:
        self.db.execute("INSERT INTO actions(id,type,finding_id,status,detail,reversible,created_at) VALUES(?,?,?,?,?,?,?)",
                        (aid, type_, fid, status, json.dumps(detail, default=str), int(reversible), now_iso()))

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT * FROM actions ORDER BY created_at DESC LIMIT ?", (limit,))
        for r in rows:
            r["detail"] = json.loads(r["detail"])
        return rows
