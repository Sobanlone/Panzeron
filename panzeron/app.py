"""Application container: owns the database, settings, services and background jobs.

The HTTP layer (api/server.py) is deliberately thin; all behaviour lives in services that are unit-testable.
"""
from __future__ import annotations

import os
import platform
import shutil
import sys
import threading
from pathlib import Path
from typing import Any

from .ai.provider import provider_from_settings
from .core.audit import AuditLog
from .core.cache import BackgroundCache
from .core.config import DEFAULT_SETTINGS, UNIMPLEMENTED_SETTINGS, Paths
from .core.db import Database
from .core.log import get_logger
from .core.uiprefs import DEFAULTS as UI_DEFAULTS, sanitize as sanitize_ui_prefs
import json

from . import autostart
from .connectors.gmail import GmailGuard
from .core.models import Finding, Module, new_id, now_iso
from .inference.engine import FORMULA, run_inference
from .response.service import ResponseService
from .sentinel import analyzer as sentinel
from .core import picker
from .shield import defender, scopes, startup
from .shield.hashlists import HashLists
from .shield.browsers import BrowserGuard
from .shield.quarantine import ConsentRequired, ConfirmationRequired, QuarantineVault
from .shield.rules import BUILTIN_RULES, load_user_rules
from .shield.scancache import ScanCache
from .shield.scanner import ScanResult, Scanner
from .shield.trust import TrustStore
from .shield.watcher import FolderWatcher
from .vision.analyze import analyze_file, analyze_text
from .vision.extract import ocr_status

log = get_logger("app")
APP_VERSION = "0.1.0"


def _memory_gb() -> float | None:
    try:
        if sys.platform == "win32":
            import ctypes

            class MEMSTAT(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong), ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong), ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong), ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
            s = MEMSTAT()
            s.dwLength = ctypes.sizeof(MEMSTAT)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s))
            return round(s.ullTotalPhys / 1024 ** 3, 1)
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    return round(int(line.split()[1]) / 1024 ** 2, 1)
    except Exception:
        return None
    return None


def safe_filename(name: str) -> str:
    base = os.path.basename(name.replace("\\", "/"))
    cleaned = "".join(c for c in base if c.isalnum() or c in "._- ").strip(" .")
    return cleaned[:120] or "upload.bin"


class PanzeronApp:
    def __init__(self, home: Path | None = None):
        self.paths = Paths.create(home)
        self.salt = self.paths.load_salt()
        self.db = Database(self.paths.db)
        self.audit = AuditLog(self.db)
        self.trust = TrustStore()                      # Panzeron's own files, recognised by hash (see shield/trust.py)
        self.vault = QuarantineVault(self.db, self.paths.vault, protected_roots=[self.trust.root])
        self.response = ResponseService(self.db, self.audit, self.vault, self.paths.outputs, self.salt,
                                        lambda: self.settings()["tesseract_path"], self._reanalyze)
        self.hashlists = HashLists(self.db)
        self.rules_dir = self.paths.home / "rules"
        self.rules_dir.mkdir(exist_ok=True)
        self.rule_problems: list[str] = []
        self.picker = picker.pick                      # replaceable (tests inject a stand-in for the native dialog)
        self.watcher = FolderWatcher(self._watch_scan, self._watch_found)
        self._jobs: dict[str, tuple[Scanner, ScanResult]] = {}
        self._jobs_lock = threading.Lock()
        # Slow probes run in the background so navigating the UI never waits on PowerShell or Ollama.
        self._defender = BackgroundCache(defender.snapshot, ttl=120)
        self._ai = BackgroundCache(self._ai_status_uncached, ttl=20)
        self._defender.refresh()
        self._ai.refresh()
        self.audit.append("system", "app.start", {"version": APP_VERSION})
        # Browser protection: reads nothing until the user allows it (see shield/browsers.py). Automatic checks restart only if they were allowed.
        try:
            autostart.migrate_legacy()                    # Windows only; a no-op everywhere else and when there is nothing to migrate
        except Exception:
            pass
        self.browser = BrowserGuard(self.db, self.audit, self.salt, self._watch_scan, self._sync_watcher)
        self.gmail = GmailGuard(self.db, self.audit, self.salt, self.paths.home)   # reads nothing until you connect it (connectors/gmail.py)
        if self.gmail.connected() and self.gmail._state().get("automatic"):
            self.gmail.start_auto()
        self._sync_watcher()                              # only ever restarts a watcher the user explicitly approved (folders they chose, plus their browser's download folder if they allowed that)
        if self.browser.granted() and self.browser._state().get("automatic"):
            self.browser.start_auto()

    # ---- settings ---------------------------------------------------------------------------------------
    def settings(self) -> dict[str, Any]:
        return self.db.get_settings(DEFAULT_SETTINGS)

    def update_settings(self, patch: dict[str, Any]) -> dict[str, Any]:
        for k, v in patch.items():
            if k not in DEFAULT_SETTINGS:
                raise ValueError(f"unknown setting: {k}")
            if type(v) is not type(DEFAULT_SETTINGS[k]):
                raise ValueError(f"setting '{k}' must be of type {type(DEFAULT_SETTINGS[k]).__name__}")
            if k == "max_scan_file_mb" and not 1 <= v <= 4096:
                raise ValueError("max_scan_file_mb must be between 1 and 4096")
            if k == "scan_mode" and v not in ("smart", "deep"):
                raise ValueError("scan_mode must be 'smart' or 'deep'")
            if k == "ollama_host" and not v.startswith(("http://", "https://")):
                raise ValueError("ollama_host must start with http:// or https://")
            self.db.set_setting(k, v)
            self.audit.append("user", "settings.change", {"key": k, "value": v})
        self._ai.invalidate(); self._ai.refresh(force=True)
        return self.settings()

    # ---- status -----------------------------------------------------------------------------------------
    def defender_info(self, refresh: bool = False) -> dict[str, Any]:
        if refresh:
            self._defender.refresh(force=True)
        snap, busy = self._defender.get(wait=0.3)
        if snap is None:
            chk = {"available": None, "checking": True, "reason": "Checking Windows Security…"}
            return {"checking": True, "status": chk, "products": chk, "detections": chk}
        return {"checking": False, "refreshing": busy, **snap}

    def ai_status(self) -> dict[str, Any]:
        v, _ = self._ai.get(wait=0.3)
        return v if v is not None else {"available": None, "checking": True, "enabled": True, "reason": "Checking local AI…"}

    def _ai_status_uncached(self) -> dict[str, Any]:
        s = self.settings()
        p = provider_from_settings(s)
        if p is None:
            return {"available": False, "reason": "AI features are turned off in Settings.", "enabled": False}
        st = p.status()
        st["enabled"] = True
        return st

    def system_info(self) -> dict[str, Any]:
        return {"os": platform.platform(), "machine": platform.machine(), "python": platform.python_version(),
                "cpu_threads": os.cpu_count(), "memory_gb": _memory_gb(),
                "disk_free_gb": round(shutil.disk_usage(self.paths.home).free / 1024 ** 3, 1), "app_version": APP_VERSION,
                "data_dir": str(self.paths.home)}

    # ---- appearance preferences (validated; applied live by the UI) -------------------------------------
    def get_ui_prefs(self) -> dict[str, Any] | None:
        rows = self.db.query("SELECT value FROM settings WHERE key='ui_prefs'")
        return sanitize_ui_prefs(json.loads(rows[0]["value"]))[0] if rows else None

    def set_ui_prefs(self, raw: Any) -> tuple[dict[str, Any], list[str]]:
        clean, rejected = sanitize_ui_prefs(raw)
        self.db.set_setting("ui_prefs", clean)       # appearance is not security-relevant, so it is not written to the audit log
        return clean, rejected

    def reset_ui_prefs(self) -> None:
        self.db.execute("DELETE FROM settings WHERE key='ui_prefs'")

    def summary(self) -> dict[str, Any]:
        """Tiny, instant payload for the navigation badge (no probes, no scans)."""
        n = self.db.query("SELECT COUNT(*) AS n FROM findings WHERE status='open'")[0]["n"]
        st = self.settings()
        from .ai.provider import is_local
        remote_ai = bool(st["ai_enabled"] and st["allow_remote_processing"] and not is_local(st["ollama_host"]))
        return {"open": n, "version": APP_VERSION, "remote_ai": remote_ai, "watcher": {"running": self.watcher.running, "scanned": self.watcher.scanned_count, "detected": self.watcher.detected}}

    def status(self) -> dict[str, Any]:
        fs = self.db.list_findings()
        open_f = [f for f in fs if f.status == "open"]
        sev: dict[str, int] = {}
        for f in open_f:
            sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
        by_mod: dict[str, int] = {}
        for f in open_f:
            by_mod[f.module.value] = by_mod.get(f.module.value, 0) + 1
        ent_kinds: dict[str, int] = {}
        seen = set()
        for f in open_f:
            for e in f.entities:
                if e.id not in seen and e.kind not in ("file", "url"):
                    seen.add(e.id)
                    ent_kinds[e.kind] = ent_kinds.get(e.kind, 0) + 1
        verdicts: dict[str, int] = {}
        for f in open_f:
            if f.module == Module.SENTINEL:
                verdicts[f.category.replace("sentinel.", "")] = verdicts.get(f.category.replace("sentinel.", ""), 0) + 1
        scans = self.scan_history(5)
        return {
            "system": self.system_info(),
            "defender": self.defender_info()["status"],
            "ai": self.ai_status(),
            "ocr": ocr_status(self.settings()["tesseract_path"]),
            "watcher": self.watcher_status(),
            "browser": self.browser.status(),
            "gmail": self.gmail.status(),
            "hashlist": self.hashlists.summary(),
            "monitoring": {"realtime": False, "note": "Panzeron scans on demand, plus an optional Downloads watcher that checks new files in folders you approve. "
                                                       "It is not kernel-level real-time protection; that is provided by Windows Security."},
            "findings": {"open": len(open_f), "by_severity": sev, "by_module": by_mod, "total_recorded": len(fs),
                         "resolved": len([f for f in fs if f.status == "resolved"])},
            "privacy": {"entity_kinds": ent_kinds, "distinct_entities": len(seen)},
            "threats": {"sentinel_verdicts": verdicts},
            "recent_scans": scans,
            "recent_events": self.audit.entries(8),
            "audit": self.audit.verify_incremental(),
            "unimplemented": UNIMPLEMENTED_SETTINGS,
        }

    # ---- shield -----------------------------------------------------------------------------------------
    def _rules(self):
        user, self.rule_problems = load_user_rules(self.rules_dir)
        return BUILTIN_RULES + user

    def _make_scanner(self, mode: str | None = None, cache: bool = False) -> Scanner:
        s = self.settings()
        rules, hashes = self._rules(), self.hashlists.as_dict()
        fp = f"{','.join(r.id for r in rules)}|{len(hashes)}|{self.trust.fingerprint()}"
        return Scanner(self.salt, self.db.list_exclusions(), s["max_scan_file_mb"], defender.authenticode_status, mode or s["scan_mode"],
                       known_hashes=hashes, rules=rules, trust=self.trust, cache=ScanCache(self.db, fp) if cache else None)

    def _plan(self, sid: str) -> scopes.ScopePlan:
        plan = scopes.build_plan(sid)
        if sid == "quick":                                 # the browser's download folder joins the Quick scan if the user allowed that (and it is listed in the permission sheet)
            have = {str(r.resolve()).lower() for r in plan.roots}
            extra = [d for d in self.browser.watch_dirs() if str(d.resolve()).lower() not in have]
            if extra:
                plan.roots = plan.roots + extra
                plan.summary += " Plus your browser's download folder, because you allowed browser protection."
        return plan

    def scope_plans(self) -> list[dict[str, Any]]:
        out = []
        for sid in ("quick", "user", "computer"):
            d = self._plan(sid).describe()
            d["available"] = bool(d["roots"])
            out.append(d)
        return out

    def start_scan(self, target: Any = None, scope: str | None = None, consent: bool = False, mode: str | None = None) -> dict[str, Any]:
        """Start a scan. A folder/file you chose yourself needs no extra approval. Scopes (quick / user / computer) and broad targets
        (a drive root, your whole profile) need explicit consent, enforced here and recorded in the audit log."""
        if mode is not None and mode not in ("smart", "deep"):
            raise ValueError("mode must be 'smart' or 'deep'")
        skip: list[tuple[str, str]] = []
        label = "custom"
        if scope:
            plan = self._plan(scope)
            if not plan.roots:
                raise ValueError("Nothing to scan for that scope on this computer")
            if not consent:
                raise ConsentRequired(f"{plan.label} needs your permission before Panzeron reads these locations.", scopes.consent_details(plan))
            roots, skip, label = plan.roots, plan.skip, plan.id
        else:
            raw = target if isinstance(target, (list, tuple)) else [target]
            roots = [Path(str(t).strip().strip('"')) for t in raw if str(t or "").strip()]
            if not roots or any(not r.exists() for r in roots):
                raise ValueError("Path does not exist")
            broad = [r for r in roots if scopes.classify_target(r) == "broad"]
            if broad and not consent:
                raise ConsentRequired("This location is very broad (a whole drive or your whole user profile). Panzeron needs your permission to read all of it.",
                                      scopes.consent_details(None, roots, "Broad location"))
            if broad:
                skip = scopes.build_plan("computer").skip
                label = "broad"
        skip = skip + [("^" + str(self.paths.vault).replace("\\", "/").lower() + "/", "Panzeron quarantine vault (files already isolated)")]
        if scope or label == "broad":
            skip.append(("^" + str(self.paths.demo).replace("\\", "/").lower() + "/", "Panzeron demo data (contains simulated threats by design)"))
        scanner = self._make_scanner(mode, cache=True)
        job_id = new_id("scan")
        res = ScanResult(id=job_id, target=", ".join(str(r) for r in roots)[:300], started_at=now_iso(), scope=label, mode=scanner.mode)
        with self._jobs_lock:
            self._jobs[job_id] = (scanner, res)
        if scope or label == "broad":
            self.audit.append("user", "scan.consent_granted", {"scan": job_id, "scope": label, "roots": [str(r) for r in roots][:20]})
        self.audit.append("user", "scan.started", {"scan": job_id, "scope": label, "mode": scanner.mode, "targets": [str(r) for r in roots][:20]})
        threading.Thread(target=self._run_scan, args=(scanner, roots, skip, job_id, res, label), daemon=True, name="scan").start()
        return {"scan_id": job_id}

    def _run_scan(self, scanner: Scanner, roots: list[Path], skip: list[tuple[str, str]], job_id: str, res: ScanResult, label: str) -> None:
        try:
            result, findings = scanner.scan(roots, skip=skip, scope=label, result=res)
        except Exception as e:
            log.exception("scan crashed")
            res.status, res.finished_at, res.enumerating, res.verdict = "failed", now_iso(), False, "incomplete"
            res.errors.append({"path": res.target, "error": f"internal error: {e}"})
            result, findings = res, []
        if scanner.cache and result.status == "completed":
            scanner.cache.flush()
        for f in findings:
            self.db.save_finding(f)
        self.db.execute("INSERT OR REPLACE INTO scans(id,kind,target,status,started_at,finished_at,summary) VALUES(?,?,?,?,?,?,?)",
                        (job_id, "shield", result.target, result.status, result.started_at, result.finished_at, json.dumps(result.to_dict())))
        self.audit.append("system", "scan.completed", {"scan": job_id, "status": result.status, "verdict": result.verdict, "files": result.files_scanned,
                                                      "findings": len(findings), "errors": len(result.errors), "seconds": result.duration_s})

    # ---- native pickers ---------------------------------------------------------------------------------
    def pick(self, kind: str, title: str = "Choose", filter_name: str = "all") -> dict[str, Any]:
        try:
            paths = self.picker(kind, title, filter_name)
        except picker.PickerUnavailable as e:
            return {"paths": [], "unavailable": True, "message": f"The file dialog could not open ({e}). You can type the path instead."}
        return {"paths": paths, "cancelled": not paths}

    # ---- system review, hash lists, rules ---------------------------------------------------------------
    def system_check(self) -> dict[str, Any]:
        st = startup.collect()
        findings = startup.assess(st["entries"], self.salt) if st["available"] else []
        hosts = startup.read_hosts()
        if hosts:
            findings += startup.check_hosts(hosts, self.salt)
        for old in self.db.list_findings(status="open", module="shield"):
            if old.category in ("shield.startup", "shield.hosts"):
                self.db.execute("DELETE FROM findings WHERE id=?", (old.id,))
        for f in findings:
            self.db.save_finding(f)
        self.audit.append("user", "shield.system_check", {"entries": len(st["entries"]), "flagged": len(findings)})
        return {"available": st["available"], "reason": st["reason"], "entries": len(st["entries"]), "flagged": len(findings),
                "hosts_checked": hosts is not None, "finding_ids": [f.id for f in findings]}

    def import_hashlist(self, path: str) -> dict[str, Any]:
        r = self.hashlists.import_file(path)
        self.audit.append("user", "hashlist.imported", {"source": r["source"], "imported": r["imported"]})
        return r

    def clear_hashlist(self) -> None:
        self.hashlists.clear()
        self.audit.append("user", "hashlist.cleared", {})

    # ---- diagnostics (run as a background job so the interface never waits) -------------------------------
    def start_diagnostics(self) -> dict[str, Any]:
        from . import diagnostics
        with self._jobs_lock:
            if getattr(self, "_diag", {}).get("running"):
                return {"running": True}
            self._diag = {"running": True, "started_at": now_iso(), "result": getattr(self, "_diag", {}).get("result")}

        def work() -> None:
            try:
                res = diagnostics.run(self)
            except Exception as e:                      # never leave the UI waiting forever
                log.exception("diagnostics crashed")
                res = {"checks": [], "counts": {}, "ok": False, "report": f"Diagnostics crashed: {e}", "finished_at": now_iso()}
            with self._jobs_lock:
                self._diag = {"running": False, "started_at": self._diag["started_at"], "result": res}
            self.audit.append("user", "diagnostics.run", {"ok": res["ok"], "counts": res["counts"]})
        threading.Thread(target=work, daemon=True, name="diagnostics").start()
        return {"running": True}

    def diagnostics_status(self) -> dict[str, Any]:
        with self._jobs_lock:
            d = dict(getattr(self, "_diag", {"running": False, "result": None}))
        return d

    def integrity(self) -> dict[str, Any]:
        """Verify Panzeron's own files against the manifest that shipped with them."""
        r = self.trust.verify()
        self.audit.append("user", "integrity.checked", {"ok": r["ok"], "modified": len(r["modified"]), "unexpected": len(r["unexpected_programs"])})
        return r

    def integrity_rebuild(self, confirm: bool) -> dict[str, Any]:
        if not confirm:
            raise ConfirmationRequired("Trust the files that are in Panzeron's folder right now? Only do this if you installed or edited them yourself.")
        n = self.trust.rebuild()
        self.audit.append("user", "integrity.rebuilt", {"files": n})
        return self.trust.verify()

    def rules_info(self) -> dict[str, Any]:
        self._rules()
        return {"builtin": [{"id": r.id, "name": r.name, "severity": r.severity.value, "tags": r.tags} for r in BUILTIN_RULES],
                "custom_dir": str(self.rules_dir), "custom_problems": self.rule_problems, "custom_count": len(self._rules()) - len(BUILTIN_RULES)}

    # ---- folder watcher (approved folders only) ---------------------------------------------------------
    def _watcher_row(self) -> dict[str, Any]:
        rows = self.db.query("SELECT value FROM settings WHERE key='watcher'")
        return json.loads(rows[0]["value"]) if rows else {}

    def _watch_scan(self, path: Path) -> list[Finding]:
        return self._make_scanner("smart").scan_file(path)[0]

    def _watch_found(self, path: Path, findings: list[Finding]) -> None:
        for f in findings:
            self.db.save_finding(f)
        self.audit.append("system", "watcher.detected", {"file": path.name, "findings": len(findings), "worst": max((x.severity.value for x in findings), key=lambda v: ["info", "low", "medium", "high", "critical"].index(v))})

    def watcher_status(self) -> dict[str, Any]:
        w = self._watcher_row()
        return {**self.watcher.status(), "enabled": bool(w.get("enabled")), "default_paths": [str(p) for p in scopes.quick_roots()[:1]],
                "consented_at": w.get("consented_at"),
                "note": "Scans new files in the folders you approved while Panzeron is open. This is not kernel-level real-time protection and cannot block a program from running."}

    def _sync_watcher(self) -> None:
        """One place decides which folders are watched: those the user approved for the watcher, plus the main browser's download folder
        when the user allowed browser protection with downloads in automatic mode."""
        w = self._watcher_row()
        own = [Path(x) for x in w.get("paths", [])] if w.get("enabled") and w.get("consented_at") else []
        seen, paths = set(), []
        for p in own + self.browser.watch_dirs():
            k = str(p).lower()
            if k not in seen:
                seen.add(k); paths.append(p)
        self.watcher.start(paths)                          # stops first; with no folders it just clears the list

    def set_watcher(self, enabled: bool, paths: list[str] | None = None, consent: bool = False) -> dict[str, Any]:
        if not enabled:
            self.db.set_setting("watcher", {"enabled": False, "paths": self._watcher_row().get("paths", [])})
            self._sync_watcher()
            self.audit.append("user", "watcher.disabled", {})
            return self.watcher_status()
        chosen = [Path(p) for p in (paths or [])] or [Path.home() / "Downloads"]
        bad = [p for p in chosen if not p.is_dir()]
        if bad:
            raise ValueError(f"Folder not found: {bad[0]}")
        if not consent:
            raise ConsentRequired("Panzeron needs your permission to watch these folders for new files.", {
                "scope": "watcher", "label": "Downloads watcher", "summary": "Panzeron will check new files that appear in these folders, while the app is open.",
                "roots": [str(p) for p in chosen], "estimate": "", "skipped": [],
                "promises": ["Only NEW files are scanned (files already there are left alone; run a scan for those).", "Files are only read, never changed or executed.",
                             "Nothing leaves this computer.", "This is not kernel-level real-time protection: it reports quickly, it cannot block.", "You can turn this off at any time."]})
        self.db.set_setting("watcher", {"enabled": True, "paths": [str(p) for p in chosen], "consented_at": now_iso()})
        self._sync_watcher()
        self.audit.append("user", "watcher.enabled", {"paths": [str(p) for p in chosen]})
        return self.watcher_status()

    # ---- browser protection (consent-gated; see shield/browsers.py) --------------------------------------
    def browser_status(self) -> dict[str, Any]:
        return self.browser.status()

    def browser_access(self, action: str, browser: str | None = None, caps: list[str] | None = None, automatic: bool = True, consent: bool = False) -> dict[str, Any]:
        if action == "grant":
            return self.browser.grant(browser, caps, automatic, consent)
        if action == "revoke":
            return self.browser.revoke()
        if action == "check":
            if not self.browser.granted():
                self.browser.check()                       # raises ConsentRequired with what would be read
            threading.Thread(target=self.browser._safe_check, daemon=True, name="browser-check").start()
            return {**self.browser.status(), "checking": True}
        raise ValueError("action must be grant, revoke or check")

    # ---- Gmail (read-only, connect-to-enable; see connectors/gmail.py) ------------------------------------
    def gmail_status(self) -> dict[str, Any]:
        return self.gmail.status()

    def gmail_access(self, action: str, client_id: str = "", client_secret: str = "", automatic: bool = True, consent: bool = False, json_text: str = "") -> dict[str, Any]:
        if action == "configure":
            return self.gmail.configure(client_id, client_secret)
        if action == "import_json":
            return self.gmail.configure_from_json(json_text)
        if action == "connect":
            return self.gmail.connect(automatic, consent)
        if action == "check":
            if not self.gmail.connected():
                self.gmail.check()                           # raises ConsentRequired
            threading.Thread(target=self.gmail._safe_check, daemon=True, name="gmail-check").start()
            return {**self.gmail.status(), "checking": True}
        if action == "disconnect":
            return self.gmail.disconnect()
        if action == "reset":
            return self.gmail.reset()
        raise ValueError("action must be configure, import_json, connect, check, disconnect or reset")

    # ---- search and bulk status changes (Response Centre at scale) ---------------------------------------
    def search_findings(self, **kw: Any) -> dict[str, Any]:
        r = self.db.search_findings(**kw)
        return {"items": [f.to_dict() for f in r["items"]], "total": r["total"], "counts": r["counts"]}

    def bulk_status(self, action: str, ids: list[str] | None, flt: dict[str, Any] | None) -> dict[str, Any]:
        """Resolve / mark false positive / reopen many findings. Status-only and reversible; files are never touched."""
        mapping = {"resolve": ("resolved", None), "false_positive": ("false_positive", True), "reopen": ("open", False)}
        if action not in mapping:
            raise ValueError("action must be resolve, false_positive or reopen")
        target = list(ids or [])
        if not target and flt:
            target = self.db.ids_matching(str(flt.get("q", "")), flt.get("severities"), flt.get("modules"), str(flt.get("status", "open")))
        status, fp = mapping[action]
        n = sum(1 for fid in target[:5000] if self.db.set_finding_status(fid, status, fp))
        self.audit.append("user", f"findings.bulk_{action}", {"count": n})
        return {"changed": n}

    # ---- bulk quarantine --------------------------------------------------------------------------------
    def quarantine_findings(self, ids: list[str], confirm: bool) -> dict[str, Any]:
        if not confirm:
            raise ConfirmationRequired("Move the selected files into the Panzeron quarantine vault (restorable).")
        done, failed = [], []
        for fid in ids[:500]:
            try:
                self.response.execute("quarantine_file", fid, confirm=True)
                done.append(fid)
            except Exception as e:
                failed.append({"id": fid, "error": str(e)})
        return {"quarantined": done, "failed": failed}

    def scan_status(self, scan_id: str) -> dict[str, Any] | None:
        with self._jobs_lock:
            job = self._jobs.get(scan_id)
        if job:
            return job[1].to_dict()
        rows = self.db.query("SELECT summary FROM scans WHERE id=?", (scan_id,))
        return json.loads(rows[0]["summary"]) if rows else None

    def cancel_scan(self, scan_id: str) -> bool:
        with self._jobs_lock:
            job = self._jobs.get(scan_id)
        if job:
            job[0].cancel_event.set()
            return True
        return False

    def scan_history(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,))
        for r in rows:
            r["summary"] = json.loads(r["summary"])
        return rows

    # ---- vision -----------------------------------------------------------------------------------------
    def analyze_upload(self, filename: str, data: bytes) -> dict[str, Any]:
        if len(data) > 25 * 1024 * 1024:
            raise ValueError("File exceeds the 25 MB upload limit")
        name = safe_filename(filename)
        dest = self.paths.inbox / name
        i = 1
        while dest.exists():
            dest = self.paths.inbox / f"{Path(name).stem}-{i}{Path(name).suffix}"
            i += 1
        dest.write_bytes(data)
        return self.analyze_path(str(dest), display_name=dest.name)

    def analyze_path(self, path: str, display_name: str | None = None) -> dict[str, Any]:
        p = Path(path.strip().strip('"'))
        if not p.is_file():
            raise ValueError("File not found")
        rep = analyze_file(p, self.salt, self.settings()["tesseract_path"], display_name)
        for f in rep.findings:
            self.db.save_finding(f)
        self.audit.append("user", "vision.analyzed", {"source": rep.source, "kind": rep.kind, "findings": len(rep.findings)})
        return rep.to_dict()

    def analyze_pasted_text(self, text: str, name: str = "pasted text") -> dict[str, Any]:
        fs = analyze_text(text, name, self.salt)
        for f in fs:
            self.db.save_finding(f)
        self.audit.append("user", "vision.analyzed", {"source": name, "kind": "text", "findings": len(fs)})
        return {"source": name, "kind": "text", "chars_analysed": len(text), "notes": [], "findings": [f.to_dict() for f in fs],
                "redaction_available": False}

    # ---- sentinel ---------------------------------------------------------------------------------------
    def analyze_message(self, text: str, label: str | None = None, use_ai: bool = True) -> dict[str, Any]:
        if not text.strip():
            raise ValueError("Nothing to analyse")
        if len(text) > 100_000:
            raise ValueError("Message too long (100,000 character limit)")
        provider = provider_from_settings(self.settings()) if use_ai else None
        if provider is not None and not provider.status().get("available"):
            provider = None
        count = len(self.db.query("SELECT id FROM findings WHERE module='sentinel'")) + 1
        a = sentinel.analyze(text, self.salt, label or f"message #{count}", provider)
        if a.finding:
            self.db.save_finding(a.finding)
        self.audit.append("user", "sentinel.analyzed", {"verdict": a.verdict, "confidence": a.confidence.value, "ai_used": bool(a.ai)})
        return a.to_dict()

    # ---- inference --------------------------------------------------------------------------------------
    def run_inference(self) -> dict[str, Any]:
        findings = self.db.list_findings()
        inferred, graph = run_inference(findings)
        keep = {f.id for f in inferred}
        self.db.delete_findings_for_module("inference", keep)
        for f in inferred:
            self.db.save_finding(f)
        self.audit.append("system", "inference.run", {"inferences": len(inferred), "nodes": len(graph.nodes), "edges": len(graph.edges)})
        d = graph.to_dict()
        d["inference_findings"] = [self.db.get_finding(f.id).to_dict() for f in inferred]
        return d

    def graph(self) -> dict[str, Any]:
        return self.run_inference()

    # ---- helpers ----------------------------------------------------------------------------------------
    def _reanalyze(self, f: Finding) -> list[Finding]:
        if not f.source_path:
            return []
        p = Path(f.source_path)
        if f.module == Module.SHIELD:
            sc = Scanner(self.salt, self.db.list_exclusions(), self.settings()["max_scan_file_mb"], defender.authenticode_status)
            return sc.scan_file(p)[0]
        if f.module == Module.VISION:
            return analyze_file(p, self.salt, self.settings()["tesseract_path"], f.source).findings
        return []

    def export_report(self) -> dict[str, Any]:
        fs = self.db.list_findings()
        return {"generated_at": now_iso(), "app_version": APP_VERSION, "system": self.system_info(),
                "note": "Contains masked values only. Raw sensitive values are never stored by Panzeron.",
                "scoring_formula": FORMULA, "findings": [f.to_dict() for f in fs],
                "scans": self.scan_history(100), "actions": self.response.history(200),
                "audit": {"verification": self.audit.verify(), "entries": self.audit.entries(500)},
                "exclusions": self.db.list_exclusions(), "quarantine": self.vault.list()}

    def wipe_findings(self) -> None:
        self.db.clear_findings()
        self.audit.append("user", "privacy.findings_cleared", {})
