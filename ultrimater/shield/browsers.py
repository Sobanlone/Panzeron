"""Browser protection: read-only access to your MAIN browser's safety-relevant data, only after you allow it.

What it can read (each one is a switch you see before you agree, and the engine enforces the choice):
  downloads   the browser's download list and its download folder  -> new files are scanned, and the browser's own "dangerous" flags are surfaced
  history     the addresses you recently visited                  -> screened with the same URL rules as the Threat page (phishing, look-alikes, ...)
  extensions  installed extensions and the permissions they hold  -> risky permission combinations are listed for review
  settings    homepage and start-up pages                         -> catches the classic "my homepage was hijacked" trick

What it NEVER reads, by design: saved passwords, cookies and sessions, autofill and payment cards, page contents, or tab titles. Those are
exactly what info-stealing malware takes, so a protection tool must not touch them. Browser databases that are locked while the browser runs
are copied to a temporary file (read-only) and the copy is deleted straight away. Nothing is written to the browser or sent anywhere.
Only findings are stored (never your history), and stored addresses have their query string removed.
"""
from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from ..core.log import get_logger
from ..core.models import Confidence, Evidence, EvidenceTier as T, Finding, Module, Severity, make_entity, now_iso
from ..sentinel.analyzer import MEDIUM, _score, _verdict, analyze_url, registrable_domain
from .quarantine import ConsentRequired

log = get_logger("browser")

CAPS: dict[str, dict[str, str]] = {
    "downloads": {"label": "Downloads", "reads": "the download list (file locations, source page, the browser's own danger flag) and its download folder",
                  "does": "Scans files you download, adds the download folder to the Downloads watcher and to the Quick scan."},
    "history": {"label": "Recent addresses", "reads": "web addresses you visited recently (not page titles, not page content)",
                "does": "Screens them for phishing and look-alike sites; only risky ones are kept, and without their query strings."},
    "extensions": {"label": "Extensions", "reads": "each extension's name and the permissions it asks for",
                   "does": "Lists extensions that can see or change all your browsing, or that change your search or homepage."},
    "settings": {"label": "Homepage & start-up", "reads": "your homepage and start-up pages",
                 "does": "Flags a homepage that points at a suspicious address."},
}
NEVER_READ = ["Saved passwords", "Cookies and logged-in sessions", "Autofill, addresses and payment cards", "Page contents and tab titles"]
INTERVAL_SECONDS = 15 * 60
FIRST_WINDOW_DAYS = 7
MAX_HISTORY_ROWS = 5000
MAX_DOWNLOADS_PER_CHECK = 60
EPOCH_DELTA_US = 11_644_473_600 * 1_000_000          # Chromium time = microseconds since 1601-01-01

BROAD_HOST = re.compile(r"^(<all_urls>|(\*|https?|ftp)://\*(/.*)?)$")
STRONG_PERMS = {"debugger", "proxy", "nativeMessaging", "webRequestBlocking"}
WATCH_PERMS = {"webRequest", "cookies", "history", "tabs", "clipboardRead", "management", "browsingData"}
DANGER_HIGH = {1: "dangerous file", 2: "dangerous address", 3: "dangerous content", 6: "dangerous host", 7: "potentially unwanted program"}
DANGER_LOW = {4: "possibly dangerous content", 5: "uncommon file"}


# ---- discovering browsers ---------------------------------------------------------------------------------
@dataclass
class BrowserInfo:
    id: str
    name: str
    engine: str                         # chromium | firefox
    root: Path
    profiles: list[Path] = field(default_factory=list)

    def describe(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "engine": self.engine, "profiles": len(self.profiles)}


def _candidates(home: Path) -> list[tuple[str, str, str, Path]]:
    env = os.environ.get
    if sys.platform == "win32":
        local, roaming = Path(env("LOCALAPPDATA", home / "AppData" / "Local")), Path(env("APPDATA", home / "AppData" / "Roaming"))
        return [("chrome", "Google Chrome", "chromium", local / "Google" / "Chrome" / "User Data"),
                ("edge", "Microsoft Edge", "chromium", local / "Microsoft" / "Edge" / "User Data"),
                ("brave", "Brave", "chromium", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
                ("vivaldi", "Vivaldi", "chromium", local / "Vivaldi" / "User Data"),
                ("opera", "Opera", "chromium", roaming / "Opera Software" / "Opera Stable"),
                ("firefox", "Mozilla Firefox", "firefox", roaming / "Mozilla" / "Firefox")]
    if sys.platform == "darwin":
        sup = home / "Library" / "Application Support"
        return [("chrome", "Google Chrome", "chromium", sup / "Google" / "Chrome"), ("edge", "Microsoft Edge", "chromium", sup / "Microsoft Edge"),
                ("brave", "Brave", "chromium", sup / "BraveSoftware" / "Brave-Browser"), ("firefox", "Mozilla Firefox", "firefox", sup / "Firefox")]
    cfg = home / ".config"
    return [("chrome", "Google Chrome", "chromium", cfg / "google-chrome"), ("edge", "Microsoft Edge", "chromium", cfg / "microsoft-edge"),
            ("brave", "Brave", "chromium", cfg / "BraveSoftware" / "Brave-Browser"), ("vivaldi", "Vivaldi", "chromium", cfg / "vivaldi"),
            ("firefox", "Mozilla Firefox", "firefox", home / ".mozilla" / "firefox")]


def _chromium_profiles(root: Path) -> list[Path]:
    out = [p for p in sorted(root.glob("*")) if p.is_dir() and (p / "Preferences").is_file() and (p.name == "Default" or p.name.startswith("Profile "))]
    return out or ([root] if (root / "Preferences").is_file() else [])        # Opera keeps its profile in the root folder


def _firefox_profiles(root: Path) -> list[Path]:
    ini, out = root / "profiles.ini", []
    cp = configparser.ConfigParser()
    try:
        cp.read(ini, encoding="utf-8")
    except (configparser.Error, OSError):
        pass
    for sec in cp.sections():
        if cp.has_option(sec, "Path") and sec.lower().startswith("profile"):
            p = root / cp.get(sec, "Path") if cp.get(sec, "IsRelative", fallback="1") == "1" else Path(cp.get(sec, "Path"))
            if p.is_dir():
                out.append(p)
    if not out:
        base = root / "Profiles" if (root / "Profiles").is_dir() else root
        out = [p for p in sorted(base.glob("*")) if p.is_dir() and (p / "prefs.js").is_file()]
    return out


def detect(overrides: dict[str, Path] | None = None, home: Path | None = None) -> dict[str, BrowserInfo]:
    """Installed browsers that have a profile on this computer. `overrides` (tests only) maps a browser id to a profile root and replaces the real search."""
    found: dict[str, BrowserInfo] = {}
    if overrides is not None:
        cands = [(bid, bid.title(), "firefox" if bid.startswith("firefox") else "chromium", Path(root)) for bid, root in overrides.items()]
    else:
        cands = _candidates(home or Path.home())
    for bid, name, engine, root in cands:
        try:
            if not root.is_dir():
                continue
            profiles = _chromium_profiles(root) if engine == "chromium" else _firefox_profiles(root)
        except OSError:
            continue
        if profiles:
            found[bid] = BrowserInfo(bid, name, engine, root, profiles)
    return found


_PROGID = (("chromehtml", "chrome"), ("msedgehtm", "edge"), ("bravehtml", "brave"), ("vivaldi", "vivaldi"), ("opera", "opera"), ("firefox", "firefox"))


def default_browser_id(available: dict[str, BrowserInfo]) -> tuple[str | None, str]:
    """The browser the user actually uses: Windows' default for https links, else the first installed one."""
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice") as k:
                prog = str(winreg.QueryValueEx(k, "ProgId")[0]).lower()
            for needle, bid in _PROGID:
                if needle in prog and bid in available:
                    return bid, "your Windows default browser"
        except Exception:
            pass
    return (next(iter(available)), "the first browser found") if available else (None, "")


# ---- read-only access helpers -----------------------------------------------------------------------------
def _json(path: Path) -> dict[str, Any]:
    try:
        v = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def _query(db_path: Path, sql: str, params: tuple = ()) -> list[tuple]:
    """Runs a SELECT on a temporary copy of a browser database (they are locked while the browser is open). The copy is always deleted."""
    if not db_path.is_file():
        return []
    tmp = Path(tempfile.mkdtemp(prefix="ultrimater-b-"))
    try:
        copy = tmp / "db"
        shutil.copyfile(db_path, copy)
        for suffix in ("-wal", "-shm"):                                # Firefox keeps recent rows in the write-ahead log
            side = db_path.with_name(db_path.name + suffix)
            if side.is_file():
                try:
                    shutil.copyfile(side, tmp / ("db" + suffix))
                except OSError:
                    pass
        con = sqlite3.connect(f"file:{copy.as_posix()}?mode=ro", uri=True, timeout=2)
        try:
            return con.execute(sql, params).fetchall()
        finally:
            con.close()
    except (OSError, sqlite3.Error) as e:
        log.info("browser database not readable", extra={"ctx": {"file": db_path.name, "error": str(e)[:120]}})
        raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _chrome_us(unix: float) -> int:
    return int(unix * 1_000_000) + EPOCH_DELTA_US


def _unix_from_chrome(us: int) -> float:
    return (us - EPOCH_DELTA_US) / 1_000_000


def safe_url(url: str) -> str:
    """scheme://host/path, with the query string, fragment and any credentials removed (those can hold tokens)."""
    try:
        u = urlparse(url)
        host = u.hostname or ""
        return f"{u.scheme}://{host}{u.path}"[:160]
    except ValueError:
        return "(unreadable address)"


# ---- readers (one per capability) -------------------------------------------------------------------------
def read_history(engine: str, profile: Path, since_unix: float, limit: int = MAX_HISTORY_ROWS) -> list[tuple[str, float]]:
    if engine == "chromium":
        rows = _query(profile / "History", "SELECT url, last_visit_time FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time DESC LIMIT ?", (_chrome_us(since_unix), limit))
        return [(u, _unix_from_chrome(t)) for u, t in rows if isinstance(u, str)]
    rows = _query(profile / "places.sqlite", "SELECT url, last_visit_date FROM moz_places WHERE last_visit_date > ? ORDER BY last_visit_date DESC LIMIT ?", (int(since_unix * 1_000_000), limit))
    return [(u, t / 1_000_000) for u, t in rows if isinstance(u, str) and t]


def read_downloads(engine: str, profile: Path, limit: int = 200) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if engine == "chromium":
        rows = _query(profile / "History", "SELECT target_path, tab_url, end_time, danger_type FROM downloads WHERE end_time > 0 ORDER BY end_time DESC LIMIT ?", (limit,))
        for path, src, end, danger in rows:
            if path:
                out.append({"path": str(path), "source": src or "", "time": _unix_from_chrome(end), "danger": int(danger or 0)})
        return out
    try:
        rows = _query(profile / "places.sqlite",
                      "SELECT a.content, p.url, a.dateAdded FROM moz_annos a JOIN moz_anno_attributes n ON a.anno_attribute_id=n.id JOIN moz_places p ON p.id=a.place_id "
                      "WHERE n.name='downloads/destinationFileURI' ORDER BY a.dateAdded DESC LIMIT ?", (limit,))
    except sqlite3.Error:
        return []
    from urllib.parse import unquote
    for content, src, added in rows:
        if isinstance(content, str) and content.startswith("file://"):
            p = unquote(content[7:])
            if re.match(r"^/[A-Za-z]:", p):
                p = p[1:]
            out.append({"path": p, "source": src or "", "time": (added or 0) / 1_000_000, "danger": 0})
    return out


def download_dirs(engine: str, profile: Path, home: Path | None = None) -> list[Path]:
    home = home or Path.home()
    cands: list[str] = []
    if engine == "chromium":
        prefs = _json(profile / "Preferences")
        cands += [str((prefs.get("download") or {}).get("default_directory") or ""), str((prefs.get("savefile") or {}).get("default_directory") or "")]
    else:
        try:
            m = re.search(r'user_pref\("browser\.download\.dir",\s*"((?:[^"\\]|\\.)*)"\)', (profile / "prefs.js").read_text(encoding="utf-8", errors="replace"))
            if m:
                cands.append(json.loads(f'"{m.group(1)}"'))
        except (OSError, ValueError):
            pass
    cands.append(str(home / "Downloads"))
    seen, out = set(), []
    for c in cands:
        if c and Path(c).is_dir() and str(Path(c).resolve()).lower() not in seen:
            seen.add(str(Path(c).resolve()).lower()); out.append(Path(c))
    return out[:3]


def _ext_name(ext_dir: Path, manifest: dict[str, Any], fallback: str) -> str:
    name = str(manifest.get("name") or fallback)
    m = re.fullmatch(r"__MSG_(.+)__", name)
    if m:
        loc = str(manifest.get("default_locale") or "en")
        msgs = _json(ext_dir / "_locales" / loc / "messages.json")
        hit = next((v for k, v in msgs.items() if k.lower() == m.group(1).lower() and isinstance(v, dict)), None)
        name = str((hit or {}).get("message") or fallback)
    return name[:80]


def read_extensions(engine: str, profile: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if engine == "chromium":
        root = profile / "Extensions"
        sec = (_json(profile / "Secure Preferences").get("extensions") or {}).get("settings") or {}
        try:
            ids = [p for p in root.iterdir() if p.is_dir()]
        except OSError:
            return out
        for idir in ids[:300]:
            versions = sorted((v for v in idir.iterdir() if (v / "manifest.json").is_file()), key=lambda v: v.name) if idir.is_dir() else []
            if not versions:
                continue
            ver = versions[-1]; man = _json(ver / "manifest.json")
            perms = [p for p in (man.get("permissions") or []) if isinstance(p, str)]
            hosts = [p for p in (man.get("host_permissions") or []) if isinstance(p, str)] + [p for p in perms if "://" in p or p == "<all_urls>"]
            for cs in man.get("content_scripts") or []:
                hosts += [m for m in (cs.get("matches") or []) if isinstance(m, str)] if isinstance(cs, dict) else []
            ov = man.get("chrome_settings_overrides") or {}
            info = sec.get(idir.name) or {}
            out.append({"id": idir.name, "name": _ext_name(ver, man, idir.name), "version": str(man.get("version", ""))[:20],
                        "perms": sorted({p for p in perms if "://" not in p and p != "<all_urls>"}), "hosts": hosts[:50],
                        "overrides": sorted(k for k in ("homepage", "search_provider", "startup_pages") if ov.get(k)) if isinstance(ov, dict) else [],
                        "sideloaded": bool(info) and info.get("from_webstore") is False and info.get("location") in (4, 8)})
        return out
    data = _json(profile / "extensions.json")
    for a in (data.get("addons") or [])[:300]:
        if not isinstance(a, dict) or a.get("type") != "extension" or not a.get("active", True) or a.get("location") not in ("app-profile", None):
            continue
        up = a.get("userPermissions") or {}
        out.append({"id": str(a.get("id", ""))[:80], "name": str(((a.get("defaultLocale") or {}).get("name")) or a.get("id", ""))[:80], "version": str(a.get("version", ""))[:20],
                    "perms": sorted(p for p in (up.get("permissions") or []) if isinstance(p, str)), "hosts": [h for h in (up.get("origins") or []) if isinstance(h, str)][:50],
                    "overrides": [], "sideloaded": False})
    return out


def read_settings(engine: str, profile: Path) -> list[str]:
    """Homepage and start-up page addresses."""
    urls: list[str] = []
    if engine == "chromium":
        prefs = _json(profile / "Preferences")
        if not prefs.get("homepage_is_newtabpage", True) and isinstance(prefs.get("homepage"), str):
            urls.append(prefs["homepage"])
        sess = prefs.get("session") or {}
        if sess.get("restore_on_startup") == 4:
            urls += [u for u in (sess.get("startup_urls") or []) if isinstance(u, str)]
    else:
        try:
            m = re.search(r'user_pref\("browser\.startup\.homepage",\s*"((?:[^"\\]|\\.)*)"\)', (profile / "prefs.js").read_text(encoding="utf-8", errors="replace"))
            if m:
                urls += [u for u in json.loads(f'"{m.group(1)}"').split("|") if u]
        except (OSError, ValueError):
            pass
    return [u for u in urls if re.match(r"(?i)https?://", u)][:10]


# ---- judging (deterministic, inspectable rules; same tiers and wording rules as the rest of Ultrimater) -------
def _fid(*parts: str) -> str:
    return "fnd_b" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:11]


def screen_url(url: str) -> tuple[str, Any, int, int, list[Any]] | None:
    """(verdict, confidence, score, categories, indicators) if this address deserves a look, else None. Weak signals alone never count:
    ordinary login pages, tracking links and long URLs would otherwise flood a browsing history with false alarms."""
    inds = analyze_url(url)
    score, cats = _score(inds)
    verdict, conf = _verdict(score, cats)
    if verdict == "likely_scam" or (verdict == "suspicious" and any(i.weight >= MEDIUM for i in inds)):
        return verdict, conf, score, cats, inds           # type: ignore[return-value]
    return None


def url_finding(url: str, salt: bytes, browser: str, where: str) -> Finding | None:
    hit = screen_url(url)
    if not hit:
        return None
    verdict, conf, score, cats, inds = hit
    host = (urlparse(url).hostname or "").lower()
    shown = safe_url(url)
    ev = [Evidence(f"{i.description}", f"{where} · {shown}", i.rule, i.tier) for i in inds]
    ev.append(Evidence(f"Scoring rule: score {score} from {cats} categor{'y' if cats == 1 else 'ies'} → {verdict}", where, "rule:SN-SCORE", T.DERIVED))
    ent = make_entity("url", host, salt); ent.display_masked = host
    action = ("Do not sign in or enter information on this site. If you already did, change that account's password and turn on two-step verification. "
              "Open the real site by typing its address yourself.")
    return Finding(Module.SENTINEL, "Risky link found in your browser" if verdict == "likely_scam" else "Suspicious link found in your browser",
                   Severity.HIGH if verdict == "likely_scam" else Severity.MEDIUM, conf,
                   f"{len(inds)} indicator(s) across {cats} categor{'y' if cats == 1 else 'ies'} (score {score}) on an address in {where}: {shown}. "
                   "Indicators come from fixed, inspectable rules; a match is a reason to look, not proof. " + action,
                   ev, where, [ent], [action], category=f"sentinel.{verdict}", id=_fid("url", browser, registrable_domain(host), verdict))


def extension_findings(exts: list[dict[str, Any]], browser: str, where: str) -> list[Finding]:
    out: list[Finding] = []
    for x in exts:
        broad = [h for h in x["hosts"] if BROAD_HOST.match(h)]
        strong = sorted(set(x["perms"]) & STRONG_PERMS)
        watch = sorted(set(x["perms"]) & WATCH_PERMS)
        reasons: list[tuple[str, str]] = []
        sev = None
        if broad and strong:
            sev = Severity.MEDIUM
            reasons.append((f"Can read and change every website you visit AND holds: {', '.join(strong)}", "ext:broad+strong"))
        elif broad and len(watch) >= 2:
            sev = Severity.LOW
            reasons.append((f"Can read and change every website you visit AND holds: {', '.join(watch)}", "ext:broad+watch"))
        if x["overrides"]:
            sev = sev or Severity.LOW
            reasons.append((f"Changes your browser's {', '.join(o.replace('_', ' ') for o in x['overrides'])}", "ext:overrides"))
        if x["sideloaded"] and (broad or strong):
            sev = Severity.MEDIUM
            reasons.append(("Was not installed from the browser's official store (loaded from a file or another source)", "ext:sideloaded"))
        if not sev:
            continue
        ev = [Evidence(f"{x['name']} ({x['id']}): {r}", where, rule, T.DERIVED) for r, rule in reasons]
        act = "If you do not recognise or need this extension, remove it in the browser's extensions page. Many legitimate extensions (ad blockers, password managers) ask for these permissions, so this is a prompt to review, not a verdict."
        out.append(Finding(Module.SHIELD, f"Extension to review: {x['name']}", sev, Confidence.LOW,
                           f"This extension has permissions that give it wide reach over your browsing. {act}", ev, where, [], [act],
                           category="browser.extension", id=_fid("ext", browser, x["id"])))
    return out


def settings_findings(urls: list[str], salt: bytes, browser: str, where: str) -> list[Finding]:
    out = []
    for u in urls:
        f = url_finding(u, salt, browser, where + " (homepage / start-up page)")
        if f:
            f.title = "Your browser opens a suspicious page at start-up"
            f.category = "browser.settings"
            f.id = _fid("set", browser, registrable_domain((urlparse(u).hostname or "").lower()))
            f.explanation = "A homepage or start-up page that points somewhere risky is a common sign of hijacking. " + f.explanation
            out.append(f)
    return out


def download_flag_finding(d: dict[str, Any], browser: str, where: str) -> Finding | None:
    code = d["danger"]
    label = DANGER_HIGH.get(code) or DANGER_LOW.get(code)
    if not label:
        return None
    name = Path(d["path"].replace("\\", "/")).name
    src = safe_url(d["source"]) if d["source"] else "unknown page"
    act = "Do not open this file. If you already ran it, disconnect from the internet, run a full Windows Security scan, and change important passwords from another device."
    sev = Severity.HIGH if code in DANGER_HIGH else Severity.LOW
    return Finding(Module.SHIELD, f"Browser flagged a download: {name}", sev, Confidence.HIGH if code in DANGER_HIGH else Confidence.LOW,
                   f"{where} marked this download as '{label}'. {act}",
                   [Evidence(f"The browser's own safety check classed the download as '{label}' (code {code}); downloaded from {src}", where, "browser:danger-flag", T.VERIFIED)],
                   where, [], [act], source_path=d["path"], category="browser.download", id=_fid("dl", browser, d["path"], str(int(d["time"]))))


# ---- orchestration ----------------------------------------------------------------------------------------
class BrowserGuard:
    """Holds the user's consent for browser access and runs the checks (on demand and, if allowed, automatically)."""

    def __init__(self, db: Any, audit: Any, salt: bytes, scan_file: Callable[[Path], list[Finding]], on_dirs_changed: Callable[[], None],
                 overrides: dict[str, Path] | None = None, home: Path | None = None, interval: float = INTERVAL_SECONDS, first_delay: float = 8.0):
        self.db, self.audit, self.salt, self.scan_file, self.on_dirs_changed = db, audit, salt, scan_file, on_dirs_changed
        self.overrides, self.home, self.interval, self.first_delay = overrides, home, interval, first_delay
        self.checking = False
        self.run_first_check = True                         # tests switch this off to run checks themselves
        self._run_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- state --
    def _state(self) -> dict[str, Any]:
        rows = self.db.query("SELECT value FROM settings WHERE key='browser'")
        return json.loads(rows[0]["value"]) if rows else {}

    def _save(self, st: dict[str, Any]) -> None:
        self.db.set_setting("browser", st)

    def granted(self) -> bool:
        st = self._state()
        return bool(st.get("enabled") and st.get("consented_at") and st.get("caps"))

    def available(self) -> dict[str, BrowserInfo]:
        return detect(self.overrides, self.home)

    def status(self) -> dict[str, Any]:
        av = self.available()
        main, how = default_browser_id(av)
        st = self._state()
        on = self.granted()
        return {"available": [{**b.describe(), "is_main": bid == main} for bid, b in av.items()], "main": main, "main_reason": how,
                "granted": on, "browser": st.get("browser") if on else None, "browser_name": av[st["browser"]].name if on and st.get("browser") in av else None,
                "caps": st.get("caps", []) if on else [], "automatic": bool(st.get("automatic")) if on else False, "consented_at": st.get("consented_at") if on else None,
                "last_check": st.get("last_check") if on else None, "last_summary": st.get("last_summary") if on else None, "checking": self.checking,
                "capabilities": [{"id": k, **v} for k, v in CAPS.items()], "never_read": NEVER_READ, "interval_minutes": round(self.interval / 60),
                "note": "Read-only. Ultrimater never changes your browser, and it never reads passwords, cookies, autofill or page contents."}

    def watch_dirs(self) -> list[Path]:
        """Download folders to add to the Downloads watcher and the Quick scan: only when allowed, 'downloads' is on, and automatic mode is on."""
        st = self._state()
        if not (self.granted() and "downloads" in st["caps"] and st.get("automatic")):
            return []
        b = self.available().get(st.get("browser", ""))
        if not b:
            return []
        out: list[Path] = []
        for p in self._profiles(b, st):
            out += download_dirs(b.engine, p, self.home)
        seen, uniq = set(), []
        for d in out:
            k = str(d.resolve()).lower()
            if k not in seen:
                seen.add(k); uniq.append(d)
        return uniq

    def _profiles(self, b: BrowserInfo, st: dict[str, Any]) -> list[Path]:
        chosen = {str(p) for p in st.get("profiles", [])}
        return [p for p in b.profiles if str(p) in chosen] or b.profiles

    # -- consent --
    def consent_details(self, b: BrowserInfo, caps: list[str], automatic: bool) -> dict[str, Any]:
        files: list[str] = []
        for p in b.profiles[:3]:
            if "history" in caps or "downloads" in caps:
                files.append(str(p / ("History" if b.engine == "chromium" else "places.sqlite")))
            if "extensions" in caps:
                files.append(str(p / ("Extensions" if b.engine == "chromium" else "extensions.json")))
            if "settings" in caps or "downloads" in caps:
                files.append(str(p / ("Preferences" if b.engine == "chromium" else "prefs.js")))
        return {"scope": "browser", "label": f"Browser protection for {b.name}",
                "summary": f"Ultrimater will read safety-related information from {b.name}, your main browser: "
                           + "; ".join(f"{CAPS[c]['label'].lower()} ({CAPS[c]['reads']})" for c in caps) + ".",
                "roots": list(dict.fromkeys(files)), "estimate": "", "skipped": [],
                "promises": ["Everything is read-only. Ultrimater never changes, closes or controls your browser.",
                             "It does NOT read saved passwords, cookies or sessions, autofill and cards, or page contents.",
                             "Nothing leaves this computer. Your browsing history is not stored: only risky findings are kept, without query strings.",
                             "Locked browser files are read from a temporary copy that is deleted immediately.",
                             (f"Automatic mode: checks run when Ultrimater starts and about every {round(self.interval / 60)} minutes while it is open." if automatic
                              else "Checks run only when you press Check now."),
                             "You can switch this off at any time; Ultrimater then stops reading the browser right away."]}

    def grant(self, browser: str | None, caps: list[str] | None, automatic: bool, consent: bool) -> dict[str, Any]:
        av = self.available()
        if not av:
            raise ValueError("No supported browser with a profile was found on this computer.")
        main, _ = default_browser_id(av)
        bid = browser or main
        if bid not in av:
            raise ValueError("That browser was not found on this computer.")
        caps = list(dict.fromkeys(caps if caps is not None else list(CAPS)))
        if not caps or any(c not in CAPS for c in caps):
            raise ValueError("Choose at least one valid kind of browser data.")
        if not consent:
            raise ConsentRequired(f"Ultrimater needs your permission to read safety information from {av[bid].name}.", self.consent_details(av[bid], caps, automatic))
        self._save({"enabled": True, "browser": bid, "profiles": [str(p) for p in av[bid].profiles], "caps": caps, "automatic": bool(automatic),
                    "consented_at": now_iso(), "last_check": None, "last_summary": None, "hist_cursor": 0, "seen_dl": [], "totals": {"flagged": 0}})
        self.audit.append("user", "browser.access_granted", {"browser": bid, "caps": caps, "automatic": bool(automatic)})
        self.on_dirs_changed()
        if automatic:
            self.start_auto()
        if self.run_first_check:
            threading.Thread(target=self._safe_check, daemon=True, name="browser-first-check").start()
        return self.status()

    def revoke(self) -> dict[str, Any]:
        st = self._state()
        if st:
            self._save({"enabled": False})                 # forget profiles, cursors and consent; findings already recorded stay until you wipe them
            self.audit.append("user", "browser.access_revoked", {"browser": st.get("browser")})
        self.stop()
        self.on_dirs_changed()
        return self.status()

    # -- checks --
    def _safe_check(self) -> None:
        try:
            self.check()
        except Exception as e:                              # recorded, never silent
            log.warning("browser check failed", extra={"ctx": {"error": str(e)[:200]}})

    def check(self) -> dict[str, Any]:
        if not self.granted():
            raise ConsentRequired("Browser protection is off. Ultrimater needs your permission before it reads anything from your browser.",
                                  self.consent_details(next(iter(self.available().values())), list(CAPS), True) if self.available() else {})
        if not self._run_lock.acquire(blocking=False):
            return {"busy": True}
        self.checking = True
        try:
            st = self._state()
            b = self.available().get(st["browser"])
            if not b:
                raise ValueError("The browser is no longer installed.")
            caps, where = set(st["caps"]), f"{b.name} (read-only)"
            s = {"browser": b.name, "history_screened": 0, "downloads_checked": 0, "extensions_reviewed": 0, "startup_pages_checked": 0, "new_findings": 0, "notes": []}
            seen = set(st.get("seen_dl", []))
            cursor = float(st.get("hist_cursor") or (time.time() - FIRST_WINDOW_DAYS * 86400))
            newest = cursor
            for prof in self._profiles(b, st):
                pw = f"{where} · {prof.name}"
                def attempt(label: str, fn: Callable[[], None]) -> None:
                    try:
                        fn()
                    except (OSError, sqlite3.Error):
                        s["notes"].append(f"{label}: could not read it now (the browser may have it locked). It will be retried.")
                if "history" in caps:
                    def hist() -> None:
                        nonlocal newest
                        rows = read_history(b.engine, prof, cursor)
                        seen_hosts: set[str] = set()
                        for url, ts in rows:
                            newest = max(newest, ts)
                            if not re.match(r"(?i)https?://", url):
                                continue
                            s["history_screened"] += 1
                            key = (urlparse(url).hostname or "") + "|" + urlparse(url).path[:40]
                            if key in seen_hosts:
                                continue
                            seen_hosts.add(key)
                            self._add(url_finding(url, self.salt, b.id, pw), s)
                    attempt("Recent addresses", hist)
                if "downloads" in caps:
                    def dl() -> None:
                        n = 0
                        for d in read_downloads(b.engine, prof):
                            key = hashlib.sha256(f"{d['path']}|{int(d['time'])}".encode()).hexdigest()[:16]
                            if key in seen:
                                continue
                            seen.add(key)
                            self._add(download_flag_finding(d, b.id, pw), s)
                            p = Path(d["path"])
                            if n < MAX_DOWNLOADS_PER_CHECK and time.time() - d["time"] < 14 * 86400 and p.is_file():
                                n += 1
                                s["downloads_checked"] += 1
                                for f in self.scan_file(p):
                                    self._add(f, s)
                    attempt("Downloads", dl)
                if "extensions" in caps:
                    def ex() -> None:
                        xs = read_extensions(b.engine, prof)
                        s["extensions_reviewed"] += len(xs)
                        for f in extension_findings(xs, b.id, pw):
                            self._add(f, s)
                    attempt("Extensions", ex)
                if "settings" in caps:
                    def se() -> None:
                        us = read_settings(b.engine, prof)
                        s["startup_pages_checked"] += len(us)
                        for f in settings_findings(us, self.salt, b.id, pw):
                            self._add(f, s)
                    attempt("Homepage", se)
            st = self._state()
            if st.get("enabled"):                           # still allowed (the user may have switched it off meanwhile)
                tot = st.get("totals") or {"flagged": 0}
                tot["flagged"] += s["new_findings"]
                s["since_allowing"] = dict(tot)
                st.update({"last_check": now_iso(), "last_summary": s, "hist_cursor": newest, "seen_dl": sorted(seen)[-2000:], "totals": tot})
                self._save(st)
                self.audit.append("system", "browser.checked", {k: v for k, v in s.items() if isinstance(v, int)})
            return s
        finally:
            self.checking = False
            self._run_lock.release()

    def _add(self, f: Finding | None, summary: dict[str, Any]) -> None:
        if f is None:
            return
        if self.db.get_finding(f.id) is None:
            summary["new_findings"] += 1
        self.db.save_finding(f)                             # keeps the status of a finding you already resolved

    # -- automatic mode --
    def start_auto(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="browser-guard")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        if self._stop.wait(self.first_delay):
            return
        while not self._stop.is_set():
            st = self._state()
            if st.get("enabled") and st.get("automatic"):
                self._safe_check()
            if self._stop.wait(self.interval):
                break
