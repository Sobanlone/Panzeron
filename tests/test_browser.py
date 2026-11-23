"""Browser protection: consent is enforced by the engine, reads are read-only, passwords/cookies are never touched, and the
automatic checks feed the Downloads watcher, the Quick scan, Sentinel-style link screening and the extension review."""
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from tests.helpers import new_app
from panzeron.shield import browsers
from panzeron.shield.quarantine import ConsentRequired

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
US = lambda unix: int(unix * 1_000_000) + browsers.EPOCH_DELTA_US


def make_chrome(root: Path, downloads: Path, history_urls, dl_rows, extensions=(), homepage=None) -> Path:
    prof = root / "Default"; prof.mkdir(parents=True)
    prefs = {"download": {"default_directory": str(downloads)}}
    if homepage:
        prefs.update({"homepage": homepage, "homepage_is_newtabpage": False})
    (prof / "Preferences").write_text(json.dumps(prefs))
    con = sqlite3.connect(prof / "History")
    con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT, last_visit_time INT)")
    con.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, end_time INT, start_time INT, danger_type INT)")
    now = time.time()
    for i, u in enumerate(history_urls):
        con.execute("INSERT INTO urls (url,title,visit_count,last_visit_time) VALUES (?,?,1,?)", (u, "SECRET TITLE", US(now - 60 - i)))
    for path, src, danger in dl_rows:
        con.execute("INSERT INTO downloads (target_path,tab_url,end_time,start_time,danger_type) VALUES (?,?,?,?,?)", (str(path), src, US(now - 30), US(now - 60), danger))
    con.commit(); con.close()
    for eid, man in extensions:
        d = prof / "Extensions" / eid / "1.0_0"; d.mkdir(parents=True); (d / "manifest.json").write_text(json.dumps(man))
    # things Panzeron must never read
    (prof / "Login Data").write_bytes(b"PASSWORD-DB"); (prof / "Cookies").write_bytes(b"COOKIE-DB")
    return prof


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.dl = self.tmp / "dl"; self.dl.mkdir()
        (self.dl / "invoice.exe.txt").write_bytes(EICAR)                  # the real EICAR test string: harmless by design
        (self.dl / "notes.txt").write_text("hello")
        self.root = self.tmp / "chrome"
        self.prof = make_chrome(
            self.root, self.dl,
            ["https://www.example.com/page?token=SECRETTOKEN", "http://paypa1-secure-login.xyz/verify/account?redirect=http://evil.example",
             "https://github.com/x/y"],
            [(self.dl / "invoice.exe.txt", "https://dl.example.org/page", 0), (self.dl / "notes.txt", "https://example.com", 0),
             (self.tmp / "gone.exe", "https://bad.example/x", 1)],
            extensions=[("a" * 32, {"name": "Totally Fine Tool", "version": "1.0", "permissions": ["webRequest", "webRequestBlocking", "proxy", "<all_urls>"]}),
                        ("b" * 32, {"name": "Search Helper", "version": "2", "chrome_settings_overrides": {"search_provider": {"name": "x"}}}),
                        ("c" * 32, {"name": "Calm Notes", "version": "1", "permissions": ["storage"]})],
            homepage="http://paypa1-secure-login.xyz/verify/account")
        self.app = new_app()
        self.app.browser.overrides = {"chrome": self.root}
        self.app.browser.run_first_check = False

    def grant(self, **kw):
        return self.app.browser_access("grant", "chrome", kw.get("caps"), kw.get("automatic", False), True)

    # ---- consent is enforced by the engine ----
    def test_nothing_is_read_without_permission(self):
        with self.assertRaises(ConsentRequired) as c:
            self.app.browser_access("grant", "chrome", None, True, False)
        d = c.exception.details
        self.assertEqual(d["scope"], "browser")
        self.assertTrue(any("passwords" in p for p in d["promises"]))
        self.assertFalse(self.app.browser_status()["granted"])
        with self.assertRaises(ConsentRequired):
            self.app.browser.check()
        self.assertEqual(self.app.db.list_findings(), [])

    def test_permission_sheet_lists_only_the_files_it_will_read(self):
        with self.assertRaises(ConsentRequired) as c:
            self.app.browser_access("grant", "chrome", ["history"], False, False)
        roots = " ".join(c.exception.details["roots"])
        self.assertIn("History", roots)
        self.assertNotIn("Login Data", roots); self.assertNotIn("Cookies", roots); self.assertNotIn("Extensions", roots)

    def test_unknown_browser_or_capability_is_rejected(self):
        with self.assertRaises(ValueError): self.app.browser_access("grant", "netscape", None, False, True)
        with self.assertRaises(ValueError): self.app.browser_access("grant", "chrome", ["passwords"], False, True)
        with self.assertRaises(ValueError): self.app.browser_access("grant", "chrome", [], False, True)

    # ---- what a granted check does ----
    def test_full_check_finds_the_right_things_and_keeps_no_history(self):
        self.grant()
        s = self.app.browser.check()
        self.assertEqual(s["history_screened"], 3)
        fs = self.app.db.list_findings()
        titles = " | ".join(f.title for f in fs)
        self.assertIn("link found in your browser", titles)                    # the look-alike login URL
        self.assertIn("Browser flagged a download", titles)                    # danger_type=1 although the file is gone
        self.assertIn("Extension to review: Totally Fine Tool", titles)
        self.assertIn("Extension to review: Search Helper", titles)             # settings override
        self.assertNotIn("Calm Notes", titles)
        self.assertIn("suspicious page at start-up", titles)
        self.assertTrue(any(f.source_path and f.source_path.endswith("invoice.exe.txt") for f in fs), "downloaded EICAR file was scanned")
        blob = json.dumps([f.to_dict() for f in fs])
        for secret in ("SECRETTOKEN", "SECRET TITLE", "PASSWORD-DB", "COOKIE-DB", "github.com"):
            self.assertNotIn(secret, blob)                                    # no query strings, titles, credentials or ordinary history are stored
        self.assertNotIn("?", " ".join(e.source_ref for f in fs for e in f.evidence))

    def test_weak_signals_alone_do_not_raise_alarms(self):
        self.assertIsNone(browsers.screen_url("https://accounts.example.com/login?next=https://example.com/home&ref=" + "a" * 120))
        self.assertIsNotNone(browsers.screen_url("http://paypa1-secure-login.xyz/verify/account?redirect=http://evil.example"))

    def test_capabilities_are_individually_enforced(self):
        self.grant(caps=["extensions"])
        s = self.app.browser.check()
        self.assertEqual((s["history_screened"], s["downloads_checked"], s["startup_pages_checked"]), (0, 0, 0))
        self.assertTrue(all(f.category == "browser.extension" for f in self.app.db.list_findings()))

    def test_rechecking_does_not_duplicate_and_keeps_your_decisions(self):
        self.grant(); self.app.browser.check()
        fs = self.app.db.list_findings(); n = len(fs)
        victim = next(f for f in fs if f.category == "browser.extension")
        self.app.db.set_finding_status(victim.id, "resolved")
        again = self.app.browser.check()
        self.assertEqual(len(self.app.db.list_findings()), n)
        self.assertEqual(again["new_findings"], 0)
        self.assertEqual(self.app.db.get_finding(victim.id).status, "resolved")

    def test_locked_or_missing_files_are_reported_not_crashed(self):
        (self.prof / "History").unlink()
        self.grant(); s = self.app.browser.check()
        self.assertEqual(s["history_screened"], 0)

    def test_browser_files_are_not_modified(self):
        before = {p.name: p.read_bytes() for p in self.prof.iterdir() if p.is_file()}
        self.grant(); self.app.browser.check()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.prof.iterdir() if p.is_file()})

    # ---- automatic features ----
    def test_automatic_mode_adds_download_folder_to_watcher_and_quick_scan(self):
        self.grant(automatic=True)
        self.assertIn(str(self.dl), self.app.watcher_status()["paths"])
        quick = next(p for p in self.app.scope_plans() if p["id"] == "quick")
        self.assertIn(str(self.dl), quick["roots"])
        self.app.browser_access("revoke")
        self.assertNotIn(str(self.dl), self.app.watcher_status()["paths"])
        self.assertNotIn(str(self.dl), next(p for p in self.app.scope_plans() if p["id"] == "quick")["roots"])

    def test_manual_mode_does_not_touch_watcher_or_quick_scan(self):
        self.grant(automatic=False)
        self.assertNotIn(str(self.dl), self.app.watcher_status()["paths"])

    def test_turning_the_watcher_off_keeps_the_browser_folder_and_vice_versa(self):
        self.grant(automatic=True)
        self.app.set_watcher(False)
        self.assertIn(str(self.dl), self.app.watcher_status()["paths"])       # still allowed through browser protection
        self.app.browser_access("revoke")
        self.assertEqual(self.app.watcher_status()["paths"], [])

    def test_revoke_stops_everything_and_is_audited(self):
        self.grant(automatic=True); self.app.browser_access("revoke")
        st = self.app.browser_status()
        self.assertFalse(st["granted"])
        with self.assertRaises(ConsentRequired): self.app.browser.check()
        events = [e["event"] for e in self.app.audit.entries(50)]
        self.assertIn("browser.access_granted", events); self.assertIn("browser.access_revoked", events)
        self.assertTrue(self.app.audit.verify()["ok"])

    def test_automatic_loop_runs_checks_by_itself(self):
        self.app.browser.first_delay, self.app.browser.interval = 0.05, 0.3
        self.grant(automatic=True)
        for _ in range(60):
            if self.app.browser._state().get("last_check"): break
            time.sleep(0.1)
        self.assertTrue(self.app.browser._state().get("last_check"))
        self.app.browser_access("revoke")

    def test_consent_survives_restart_only_if_granted(self):
        self.grant(automatic=False)
        again = type(self.app)(self.app.paths.home); again.browser.overrides = {"chrome": self.root}
        self.assertTrue(again.browser_status()["granted"])
        self.app.browser_access("revoke")
        third = type(self.app)(self.app.paths.home)
        self.assertFalse(third.browser_status()["granted"])


class FirefoxTests(unittest.TestCase):
    def test_firefox_profile_reads(self):
        tmp = Path(tempfile.mkdtemp()); prof = tmp / "Profiles" / "abc.default"; prof.mkdir(parents=True)
        (tmp / "profiles.ini").write_text("[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default\n")
        (prof / "prefs.js").write_text('user_pref("browser.startup.homepage", "http://paypa1-secure-login.xyz/verify");\nuser_pref("browser.download.dir", "%s");\n' % str(tmp).replace("\\", "\\\\"))
        con = sqlite3.connect(prof / "places.sqlite")
        con.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, last_visit_date INT)")
        con.execute("INSERT INTO moz_places (url,last_visit_date) VALUES ('https://example.com/', ?)", (int(time.time() * 1e6),)); con.commit(); con.close()
        (prof / "extensions.json").write_text(json.dumps({"addons": [{"id": "x@y", "type": "extension", "active": True, "location": "app-profile", "defaultLocale": {"name": "Wide"},
                                                                       "userPermissions": {"permissions": ["webRequest", "cookies"], "origins": ["<all_urls>"]}}]}))
        info = browsers.detect({"firefox": tmp})["firefox"]
        p = info.profiles[0]
        self.assertEqual(len(browsers.read_history("firefox", p, 0)), 1)
        self.assertEqual(browsers.read_settings("firefox", p), ["http://paypa1-secure-login.xyz/verify"])
        self.assertEqual(browsers.download_dirs("firefox", p)[0], tmp)
        fs = browsers.extension_findings(browsers.read_extensions("firefox", p), "firefox", "Firefox")
        self.assertEqual(len(fs), 1)


if __name__ == "__main__":
    unittest.main()
