"""The rename to Panzeron: nothing of the old name is left except the small, deliberate carry-over code, and that carry-over really works
(data folder, "start with Windows" entry, environment variable)."""
import os
import tempfile
import unittest
from pathlib import Path

from panzeron import autostart
from panzeron.core import config, legacy
from tests.test_autostart import FakeReg

ROOT = Path(__file__).resolve().parent.parent
OLD = "ultri" + "mater"
ALLOWED = {"panzeron/core/legacy.py", "panzeron/autostart.py", "panzeron/web/js/theme-boot.js", "installer/panzeron.iss", "scripts/create_shortcut.ps1",
           "README.md", "tests/test_rename.py", "MANIFEST.sha256"}


class NothingOfTheOldNameIsLeft(unittest.TestCase):
    def test_no_old_name_outside_the_carry_over_code(self):
        hits = []
        for p in ROOT.rglob("*"):
            rel = p.relative_to(ROOT).as_posix()
            if not p.is_file() or ".git/" in rel or "__pycache__" in rel or p.suffix.lower() in {".png", ".ico", ".pyc", ".zip", ".db"} or rel in ALLOWED:
                continue
            try:
                if OLD in p.read_text(encoding="utf-8").lower():
                    hits.append(rel)
            except (UnicodeDecodeError, OSError):
                pass
            if OLD in rel.lower():
                hits.append(rel)
        self.assertEqual(hits, [])

    def test_names_are_the_new_ones(self):
        for rel in ("panzeron_app.py", "Panzeron.pyw", "assets/panzeron.ico", "installer/panzeron.iss", "panzeron/__init__.py"):
            self.assertTrue((ROOT / rel).exists(), rel)
        self.assertIn("Panzeron-Setup", (ROOT / "installer/panzeron.iss").read_text(encoding="utf-8"))
        self.assertIn("PANZERON_HOME", (ROOT / "panzeron/core/config.py").read_text(encoding="utf-8"))


class DataFolderCarryOver(unittest.TestCase):
    def test_old_folder_is_moved_once_with_everything_in_it(self):
        tmp = Path(tempfile.mkdtemp()); old, new = tmp / "Old", tmp / "New"
        (old / "vault").mkdir(parents=True); (old / "findings.db").write_bytes(b"data"); (old / "vault" / "q.bin").write_bytes(b"q"); (old / "gmail.secret").write_text("s")
        self.assertTrue(legacy.migrate_home(new, old))
        self.assertEqual((new / "findings.db").read_bytes(), b"data"); self.assertEqual((new / "vault" / "q.bin").read_bytes(), b"q"); self.assertTrue((new / "gmail.secret").exists())
        self.assertFalse(old.exists())
        self.assertFalse(legacy.migrate_home(new, old))                     # second start: nothing to do

    def test_never_overwrites_an_existing_new_folder(self):
        tmp = Path(tempfile.mkdtemp()); old, new = tmp / "Old", tmp / "New"
        old.mkdir(); (old / "a").write_text("old"); new.mkdir(); (new / "a").write_text("new")
        self.assertFalse(legacy.migrate_home(new, old))
        self.assertEqual((new / "a").read_text(), "new"); self.assertEqual((old / "a").read_text(), "old")        # both untouched

    def test_missing_old_folder_is_fine(self):
        tmp = Path(tempfile.mkdtemp())
        self.assertFalse(legacy.migrate_home(tmp / "New", tmp / "Nope")); self.assertFalse((tmp / "New").exists())

    def test_old_environment_variable_still_works_and_new_one_wins(self):
        saved = {k: os.environ.pop(k, None) for k in ("PANZERON_HOME", legacy.OLD_ENV)}
        try:
            os.environ[legacy.OLD_ENV] = "/tmp/from-old-var"
            self.assertEqual(config.default_home(), Path("/tmp/from-old-var"))
            os.environ["PANZERON_HOME"] = "/tmp/from-new-var"
            self.assertEqual(config.default_home(), Path("/tmp/from-new-var"))
        finally:
            for k in ("PANZERON_HOME", legacy.OLD_ENV): os.environ.pop(k, None)
            for k, v in saved.items():
                if v is not None: os.environ[k] = v


class StartupEntryCarryOver(unittest.TestCase):
    def test_enabled_old_entry_becomes_the_new_entry(self):
        reg = FakeReg(); reg.keys[autostart.RUN_KEY] = {autostart.LEGACY_VALUE_NAME: '"C:\\gone\\old.exe"', "SomethingElse": "keep"}
        self.assertTrue(autostart.migrate_legacy(reg))
        run = reg.run_values()
        self.assertNotIn(autostart.LEGACY_VALUE_NAME, run); self.assertIn("Panzeron", run); self.assertEqual(run["SomethingElse"], "keep")       # nothing else touched

    def test_entry_the_user_had_disabled_stays_off(self):
        reg = FakeReg(); reg.keys[autostart.RUN_KEY] = {autostart.LEGACY_VALUE_NAME: "x"}; reg.disable_in_task_manager(autostart.LEGACY_VALUE_NAME)
        self.assertTrue(autostart.migrate_legacy(reg))
        self.assertEqual(reg.run_values(), {})                                # old one removed, and not silently re-enabled

    def test_nothing_to_migrate(self):
        reg = FakeReg(); reg.keys[autostart.RUN_KEY] = {"Other": "x"}
        self.assertFalse(autostart.migrate_legacy(reg)); self.assertEqual(reg.run_values(), {"Other": "x"})
        self.assertFalse(autostart.migrate_legacy(FakeReg()))                 # no Run key at all


if __name__ == "__main__":
    unittest.main()
