import unittest
from ultrimater import autostart


class FakeKey:
    def __init__(self, store): self.store = store
    def __enter__(self): return self
    def __exit__(self, *a): return False


class FakeReg:
    """A tiny stand-in for winreg with the two keys that matter: Run (the entry) and StartupApproved\\Run (Task Manager's switch)."""
    HKEY_CURRENT_USER = "HKCU"; KEY_READ = 1; KEY_SET_VALUE = 2; REG_SZ = 1
    def __init__(self): self.keys = {}              # path -> {name: value}
    def _store(self, path):
        assert path in (autostart.RUN_KEY, autostart.APPROVED_KEY), path
        return self.keys[path] if path in self.keys else None
    def OpenKey(self, hive, path, res=0, access=0):
        assert hive == "HKCU"
        st = self._store(path)
        if st is None: raise FileNotFoundError
        return FakeKey(st)
    def CreateKey(self, hive, path):
        assert hive == "HKCU"; self._store(path); return FakeKey(self.keys.setdefault(path, {}))
    def QueryValueEx(self, k, name):
        if name not in k.store: raise FileNotFoundError
        return k.store[name], 1
    def SetValueEx(self, k, name, _r, _t, val): k.store[name] = val
    def DeleteValue(self, k, name):
        if name not in k.store: raise FileNotFoundError
        del k.store[name]
    # helpers for the tests
    def run_values(self): return self.keys.get(autostart.RUN_KEY, {})
    def disable_in_task_manager(self, name="Ultrimater"):
        self.keys.setdefault(autostart.APPROVED_KEY, {})[name] = bytes([3]) + bytes(11)       # what Task Manager writes for "Disabled"


class AutostartTests(unittest.TestCase):
    def test_off_by_default_then_on_then_off(self):
        reg = FakeReg()
        self.assertFalse(autostart.status(reg)["enabled"])
        st = autostart.set_enabled(True, reg)
        self.assertTrue(st["enabled"] and st["current"])
        self.assertEqual(list(reg.run_values()), ["Ultrimater"])          # only its own value, nothing else touched
        self.assertTrue(reg.run_values()["Ultrimater"].startswith('"'))   # quoted path: safe with spaces
        self.assertFalse(autostart.set_enabled(False, reg)["enabled"])
        self.assertEqual(reg.run_values(), {})

    def test_disable_when_never_enabled_is_harmless(self):
        reg = FakeReg(); reg.keys[autostart.RUN_KEY] = {}
        self.assertFalse(autostart.set_enabled(False, reg)["enabled"])

    def test_not_windows_reports_unavailable(self):
        import sys
        if sys.platform != "win32":
            self.assertFalse(autostart.status()["available"])
            with self.assertRaises(RuntimeError): autostart.set_enabled(True)

    def test_turned_off_in_task_manager_is_reported_as_not_enabled(self):
        """Windows ignores a Run value that Task Manager disabled. The toggle must not claim it will start."""
        reg = FakeReg(); autostart.set_enabled(True, reg); reg.disable_in_task_manager()
        st = autostart.status(reg)
        self.assertFalse(st["enabled"]); self.assertTrue(st["blocked_by_windows"])

    def test_turning_it_on_again_clears_windows_disabled_marker_for_ultrimater_only(self):
        reg = FakeReg(); autostart.set_enabled(True, reg)
        reg.disable_in_task_manager(); reg.disable_in_task_manager("SomethingElse")
        st = autostart.set_enabled(True, reg)
        self.assertTrue(st["enabled"]); self.assertFalse(st["blocked_by_windows"])
        self.assertNotIn("Ultrimater", reg.keys[autostart.APPROVED_KEY])
        self.assertIn("SomethingElse", reg.keys[autostart.APPROVED_KEY])       # another app's switch is never touched

    def test_enabled_marker_values_do_not_count_as_disabled(self):
        reg = FakeReg(); autostart.set_enabled(True, reg)
        for first_byte in (2, 6):                                              # Windows' "enabled" encodings
            reg.keys[autostart.APPROVED_KEY] = {"Ultrimater": bytes([first_byte]) + bytes(11)}
            self.assertTrue(autostart.status(reg)["enabled"], first_byte)

    def test_entry_pointing_somewhere_else_is_flagged_as_not_current(self):
        reg = FakeReg(); autostart.set_enabled(True, reg)
        reg.keys[autostart.RUN_KEY]["Ultrimater"] = '"C:\\Old Place\\pythonw.exe" "C:\\Old Place\\Ultrimater.pyw"'
        st = autostart.status(reg)
        self.assertTrue(st["enabled"]); self.assertFalse(st["current"])        # the UI tells the user to switch it off and on to repair it

    def test_comparison_ignores_letter_case_of_the_path(self):
        reg = FakeReg(); autostart.set_enabled(True, reg)
        reg.keys[autostart.RUN_KEY]["Ultrimater"] = reg.keys[autostart.RUN_KEY]["Ultrimater"].upper()
        self.assertTrue(autostart.status(reg)["current"])                      # Windows paths are case-insensitive


if __name__ == "__main__": unittest.main()
