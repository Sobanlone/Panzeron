import runpy
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent


class LauncherTests(unittest.TestCase):
    def test_entry_point_runs_the_desktop_application(self):
        desktop = types.ModuleType("panzeron.desktop")
        desktop.main = lambda: 23
        with patch.dict(sys.modules, {"panzeron.desktop": desktop}):
            with self.assertRaises(SystemExit) as exc:
                runpy.run_path(str(ROOT / "panzeron_app.py"), run_name="__main__")
        self.assertEqual(exc.exception.code, 23)


if __name__ == "__main__":
    unittest.main()
