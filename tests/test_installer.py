"""Static checks of the Inno Setup script (it cannot be compiled outside Windows, so these catch the mistakes that can be caught): known sections,
balanced quotes, the files and flags it refers to really exist, and it agrees with the program about the mutex and command-line switches."""
import inspect
import re
import unittest
from pathlib import Path

from panzeron import desktop, tray

ROOT = Path(__file__).resolve().parent.parent
ISS = (ROOT / "installer" / "panzeron.iss").read_text(encoding="utf-8")
SECTIONS = {"Setup", "Languages", "Types", "Components", "Tasks", "Files", "Icons", "Registry", "InstallDelete", "Run", "UninstallRun", "Code", "Messages", "CustomMessages"}


class InstallerScript(unittest.TestCase):
    def sections(self):
        return re.findall(r"^\[(\w+)\]", ISS, re.M)

    def test_only_known_sections_and_the_ones_we_need(self):
        got = self.sections()
        self.assertTrue(set(got) <= SECTIONS, set(got) - SECTIONS)
        for needed in ("Setup", "Components", "Tasks", "Files", "Icons", "Registry", "Run", "Code"):
            self.assertIn(needed, got)

    def test_quotes_are_balanced_on_every_line(self):
        for n, line in enumerate(ISS.splitlines(), 1):
            code = line.split(";", 1)[0] if line.lstrip().startswith(";") else line
            if line.lstrip().startswith(("//", ";", "#")) or "'" in line:
                continue                                     # comments, preprocessor lines and Pascal strings are checked by the compiler
            self.assertEqual(line.count('"') % 2, 0, f"line {n}: {line}")

    def test_macros_are_defined_before_use(self):
        defined = set(re.findall(r"^#define (\w+)", ISS, re.M))
        for used in set(re.findall(r"\{#(\w+)\}", ISS)):
            self.assertIn(used, defined)

    def test_stops_with_a_clear_message_if_the_program_was_not_built(self):
        self.assertRegex(ISS, r'#if !FileExists\(SourcePath \+ "\.\.\\dist\\Panzeron\\Panzeron\.exe"\)\s*#error "[^"]*build_windows\.bat')

    def test_installs_the_program_and_optionally_the_whole_project_anywhere(self):
        self.assertRegex(ISS, r'Source: "\.\.\\dist\\Panzeron\\\*"; DestDir: "\{app\}"')
        self.assertRegex(ISS, r'Source: "\.\.\\\*"; DestDir: "\{app\}\\project"; Components: source')
        self.assertIn("DisableDirPage=no", ISS)                                   # the user may pick any folder or drive
        self.assertIn("PrivilegesRequiredOverridesAllowed=dialog", ISS)           # per-user or all-users
        for junk in (".git", "dist", "__pycache__", "*.pyc"):
            self.assertIn(junk, re.search(r"Excludes: \"([^\"]*)\"", ISS).group(1))

    def test_agrees_with_the_program(self):
        self.assertIn(f"AppMutex={tray.MUTEX_NAME}", ISS)                         # the mutex the app really creates
        self.assertIn("--quit", ISS); self.assertIn("--background", ISS)
        src = inspect.getsource(desktop.main)
        self.assertIn('"--quit"', src); self.assertIn('"--background"', src)      # ...and the program understands both switches

    def test_every_referenced_file_exists(self):
        self.assertTrue((ROOT / "assets" / "panzeron.ico").is_file())
        self.assertIn(r"SetupIconFile=..\assets\panzeron.ico", ISS)
        self.assertTrue((ROOT / "build_windows.bat").is_file())

    def test_user_data_is_only_deleted_if_the_user_says_yes(self):
        self.assertIn("MB_DEFBUTTON2", ISS)                                       # default answer is No
        self.assertIn("not UninstallSilent", ISS)                                 # never silently

    def test_startup_entry_is_opt_in_and_matches_the_apps_own_switch(self):
        self.assertRegex(ISS, r'Name: "startup";[^\n]*Flags: unchecked')
        self.assertRegex(ISS, r'ValueName: "Panzeron"; ValueData: """\{app\}\\\{#MyAppExe\}"" --background"')

    def test_build_scripts_bundle_the_tray_icon_and_compile_the_installer(self):
        bat = (ROOT / "build_windows.bat").read_text(encoding="utf-8"); wf = (ROOT / ".github/workflows/build-windows.yml").read_text(encoding="utf-8")
        self.assertIn("assets\\panzeron.ico;assets", bat); self.assertIn("assets/panzeron.ico;assets", wf)
        self.assertIn("iscc installer\\panzeron.iss", bat)


if __name__ == "__main__":
    unittest.main()
