import subprocess, sys, tempfile, threading, time, unittest, urllib.error, urllib.request
from pathlib import Path
from unittest import mock
from panzeron import desktop
from panzeron.core.config import Paths


class UnavailableTray:
    def start(self): return False
    def stop(self): pass


def stub_window(seconds):
    """Stands in for the Edge app window: stays 'open' for a while, then exits (= user closed the window)."""
    return lambda url, profile: subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({seconds})"])


class DesktopTests(unittest.TestCase):
    def test_app_window_command_has_no_browser_chrome(self):
        cmd = desktop.build_command("msedge.exe", "http://127.0.0.1:1/", Path("p"))
        self.assertIn("--app=http://127.0.0.1:1/", cmd); self.assertTrue(any(c.startswith("--user-data-dir=") for c in cmd))
        self.assertIn("--autoplay-policy=no-user-gesture-required", cmd)

    def test_edge_is_preferred_on_windows_paths(self):
        d = Path(tempfile.mkdtemp()); edge = d / "Microsoft" / "Edge" / "Application"; edge.mkdir(parents=True); (edge / "msedge.exe").write_text("")
        with mock.patch.dict("os.environ", {"PROGRAMFILES(X86)": str(d)}, clear=False):
            self.assertEqual(desktop.find_app_browser(), str(edge / "msedge.exe"))

    def test_window_close_stops_engine_and_removes_lock(self):
        home = Path(tempfile.mkdtemp()); seen = {}
        def launch(url, profile):
            seen["url"] = url; seen["body"] = urllib.request.urlopen(url).read().decode()   # engine is up while the window is open
            return stub_window(0.4)(url, profile)
        self.assertEqual(desktop.run(launch=launch, home=home, port=0, tray_factory=lambda _open, _quit: UnavailableTray()), 0)
        self.assertIn("panzeron", seen["body"].lower())
        with self.assertRaises(urllib.error.URLError): urllib.request.urlopen(seen["url"], timeout=1)   # engine stopped
        self.assertFalse((home / "instance.json").exists())

    def test_second_launch_reuses_running_engine(self):
        home = Path(tempfile.mkdtemp()); urls = []
        def launch1(url, profile): urls.append(url); return stub_window(2.0)(url, profile)
        t = threading.Thread(target=lambda: desktop.run(launch=launch1, home=home, port=0, tray_factory=lambda _open, _quit: UnavailableTray())); t.start()
        for _ in range(50):
            if urls: break
            time.sleep(0.05)
        second = []
        rc = desktop.run(launch=lambda u, p: second.append(u), home=home, port=0)
        self.assertEqual(rc, 0); self.assertEqual(second, [urls[0]])      # same engine, not a new one
        t.join()

    def test_missing_browser_gives_clear_error_not_silence(self):
        with mock.patch.object(desktop, "find_app_browser", return_value=None), mock.patch.object(desktop, "show_error") as err:
            self.assertEqual(desktop.run(home=Path(tempfile.mkdtemp())), 1)
        self.assertIn("Edge", err.call_args[0][1])

    def test_stale_lock_is_ignored(self):
        home = Path(tempfile.mkdtemp()); paths = Paths.create(home)
        (paths.home / "instance.json").write_text('{"port": 1, "pid": 0}')
        self.assertIsNone(desktop.running_instance_url(paths))

    def test_packaged_web_assets_exist(self):
        web = Path(desktop.__file__).parent / "web"
        for f in ("index.html", "favicon.png", "js/app.js", "css/app.css"): self.assertTrue((web / f).is_file(), f)
        self.assertTrue((Path(desktop.__file__).parent.parent / "assets" / "panzeron.ico").is_file())
