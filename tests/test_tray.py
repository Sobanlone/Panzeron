"""Tray behaviour of the desktop shell, tested with a stand-in tray (the real one is Windows-only): closing the window keeps Panzeron running,
only Quit stops it, a background start shows no window, and a tray that cannot start falls back to the old close-quits behaviour."""
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from panzeron import desktop, tray


class FakeTray:
    instances: list = []

    def __init__(self, on_open, on_quit, starts=True):
        self.on_open, self.on_quit, self.starts = on_open, on_quit, starts
        self.notes, self.stopped = [], False
        FakeTray.instances.append(self)

    def start(self): return self.starts
    def notify(self, title, text): self.notes.append((title, text))
    def stop(self): self.stopped = True


class FakeWindow:
    """A window process we can close on demand."""
    def __init__(self): self.closed = threading.Event(); self.terminated = False
    def wait(self): self.closed.wait(20)
    def poll(self): return 0 if self.closed.is_set() else None
    def terminate(self): self.terminated = True; self.closed.set()


class Harness:
    def __init__(self, background=False, tray_starts=True):
        FakeTray.instances.clear()
        self.home, self.windows, self.urls, self.rc = Path(tempfile.mkdtemp()), [], [], []
        def launch(url, profile):
            w = FakeWindow(); self.windows.append(w); self.urls.append(url); return w
        factory = lambda o, q: FakeTray(o, q, tray_starts)  # noqa: E731
        self.thread = threading.Thread(target=lambda: self.rc.append(desktop.run(launch=launch, home=self.home, port=0, background=background, tray_factory=factory)))
        self.thread.start()
        for _ in range(100):
            if (self.home / "instance.json").exists() and FakeTray.instances: break
            time.sleep(0.05)
        self.tray = FakeTray.instances[0]

    def url(self): return f"http://127.0.0.1:{__import__('json').loads((self.home / 'instance.json').read_text())['port']}/"
    def alive(self):
        try: urllib.request.urlopen(self.url(), timeout=1); return True
        except Exception: return False
    def wait_for(self, cond, secs=5):
        for _ in range(int(secs * 20)):
            if cond(): return True
            time.sleep(0.05)
        return False
    def finish(self):
        self.tray.on_quit(); self.thread.join(10)


class TrayBehaviour(unittest.TestCase):
    def test_closing_the_window_keeps_panzeron_running_in_the_tray(self):
        h = Harness(); self.assertTrue(h.wait_for(lambda: len(h.windows) == 1))
        h.windows[0].closed.set()                                         # the user clicks the window's X
        self.assertTrue(h.wait_for(lambda: len(h.tray.notes) == 1))       # told once that it is still running
        self.assertTrue(h.alive()); self.assertTrue(h.thread.is_alive()); self.assertTrue((h.home / "instance.json").exists())
        h.finish()

    def test_only_quit_from_the_tray_stops_it(self):
        h = Harness(); self.assertTrue(h.wait_for(lambda: len(h.windows) == 1))
        h.windows[0].closed.set(); h.wait_for(lambda: h.tray.notes)
        h.tray.on_quit(); h.thread.join(10)
        self.assertFalse(h.thread.is_alive()); self.assertEqual(h.rc, [0])
        self.assertFalse((h.home / "instance.json").exists()); self.assertTrue(h.tray.stopped)

    def test_quit_also_closes_an_open_window(self):
        h = Harness(); self.assertTrue(h.wait_for(lambda: len(h.windows) == 1))
        h.tray.on_quit(); h.thread.join(10)
        self.assertTrue(h.windows[0].terminated); self.assertFalse(h.thread.is_alive())

    def test_tray_open_reopens_the_window_after_it_was_closed(self):
        h = Harness(); self.assertTrue(h.wait_for(lambda: len(h.windows) == 1))
        h.windows[0].closed.set(); h.wait_for(lambda: h.tray.notes)
        h.tray.on_open()
        self.assertEqual(len(h.windows), 2); self.assertEqual(h.urls[0], h.urls[1])        # same engine, a new window
        h.finish()

    def test_open_while_a_window_is_already_open_does_not_stack_windows(self):
        h = Harness(); self.assertTrue(h.wait_for(lambda: len(h.windows) == 1))
        h.tray.on_open(); h.tray.on_open()
        self.assertEqual(len(h.windows), 1)
        h.finish()

    def test_background_start_shows_no_window_until_asked(self):
        h = Harness(background=True); time.sleep(0.5)
        self.assertEqual(len(h.windows), 0); self.assertTrue(h.alive())    # protecting, invisible
        h.tray.on_open(); self.assertEqual(len(h.windows), 1)
        h.finish()

    def test_tray_that_cannot_start_falls_back_to_close_quits(self):
        h = Harness(background=True, tray_starts=False)                    # even a background start must show a window if there is no tray
        self.assertTrue(h.wait_for(lambda: len(h.windows) == 1))
        h.windows[0].closed.set(); h.thread.join(10)
        self.assertFalse(h.thread.is_alive()); self.assertEqual(h.rc, [0]); self.assertFalse(h.tray.notes)

    def test_second_launch_in_background_does_nothing_and_normal_launch_uses_running_engine(self):
        h = Harness(); self.assertTrue(h.wait_for(lambda: len(h.windows) == 1))
        extra = []
        self.assertEqual(desktop.run(launch=lambda u, p: extra.append(u), home=h.home, port=0, background=True), 0); self.assertEqual(extra, [])
        self.assertEqual(desktop.run(launch=lambda u, p: extra.append(u), home=h.home, port=0), 0); self.assertEqual(extra, [h.urls[0]])
        h.finish()


class TrayModuleBasics(unittest.TestCase):
    def test_win32_api_is_cached(self):
        if sys.platform == "win32":
            self.assertIs(tray._api(), tray._api())

    def test_helpers_are_harmless_where_there_is_no_windows_tray(self):
        if sys.platform != "win32":
            self.assertFalse(tray.available()); self.assertFalse(tray.request_quit()); self.assertFalse(tray.request_open()); self.assertFalse(tray.focus_window())
            self.assertTrue(tray.create_mutex()); self.assertFalse(tray.Tray("x.ico", lambda: None, lambda: None).start())

    def test_message_ids_are_distinct_and_in_the_app_range(self):
        ids = [tray.MSG_TRAY, tray.MSG_QUIT_REQUEST, tray.MSG_OPEN_REQUEST, tray.MSG_NOTIFY]
        self.assertEqual(len(set(ids)), 4); self.assertTrue(all(i >= tray.WM_APP for i in ids))

    def test_menu_offers_open_and_quit(self):
        self.assertIn("Open", tray.MENU_OPEN); self.assertIn("Quit", tray.MENU_QUIT)

    def test_icon_file_is_found_from_source(self):
        self.assertTrue(desktop.icon_path().is_file())

    def test_command_line(self):
        calls = []
        orig_run, orig_quit = desktop.run, tray.request_quit
        desktop.run = lambda **kw: calls.append(kw) or 0; tray.request_quit = lambda: calls.append("quit") or True
        try:
            desktop.main(["--background"]); desktop.main([]); desktop.main(["--quit"])
        finally:
            desktop.run, tray.request_quit = orig_run, orig_quit
        self.assertEqual(calls, [{"port": 8765, "background": True}, {"port": 8765, "background": False}, "quit"])


if __name__ == "__main__":
    unittest.main()
