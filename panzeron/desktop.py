"""Desktop shell: runs Panzeron as a normal Windows application window (no browser tabs, no address bar).

How it works (no extra dependencies): the local engine starts in-process on 127.0.0.1, then the UI opens in an
"app mode" window of Microsoft Edge (WebView2/Chromium, present on every Windows 11 install) using a private profile.
Closing that window leaves the engine running in the system tray; choose Quit Panzeron there to stop it. A second launch
opens the existing instance. Chrome/Chromium are used if Edge is missing. If none exist the user gets a clear dialog.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Any, Callable

from .api.server import create_server
from .app import PanzeronApp
from .core.config import Paths
from .core.log import get_logger, setup_logging
from . import tray

log = get_logger("desktop")
WINDOW_SIZE = (1360, 880)


def icon_path() -> Path:
    """Find the bundled tray icon in source and PyInstaller builds."""
    bundle = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
    return bundle / "assets" / "panzeron.ico"


def find_app_browser() -> str | None:
    cands: list[str] = []
    for var in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA"):
        base = os.environ.get(var)
        if base:
            cands += [os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
                      os.path.join(base, "Google", "Chrome", "Application", "chrome.exe")]
    for c in cands:
        if os.path.isfile(c):
            return c
    for name in ("msedge", "google-chrome", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    return None


def build_command(exe: str, url: str, profile_dir: Path, size: tuple[int, int] = WINDOW_SIZE) -> list[str]:
    return [exe, f"--app={url}", f"--user-data-dir={profile_dir}", f"--window-size={size[0]},{size[1]}",
            "--no-first-run", "--no-default-browser-check", "--disable-sync", "--autoplay-policy=no-user-gesture-required"]


def show_error(title: str, message: str) -> None:
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)  # MB_ICONERROR
    else:
        print(f"{title}: {message}", file=sys.stderr)


def _lock_file(paths: Paths) -> Path:
    return paths.home / "instance.json"


def running_instance_url(paths: Paths) -> str | None:
    """URL of an already-running Panzeron engine, or None. Stale lock files are ignored."""
    try:
        port = json.loads(_lock_file(paths).read_text())["port"]
        url = f"http://127.0.0.1:{int(port)}/"
        with urllib.request.urlopen(url, timeout=1.5) as r:
            return url if b"panzeron" in r.read(4096).lower() else None
    except Exception:
        return None


def run(
    launch: Callable[[str, Path], subprocess.Popen] | None = None,
    home: Path | None = None,
    port: int = 8765,
    background: bool = False,
    tray_factory: Callable[[Callable[[], None], Callable[[], None]], Any] | None = None,
) -> int:
    tray.create_mutex()
    paths = Paths.create(home)
    setup_logging(paths.logs)
    profile = paths.home / "window-profile"
    profile.mkdir(exist_ok=True)

    if launch is None:
        exe = find_app_browser()
        if not exe:
            show_error("Panzeron", "Panzeron needs Microsoft Edge (included with Windows 11) or Google Chrome to display its window. "
                                     "Please install one and start Panzeron again.")
            return 1
        launch = lambda url, prof: subprocess.Popen(build_command(exe, url, prof))  # noqa: E731

    existing = running_instance_url(paths)
    if existing:                       # second launch: just open another window on the running engine
        if background:
            return 0
        if not tray.request_open():
            launch(existing, profile)
        return 0

    app = PanzeronApp(paths.home)
    try:
        srv, _ = create_server(app, port)
    except OSError:
        srv, _ = create_server(app, 0)     # preferred port busy
    real_port = srv.server_address[1]
    url = f"http://127.0.0.1:{real_port}/"
    lock = _lock_file(paths)
    lock.write_text(json.dumps({"port": real_port, "pid": os.getpid()}))
    threading.Thread(target=srv.serve_forever, daemon=True, name="panzeron-engine").start()
    log.info(f"engine listening on {url}")
    quit_requested = threading.Event()
    window_lock = threading.Lock()
    window: subprocess.Popen | None = None

    def open_window() -> None:
        nonlocal window
        with window_lock:
            if window is not None and window.poll() is None:
                tray.focus_window()
                return
            window = launch(url, profile)

    def quit_app() -> None:
        quit_requested.set()
        with window_lock:
            if window is not None and window.poll() is None:
                window.terminate()

    make_tray = tray_factory or (
        lambda on_open, on_quit: tray.Tray(str(icon_path()), on_open, on_quit)
    )
    tray_icon = make_tray(open_window, quit_app)
    tray_started = False
    try:
        tray_started = tray_icon.start()
        if not background or not tray_started:
            open_window()
        while not quit_requested.wait(0.1):
            with window_lock:
                if window is not None and window.poll() is not None:
                    window = None
                    if tray_started and not quit_requested.is_set():
                        tray_icon.notify("Panzeron is still running", "Choose Quit Panzeron from the tray icon to close it.")
                    elif not tray_started:
                        quit_requested.set()
    finally:
        tray_icon.stop()
        with window_lock:
            if window is not None and window.poll() is None:
                window.terminate()
        srv.shutdown()
        srv.server_close()
        lock.unlink(missing_ok=True)
        app.audit.append("system", "app.stop", {})
        app.db.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="Panzeron")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--background", action="store_true", help="start in the system tray without opening a window")
    ap.add_argument("--quit", action="store_true", help="quit a running Panzeron from another process")
    args = ap.parse_args(argv)
    if args.quit:
        tray.request_quit()
        return 0
    return run(port=args.port, background=args.background)
