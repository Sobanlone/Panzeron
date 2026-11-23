"""Desktop shell: runs Panzeron as a normal Windows application window (no browser tabs, no address bar).

How it works (no extra dependencies): the local engine starts in-process on 127.0.0.1, then the UI opens in an
"app mode" window of Microsoft Edge (WebView2/Chromium, present on every Windows 11 install) using a private profile.
Closing that window shuts the engine down. A second launch just opens another window on the running instance.
Chrome/Chromium are used if Edge is missing. If none exist the user gets a clear dialog, not a silent failure.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Callable

from .api.server import create_server
from .app import PanzeronApp
from .core.config import Paths
from .core.log import get_logger, setup_logging

log = get_logger("desktop")
WINDOW_SIZE = (1360, 880)


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
            "--no-first-run", "--no-default-browser-check", "--disable-sync"]


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


def run(launch: Callable[[str, Path], subprocess.Popen] | None = None, home: Path | None = None, port: int = 8765) -> int:
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
    try:
        proc = launch(url, profile)
        proc.wait()                    # blocks until the user closes the window
    finally:
        srv.shutdown()
        srv.server_close()
        lock.unlink(missing_ok=True)
        app.audit.append("system", "app.stop", {})
        app.db.close()
    return 0
