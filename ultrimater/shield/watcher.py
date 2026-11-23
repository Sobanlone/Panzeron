"""Downloads watcher: scans NEW files appearing in folders you approved, while Ultrimater is open.

Honest scope: this is a user-space folder monitor (polling), NOT kernel-level real-time protection. It cannot block a program from
running; it tells you quickly when something suspicious has landed. Files are scanned once they stop growing (so half-downloaded
files are not judged) and partial-download extensions are ignored.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

from ..core.log import get_logger

log = get_logger("watcher")
PARTIAL = (".crdownload", ".part", ".tmp", ".download", ".partial", ".opdownload")


class FolderWatcher:
    def __init__(self, scan_file: Callable[[Path], list[Any]], on_findings: Callable[[Path, list[Any]], None], poll: float = 3.0):
        self.scan_file, self.on_findings, self.poll = scan_file, on_findings, poll
        self._paths: list[Path] = []
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.recent: deque[dict[str, Any]] = deque(maxlen=50)
        self.scanned_count = 0
        self.detected = 0

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self, paths: list[Path]) -> None:
        self.stop()
        self._paths = [p for p in paths if p.is_dir()]
        self._stop.clear()
        if not self._paths:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="folder-watcher")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=self.poll + 2)
        self._thread = None

    def status(self) -> dict[str, Any]:
        return {"running": self.running, "paths": [str(p) for p in self._paths], "scanned": self.scanned_count, "detected": self.detected, "recent": list(self.recent)}

    @staticmethod
    def _snapshot(d: Path) -> dict[str, tuple[int, float]]:
        out = {}
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_file(follow_symlinks=False):
                            st = e.stat(follow_symlinks=False)
                            out[e.path] = (st.st_size, st.st_mtime)
                    except OSError:
                        continue
        except OSError:
            pass
        return out

    def _loop(self) -> None:
        seen: dict[str, tuple[int, float]] = {}       # already handled (or pre-existing) files
        pending: dict[str, tuple[int, float]] = {}    # new files waiting to stop changing
        for d in self._paths:                         # files that already exist are NOT scanned by the watcher (use a scan for those)
            seen.update(self._snapshot(d))
        while not self._stop.wait(self.poll):
            for d in self._paths:
                for path, sig in self._snapshot(d).items():
                    if seen.get(path) == sig or path.lower().endswith(PARTIAL):
                        continue
                    if pending.get(path) == sig:      # unchanged since the previous poll: the download has finished
                        seen[path] = sig
                        pending.pop(path, None)
                        self._handle(Path(path))
                    else:
                        pending[path] = sig

    def _handle(self, p: Path) -> None:
        try:
            findings = self.scan_file(p)
        except Exception as e:                        # a failure is recorded, never silent
            log.warning("watcher scan failed", extra={"ctx": {"path": str(p), "error": str(e)}})
            self.recent.appendleft({"path": str(p), "time": time.strftime("%H:%M:%S"), "result": f"could not scan: {e}", "findings": 0})
            return
        self.scanned_count += 1
        self.recent.appendleft({"path": str(p), "time": time.strftime("%H:%M:%S"), "result": "flagged" if findings else "clean", "findings": len(findings)})
        if findings:
            self.detected += 1
            self.on_findings(p, findings)
