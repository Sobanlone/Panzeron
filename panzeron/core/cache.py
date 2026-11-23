"""Background cache: slow lookups (PowerShell, Ollama probes) must NEVER block the UI.

get() returns immediately with the last known value (or None while the first lookup is running); a refresh runs in a
single background thread (single-flight, so concurrent requests cannot spawn a pile of PowerShell processes).
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

from .log import get_logger

log = get_logger("cache")


class BackgroundCache:
    def __init__(self, fn: Callable[[], Any], ttl: float):
        self.fn, self.ttl = fn, ttl
        self._lock = threading.Lock()
        self._value: Any = None
        self._at = 0.0
        self._running = False
        self._done = threading.Event()
        self._done.set()
        self.last_error: str | None = None

    def refresh(self, force: bool = False) -> bool:
        """Start a background refresh unless one is already running. Returns True if one was started."""
        with self._lock:
            if self._running:
                return False
            if not force and self._at and time.monotonic() - self._at <= self.ttl:
                return False
            self._running = True
            self._done = threading.Event()
        threading.Thread(target=self._run, daemon=True, name="bg-cache").start()
        return True

    def _run(self) -> None:
        value, err = None, None
        try:
            value = self.fn()
        except Exception as e:  # keep the old value; the failure is logged, not swallowed
            err = f"{type(e).__name__}: {e}"
            log.warning("background refresh failed", extra={"ctx": {"error": err}})
        with self._lock:
            if value is not None:
                self._value = value
            self._at = time.monotonic()      # on failure too: back off for one TTL instead of retrying on every request
            self.last_error = err
            self._running = False
            self._done.set()

    def get(self, wait: float = 0.0) -> tuple[Any, bool]:
        """(value or None, refreshing). Never blocks longer than `wait` seconds, and only when there is no value yet."""
        self.refresh()
        with self._lock:
            value, done = self._value, self._done
        if value is None and wait > 0:
            done.wait(wait)
            with self._lock:
                value = self._value
        with self._lock:
            return value, self._running

    def invalidate(self) -> None:
        with self._lock:
            self._at = 0.0
