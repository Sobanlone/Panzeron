"""Carry-over from the app's former name (Ultrimater), so nobody loses data or settings when upgrading to Panzeron.

This is the ONE place (besides the tiny early-boot script, the installer's old-shortcut clean-up and the startup-entry migration) that
still mentions the old name. Everything is move-or-keep, never delete user data: the old folder is MOVED to the new location only when
the new location does not exist yet.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .log import get_logger

log = get_logger("legacy")
OLD_NAME = "Ultrimater"
OLD_ENV = "ULTRIMATER_HOME"          # the old environment variable for the data folder is still honoured


def old_home() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / OLD_NAME
    return Path.home() / ("." + OLD_NAME.lower())


def migrate_home(new: Path, old: Path | None = None) -> bool:
    """Move the old data folder (findings, quarantine vault, audit log, settings, Gmail sign-in) to `new`, once. True if it moved."""
    old = old or old_home()
    try:
        if new.exists() or not old.is_dir():
            return False
        new.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(old, new)                                   # same drive: instant and atomic
        except OSError:
            shutil.copytree(old, new)                              # different drive: copy first, and keep the original until it worked
            shutil.rmtree(old, ignore_errors=True)
        log.info("moved data folder to its new name", extra={"ctx": {"from": str(old), "to": str(new)}})
        return True
    except OSError as e:                                            # never block start-up: the app just starts fresh if it cannot move
        log.warning("could not move the old data folder", extra={"ctx": {"error": str(e)[:160]}})
        return False
