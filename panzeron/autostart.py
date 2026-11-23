"""Start Panzeron when you sign in to Windows.

Uses the per-user Run key (HKEY_CURRENT_USER\\...\\Run): no administrator rights, nothing outside your account, and you can see and
remove the entry in Task Manager > Startup apps. Panzeron only ever adds or removes its own "Panzeron" value, and the Shield's
startup review lists it like any other entry. Off by default; the user turns it on in Settings.

Windows keeps a second, separate switch for every startup entry (StartupApproved\\Run). If the user ever turned Panzeron off in Task
Manager, Windows ignores the Run value even though it is still there, so a naive "is the value present?" check reports "on" while
nothing ever starts. status() therefore reports that case honestly (enabled = False, blocked_by_windows = True), and turning the
option on from Settings clears Windows' "disabled" marker for Panzeron's own entry, which is exactly what the user just asked for.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APPROVED_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"   # Task Manager's on/off switch
VALUE_NAME = "Panzeron"


def launch_command() -> str | None:
    """The exact command Windows should run at sign-in: the installed exe, or pythonw + Panzeron.pyw (no console window)."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    pyw = Path(__file__).resolve().parent.parent / "Panzeron.pyw"
    if not pyw.is_file():
        return None
    exe = Path(sys.executable)
    pythonw = exe.with_name("pythonw.exe")
    return f'"{pythonw if pythonw.is_file() else exe}" "{pyw}"'


def _winreg(reg: Any = None) -> Any:
    if reg is not None:
        return reg
    if sys.platform != "win32":
        return None
    import winreg
    return winreg


def _disabled_in_windows(r: Any) -> bool:
    """True when the user switched this entry off in Task Manager > Startup apps (first byte odd, e.g. 03 = disabled; 02/06 = enabled)."""
    try:
        with r.OpenKey(r.HKEY_CURRENT_USER, APPROVED_KEY, 0, r.KEY_READ) as k:
            data, _ = r.QueryValueEx(k, VALUE_NAME)
        return bool(data) and bool(data[0] & 1)
    except (OSError, TypeError, IndexError):
        return False


def _clear_windows_switch(r: Any) -> None:
    """Remove Windows' on/off record for Panzeron's own entry only (no record = enabled). Never touches any other entry."""
    try:
        with r.OpenKey(r.HKEY_CURRENT_USER, APPROVED_KEY, 0, r.KEY_SET_VALUE) as k:
            r.DeleteValue(k, VALUE_NAME)
    except OSError:
        pass


def status(reg: Any = None) -> dict[str, Any]:
    r = _winreg(reg)
    if r is None:
        return {"available": False, "enabled": False, "reason": "Starting with Windows is only available on Windows."}
    cmd = launch_command()
    try:
        with r.OpenKey(r.HKEY_CURRENT_USER, RUN_KEY, 0, r.KEY_READ) as k:
            value, _ = r.QueryValueEx(k, VALUE_NAME)
    except FileNotFoundError:
        return {"available": cmd is not None, "enabled": False, "blocked_by_windows": False, "command": None, "current": False,
                "reason": None if cmd else "Could not locate the program to start."}
    except OSError as e:
        return {"available": False, "enabled": False, "reason": f"Windows refused access to the startup list: {e}"}
    blocked = _disabled_in_windows(r)
    return {"available": cmd is not None, "enabled": not blocked, "blocked_by_windows": blocked, "command": value,
            "current": cmd is not None and str(value).lower() == cmd.lower(),      # False = the entry points at another copy / an old location
            "reason": None if cmd else "Could not locate the program to start."}


def set_enabled(enabled: bool, reg: Any = None) -> dict[str, Any]:
    r = _winreg(reg)
    if r is None:
        raise RuntimeError("Starting with Windows is only available on Windows.")
    if enabled:
        cmd = launch_command()
        if cmd is None:
            raise RuntimeError("Could not locate the program to start.")
        with r.CreateKey(r.HKEY_CURRENT_USER, RUN_KEY) as k:
            r.SetValueEx(k, VALUE_NAME, 0, r.REG_SZ, cmd)
        _clear_windows_switch(r)       # the user explicitly asked for it: undo an earlier "disabled" in Task Manager
    else:
        try:
            with r.OpenKey(r.HKEY_CURRENT_USER, RUN_KEY, 0, r.KEY_SET_VALUE) as k:
                r.DeleteValue(k, VALUE_NAME)
        except FileNotFoundError:
            pass
        _clear_windows_switch(r)
    return status(reg)
