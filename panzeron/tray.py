"""System-tray icon for Windows, written with ctypes only (no extra packages, nothing to install).

What the user gets: closing the Panzeron window does NOT stop protection. Panzeron keeps running in the tray, still watching downloads and
running its automatic checks. Left-click the tray icon (or choose "Open Panzeron") to bring the window back. The app only really stops when
the user chooses "Quit Panzeron" from the tray menu (or runs `Panzeron.exe --quit`, which the installer does before upgrading/uninstalling).

Everything Windows-specific lives behind `sys.platform == "win32"`; on any other system the helpers are harmless no-ops, which is also how the
tests run. A tray that cannot start is never fatal: the desktop shell then behaves like before (closing the window quits).
"""
from __future__ import annotations

import sys
import threading
from functools import lru_cache
from typing import Any, Callable

from .core.log import get_logger

log = get_logger("tray")

WINDOW_CLASS = "PanzeronTrayWindow"           # hidden window that receives the tray events; also how a second process finds this one
MUTEX_NAME = "Panzeron-Instance"              # the installer's AppMutex: lets Setup know Panzeron is running
WM_APP = 0x8000
MSG_TRAY = WM_APP + 1                         # events from the tray icon (mouse)
MSG_QUIT_REQUEST = WM_APP + 2                 # another process asks this one to quit (Panzeron.exe --quit)
MSG_OPEN_REQUEST = WM_APP + 3                 # another process asks this one to show its window
MSG_NOTIFY = WM_APP + 4                       # show a balloon message (posted so it runs on the tray thread)
ID_OPEN, ID_QUIT = 1, 2
MENU_OPEN, MENU_QUIT = "Open Panzeron", "Quit Panzeron"
TOOLTIP = "Panzeron: protecting this computer"

_mutex_handle: Any = None


def available() -> bool:
    return sys.platform == "win32"


@lru_cache(maxsize=1)
def _api() -> Any:
    """The few Win32 functions we need, with exact 64-bit-safe signatures. Only ever called on Windows."""
    import ctypes
    from ctypes import wintypes as w

    LRESULT, WPARAM, LPARAM = ctypes.c_ssize_t, ctypes.c_size_t, ctypes.c_ssize_t     # LONG_PTR sizes (wintypes' LPARAM is 32-bit: wrong on x64)
    HANDLE = ctypes.c_void_p
    user32, kernel32, shell32 = ctypes.windll.user32, ctypes.windll.kernel32, ctypes.windll.shell32

    class WNDCLASSW(ctypes.Structure):
        pass
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, HANDLE, ctypes.c_uint, WPARAM, LPARAM)
    WNDCLASSW._fields_ = [("style", ctypes.c_uint), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int), ("hInstance", HANDLE),
                          ("hIcon", HANDLE), ("hCursor", HANDLE), ("hbrBackground", HANDLE), ("lpszMenuName", w.LPCWSTR), ("lpszClassName", w.LPCWSTR)]

    class GUID(ctypes.Structure):
        _fields_ = [("a", ctypes.c_ulong), ("b", ctypes.c_ushort), ("c", ctypes.c_ushort), ("d", ctypes.c_ubyte * 8)]

    class NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_ulong), ("hWnd", HANDLE), ("uID", ctypes.c_uint), ("uFlags", ctypes.c_uint), ("uCallbackMessage", ctypes.c_uint), ("hIcon", HANDLE),
                    ("szTip", ctypes.c_wchar * 128), ("dwState", ctypes.c_ulong), ("dwStateMask", ctypes.c_ulong), ("szInfo", ctypes.c_wchar * 256),
                    ("uTimeout", ctypes.c_uint), ("szInfoTitle", ctypes.c_wchar * 64), ("dwInfoFlags", ctypes.c_ulong), ("guidItem", GUID), ("hBalloonIcon", HANDLE)]

    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    class MSG(ctypes.Structure):
        _fields_ = [("hwnd", HANDLE), ("message", ctypes.c_uint), ("wParam", WPARAM), ("lParam", LPARAM), ("time", ctypes.c_ulong), ("pt", POINT)]

    user32.DefWindowProcW.argtypes, user32.DefWindowProcW.restype = [HANDLE, ctypes.c_uint, WPARAM, LPARAM], LRESULT
    user32.RegisterClassW.argtypes, user32.RegisterClassW.restype = [ctypes.POINTER(WNDCLASSW)], ctypes.c_ushort
    user32.CreateWindowExW.argtypes = [ctypes.c_ulong, w.LPCWSTR, w.LPCWSTR, ctypes.c_ulong, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, HANDLE, HANDLE, HANDLE, HANDLE]
    user32.CreateWindowExW.restype = HANDLE
    user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), HANDLE, ctypes.c_uint, ctypes.c_uint]
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
    user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
    user32.PostMessageW.argtypes, user32.PostMessageW.restype = [HANDLE, ctypes.c_uint, WPARAM, LPARAM], ctypes.c_int
    user32.FindWindowW.argtypes, user32.FindWindowW.restype = [w.LPCWSTR, w.LPCWSTR], HANDLE
    user32.DestroyWindow.argtypes = [HANDLE]
    user32.LoadImageW.argtypes, user32.LoadImageW.restype = [HANDLE, w.LPCWSTR, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_uint], HANDLE
    user32.LoadIconW.argtypes, user32.LoadIconW.restype = [HANDLE, HANDLE], HANDLE
    user32.CreatePopupMenu.restype = HANDLE
    user32.AppendMenuW.argtypes = [HANDLE, ctypes.c_uint, ctypes.c_size_t, w.LPCWSTR]
    user32.SetMenuDefaultItem.argtypes = [HANDLE, ctypes.c_uint, ctypes.c_uint]
    user32.TrackPopupMenu.argtypes = [HANDLE, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int, HANDLE, HANDLE]
    user32.DestroyMenu.argtypes = [HANDLE]
    user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
    user32.SetForegroundWindow.argtypes = [HANDLE]
    user32.RegisterWindowMessageW.argtypes, user32.RegisterWindowMessageW.restype = [w.LPCWSTR], ctypes.c_uint
    user32.ShowWindow.argtypes = [HANDLE, ctypes.c_int]
    user32.IsIconic.argtypes = [HANDLE]
    user32.IsWindowVisible.argtypes = [HANDLE]
    user32.GetClassNameW.argtypes = [HANDLE, w.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.argtypes = [HANDLE, w.LPWSTR, ctypes.c_int]
    ENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_int, HANDLE, LPARAM)
    user32.EnumWindows.argtypes = [ENUMPROC, LPARAM]
    shell32.Shell_NotifyIconW.argtypes, shell32.Shell_NotifyIconW.restype = [ctypes.c_ulong, ctypes.POINTER(NOTIFYICONDATAW)], ctypes.c_int
    kernel32.GetModuleHandleW.argtypes, kernel32.GetModuleHandleW.restype = [w.LPCWSTR], HANDLE
    kernel32.CreateMutexW.argtypes, kernel32.CreateMutexW.restype = [HANDLE, ctypes.c_int, w.LPCWSTR], HANDLE

    class Api:
        pass
    a = Api()
    a.ctypes, a.user32, a.kernel32, a.shell32 = ctypes, user32, kernel32, shell32
    a.WNDCLASSW, a.WNDPROC, a.NOTIFYICONDATAW, a.POINT, a.MSG, a.ENUMPROC, a.LRESULT = WNDCLASSW, WNDPROC, NOTIFYICONDATAW, POINT, MSG, ENUMPROC, LRESULT
    return a


# ---- helpers used by the desktop shell and by other processes -------------------------------------------------------------------
def create_mutex() -> bool:
    """Marks this process as THE running Panzeron (the installer waits for it to quit). Always True where mutexes do not exist."""
    global _mutex_handle
    if not available():
        return True
    try:
        a = _api()
        _mutex_handle = a.kernel32.CreateMutexW(None, False, MUTEX_NAME)
        return True
    except Exception:
        return True


def _post(msg: int) -> bool:
    if not available():
        return False
    try:
        a = _api()
        hwnd = a.user32.FindWindowW(WINDOW_CLASS, None)
        return bool(hwnd) and bool(a.user32.PostMessageW(hwnd, msg, 0, 0))
    except Exception:
        return False


def request_quit() -> bool:
    """Ask the running Panzeron to quit (what `Panzeron.exe --quit` does). True if one was running."""
    return _post(MSG_QUIT_REQUEST)


def request_open() -> bool:
    """Ask the running Panzeron to show its window. True if one was running."""
    return _post(MSG_OPEN_REQUEST)


def focus_window() -> bool:
    """Bring an already-open Panzeron window to the front (restoring it if minimised). True if there was one."""
    if not available():
        return False
    try:
        a = _api(); ct = a.ctypes
        found: list[Any] = []

        def each(hwnd: Any, _lp: Any) -> int:
            cls, title = ct.create_unicode_buffer(64), ct.create_unicode_buffer(256)
            a.user32.GetClassNameW(hwnd, cls, 64); a.user32.GetWindowTextW(hwnd, title, 256)
            if cls.value == "Chrome_WidgetWin_1" and "Panzeron" in title.value and a.user32.IsWindowVisible(hwnd):
                found.append(hwnd)
                return 0
            return 1
        a.user32.EnumWindows(a.ENUMPROC(each), 0)
        if not found:
            return False
        if a.user32.IsIconic(found[0]):
            a.user32.ShowWindow(found[0], 9)                       # SW_RESTORE
        a.user32.SetForegroundWindow(found[0])
        return True
    except Exception:
        return False


class Tray:
    """The tray icon and its menu. `on_open` / `on_quit` are called on the tray thread; keep them quick."""

    def __init__(self, icon_path: str, on_open: Callable[[], None], on_quit: Callable[[], None], tooltip: str = TOOLTIP):
        self.icon_path, self.on_open, self.on_quit, self.tooltip = str(icon_path), on_open, on_quit, tooltip
        self._ready = threading.Event(); self._ok = False
        self._hwnd: Any = None; self._pending: tuple[str, str] | None = None; self._a: Any = None

    def start(self, timeout: float = 5.0) -> bool:
        """Create the icon. False (never an exception) if it could not be created; the caller then runs without a tray."""
        if not available():
            return False
        threading.Thread(target=self._run, daemon=True, name="panzeron-tray").start()
        return self._ready.wait(timeout) and self._ok

    def notify(self, title: str, text: str) -> None:
        if self._hwnd and self._a:
            self._pending = (title, text)
            self._a.user32.PostMessageW(self._hwnd, MSG_NOTIFY, 0, 0)

    def stop(self) -> None:
        if self._hwnd and self._a:
            self._a.user32.PostMessageW(self._hwnd, 0x0010, 0, 0)         # WM_CLOSE -> destroys the window -> removes the icon -> ends the loop

    # -- everything below runs on the tray thread --
    def _icon(self, a: Any) -> Any:
        w = a.user32
        cx, cy = a.ctypes.windll.user32.GetSystemMetrics(49), a.ctypes.windll.user32.GetSystemMetrics(50)         # SM_CXSMICON / SM_CYSMICON
        h = w.LoadImageW(None, self.icon_path, 1, cx or 16, cy or 16, 0x10)                                         # IMAGE_ICON from file
        return h or w.LoadIconW(None, a.ctypes.c_void_p(32512))                                                    # fall back to the default application icon

    def _data(self, a: Any, flags: int) -> Any:
        nid = a.NOTIFYICONDATAW(); nid.cbSize = a.ctypes.sizeof(nid); nid.hWnd = self._hwnd; nid.uID = 1; nid.uFlags = flags
        return nid

    def _add(self, a: Any) -> bool:
        nid = self._data(a, 0x1 | 0x2 | 0x4)                                  # NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage, nid.hIcon, nid.szTip = MSG_TRAY, self._hicon, self.tooltip[:127]
        return bool(a.shell32.Shell_NotifyIconW(0, a.ctypes.byref(nid)))      # NIM_ADD

    def _remove(self, a: Any) -> None:
        nid = self._data(a, 0); a.shell32.Shell_NotifyIconW(2, a.ctypes.byref(nid))                                 # NIM_DELETE

    def _balloon(self, a: Any) -> None:
        if not self._pending:
            return
        title, text = self._pending; self._pending = None
        nid = self._data(a, 0x10)                                             # NIF_INFO
        nid.szInfoTitle, nid.szInfo, nid.dwInfoFlags = title[:63], text[:255], 1                                      # NIIF_INFO
        a.shell32.Shell_NotifyIconW(1, a.ctypes.byref(nid))                   # NIM_MODIFY

    def _menu(self, a: Any) -> None:
        u = a.user32
        menu = u.CreatePopupMenu()
        u.AppendMenuW(menu, 0x0, ID_OPEN, MENU_OPEN); u.AppendMenuW(menu, 0x800, 0, None); u.AppendMenuW(menu, 0x0, ID_QUIT, MENU_QUIT)       # MF_STRING / MF_SEPARATOR
        u.SetMenuDefaultItem(menu, ID_OPEN, 0)
        pt = a.POINT(); u.GetCursorPos(a.ctypes.byref(pt))
        u.SetForegroundWindow(self._hwnd)                                     # required, or the menu will not close when you click elsewhere
        u.TrackPopupMenu(menu, 0x2 | 0x20, pt.x, pt.y, 0, self._hwnd, None)  # TPM_RIGHTBUTTON | TPM_BOTTOMALIGN
        u.PostMessageW(self._hwnd, 0, 0, 0)
        u.DestroyMenu(menu)

    def _run(self) -> None:
        try:
            a = self._a = _api(); u = a.user32
            taskbar_created = u.RegisterWindowMessageW("TaskbarCreated")      # Explorer restarted: our icon is gone, add it again

            def proc(hwnd: Any, msg: int, wp: int, lp: int) -> int:
                try:
                    if msg == MSG_TRAY:
                        if lp in (0x202, 0x203):                              # WM_LBUTTONUP / WM_LBUTTONDBLCLK
                            self.on_open()
                        elif lp in (0x205, 0x7B):                             # WM_RBUTTONUP / WM_CONTEXTMENU
                            self._menu(a)
                        return 0
                    if msg == 0x111:                                          # WM_COMMAND (menu)
                        {ID_OPEN: self.on_open, ID_QUIT: self.on_quit}.get(wp & 0xFFFF, lambda: None)()
                        return 0
                    if msg == MSG_OPEN_REQUEST:
                        self.on_open(); return 0
                    if msg == MSG_QUIT_REQUEST:
                        self.on_quit(); return 0
                    if msg == MSG_NOTIFY:
                        self._balloon(a); return 0
                    if msg == 0x16 and wp:                                    # WM_ENDSESSION: Windows is shutting down
                        self.on_quit(); return 0
                    if msg == taskbar_created:
                        self._add(a); return 0
                    if msg == 0x2:                                            # WM_DESTROY
                        self._remove(a); a.ctypes.windll.user32.PostQuitMessage(0); return 0
                except Exception as e:                                        # a bug in a callback must never kill the tray
                    log.warning("tray callback failed", extra={"ctx": {"error": str(e)[:120]}})
                return u.DefWindowProcW(hwnd, msg, wp, lp)
            self._proc = a.WNDPROC(proc)                                      # keep a reference: if it is garbage-collected Windows crashes the process
            hinst = a.kernel32.GetModuleHandleW(None)
            wc = a.WNDCLASSW(); wc.lpfnWndProc, wc.hInstance, wc.lpszClassName = self._proc, hinst, WINDOW_CLASS
            u.RegisterClassW(a.ctypes.byref(wc))
            self._hwnd = u.CreateWindowExW(0, WINDOW_CLASS, "Panzeron", 0, 0, 0, 0, 0, None, None, hinst, None)    # a normal, never-shown window (receives broadcasts)
            self._hicon = self._icon(a)
            self._ok = bool(self._hwnd) and self._add(a)
        except Exception as e:
            log.warning("tray could not start", extra={"ctx": {"error": str(e)[:160]}})
            self._ok = False
        finally:
            self._ready.set()
        if not self._ok:
            return
        msg = a.MSG()
        while a.user32.GetMessageW(a.ctypes.byref(msg), None, 0, 0) > 0:
            a.user32.TranslateMessage(a.ctypes.byref(msg)); a.user32.DispatchMessageW(a.ctypes.byref(msg))
