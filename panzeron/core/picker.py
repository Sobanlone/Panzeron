"""Native Windows file and folder dialogs.

A web page cannot see real file paths, so the engine opens the genuine operating-system dialogs. Primary backend: tkinter
(ships with Python; uses the native Windows dialogs). Fallback: PowerShell + System.Windows.Forms. If neither works the UI
falls back to manual path entry and says so.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from typing import Callable

_lock = threading.Lock()          # one dialog at a time
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

FILTERS = {
    "all": [("All files", "*.*")],
    "executables": [("Programs and scripts", "*.exe *.dll *.msi *.ps1 *.bat *.cmd *.vbs *.js"), ("All files", "*.*")],
    "hashlist": [("Hash lists", "*.txt *.csv *.tsv *.lst"), ("All files", "*.*")],
    "images": [("Images, PDFs and documents", "*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tif *.pdf *.docx *.txt"), ("All files", "*.*")],
}


class PickerUnavailable(Exception):
    pass


def _tk(kind: str, title: str, filetypes: list[tuple[str, str]]) -> list[str]:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as e:  # tkinter missing or no display
        raise PickerUnavailable(f"tkinter is not available: {e}") from e
    try:
        root = tk.Tk()
    except Exception as e:
        raise PickerUnavailable(f"no display for dialogs: {e}") from e
    try:
        root.withdraw()
        root.attributes("-topmost", True)
        root.update()
        if kind == "folder":
            r = filedialog.askdirectory(parent=root, title=title, mustexist=True)
            return [r] if r else []
        if kind == "file":
            r = filedialog.askopenfilename(parent=root, title=title, filetypes=filetypes)
            return [r] if r else []
        return list(filedialog.askopenfilenames(parent=root, title=title, filetypes=filetypes))
    finally:
        root.destroy()


def _powershell(kind: str, title: str, filetypes: list[tuple[str, str]]) -> list[str]:
    if sys.platform != "win32":
        raise PickerUnavailable("PowerShell dialogs need Windows")
    flt = "|".join(f"{lbl}|{pat.replace(' ', ';')}" for lbl, pat in filetypes)
    script = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        "$f = New-Object System.Windows.Forms.Form -Property @{TopMost=$true; ShowInTaskbar=$false; Opacity=0}; $f.Show(); "
        "if ($env:UM_KIND -eq 'folder') { $d = New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description = $env:UM_TITLE; "
        "  if ($d.ShowDialog($f) -eq 'OK') { $d.SelectedPath } } "
        "else { $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Title = $env:UM_TITLE; $d.Filter = $env:UM_FILTER; $d.Multiselect = ($env:UM_KIND -eq 'files'); "
        "  if ($d.ShowDialog($f) -eq 'OK') { $d.FileNames } }; $f.Close()")
    env = dict(os.environ, UM_KIND=kind, UM_TITLE=title, UM_FILTER=flt)
    try:
        cp = subprocess.run(["powershell", "-STA", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True,
                            timeout=600, env=env, creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PickerUnavailable(str(e)) from e
    if cp.returncode != 0:
        raise PickerUnavailable((cp.stderr or "dialog failed").strip()[:200])
    return [ln.strip() for ln in cp.stdout.splitlines() if ln.strip()]


def pick(kind: str, title: str = "Choose", filter_name: str = "all") -> list[str]:
    """kind: 'file' | 'files' | 'folder'. Returns normalised absolute paths ([] if the user cancelled). Raises PickerUnavailable."""
    if kind not in ("file", "files", "folder"):
        raise ValueError("kind must be 'file', 'files' or 'folder'")
    types = FILTERS.get(filter_name, FILTERS["all"])
    with _lock:
        errors = []
        for backend in (_tk, _powershell):
            try:
                return [os.path.normpath(p) for p in backend(kind, title, types)]
            except PickerUnavailable as e:
                errors.append(str(e))
        raise PickerUnavailable("; ".join(errors))
