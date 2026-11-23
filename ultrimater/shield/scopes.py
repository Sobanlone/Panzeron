"""Scan scopes and the permission model.

Principle: Ultrimater only reads places you chose or approved. A folder or file you pick yourself is implicit consent for that
location. Anything BROADER than that (quick scan of your user folders, your whole profile, the whole computer, a drive root)
requires explicit approval, which the engine enforces itself (the UI is not the only gate) and records in the audit log.
"""
from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Skip patterns are matched against a lower-cased, forward-slashed path. "^" = starts-with; otherwise "contains".
SKIP_WINDOWS = [
    (":/windows/", "Windows system files (protected and monitored by Windows Security; scanning them here is slow and adds little)"),
    (":/$recycle.bin/", "Recycle Bin"),
    (":/system volume information/", "System restore data (protected)"),
    (":/programdata/microsoft/windows defender/", "Windows Defender's own data and quarantine"),
    ("/.git/objects/", "Git object storage (compressed, not executable)"),
]
SKIP_POSIX = [("^/proc/", "Virtual filesystem"), ("^/sys/", "Virtual filesystem"), ("^/dev/", "Device files"), ("^/run/", "Runtime data"),
              ("^/snap/", "Packaged apps"), ("^/var/lib/docker/", "Container storage"), ("^/mnt/wsl/", "WSL mounts"), ("/.git/objects/", "Git object storage")]


def _win() -> bool:
    return sys.platform == "win32"


def _existing(paths: list[Path | None]) -> list[Path]:
    seen, out = set(), []
    for p in paths:
        if p is None:
            continue
        try:
            if p.is_dir():
                key = str(p.resolve()).lower()
                if key not in seen:
                    seen.add(key)
                    out.append(p)
        except OSError:
            continue
    return out


def quick_roots(home: Path | None = None) -> list[Path]:
    """Folders where downloaded or dropped malware typically lands, plus startup locations."""
    home = home or Path.home()
    env = os.environ.get
    cands: list[Path | None] = [home / "Downloads", home / "Desktop", home / "Documents", Path(tempfile.gettempdir())]
    if _win():
        appdata, local, public = env("APPDATA"), env("LOCALAPPDATA"), env("PUBLIC")
        if appdata:
            cands.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        if local:
            cands.append(Path(local) / "Temp")
        if public:
            cands.append(Path(public) / "Downloads")
        if env("PROGRAMDATA"):
            cands.append(Path(env("PROGRAMDATA")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    return _existing(cands)


def fixed_drives() -> list[Path]:
    if not _win():
        return [Path("/")]
    import ctypes
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    drives = []
    for i in range(26):
        if mask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:      # DRIVE_FIXED (not USB, network, optical)
                drives.append(Path(root))
    return drives


@dataclass
class ScopePlan:
    id: str
    label: str
    roots: list[Path]
    skip: list[tuple[str, str]]
    broad: bool
    summary: str
    estimate: str

    def describe(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "roots": [str(r) for r in self.roots], "broad": self.broad, "summary": self.summary,
                "estimate": self.estimate, "skipped": [{"pattern": s, "reason": w} for s, w in self.skip]}


def build_plan(scope: str, home: Path | None = None) -> ScopePlan:
    home = home or Path.home()
    skips = SKIP_WINDOWS if _win() else SKIP_POSIX
    if scope == "quick":
        return ScopePlan("quick", "Quick scan", quick_roots(home), [], True,
                         "Your Downloads, Desktop, Documents, temporary-files and startup folders: the places malware most often lands.", "usually under a few minutes")
    if scope == "user":
        return ScopePlan("user", "My user folders", [home], skips, True,
                         f"Everything in your user profile ({home}).", "minutes to an hour, depending on how much you store")
    if scope == "computer":
        return ScopePlan("computer", "Entire computer", fixed_drives(), skips, True,
                         "Every file on every internal drive, except the Windows system folder and other protected locations listed below.", "can take one hour or more")
    raise ValueError(f"unknown scan scope: {scope}")


def classify_target(path: str | Path, home: Path | None = None) -> str:
    """'broad' if the target is a drive root, the user's profile, or a parent of it; otherwise 'targeted'."""
    home = home or Path.home()
    try:
        p = Path(path).resolve()
    except OSError:
        return "targeted"
    h = home.resolve()
    if p == Path(p.anchor) or p == h or p in h.parents:
        return "broad"
    return "targeted"


def consent_details(plan: ScopePlan | None, roots: list[Path] | None = None, label: str | None = None) -> dict[str, Any]:
    r = plan.roots if plan else (roots or [])
    return {
        "scope": plan.id if plan else "custom", "label": label or (plan.label if plan else "Scan"),
        "summary": plan.summary if plan else "A location broader than a single folder.",
        "roots": [str(x) for x in r], "estimate": plan.estimate if plan else "",
        "skipped": [{"pattern": s, "reason": w} for s, w in (plan.skip if plan else [])],
        "promises": [
            "Files are only READ. Nothing is executed, changed, moved or deleted.",
            "Nothing leaves this computer. No file contents are uploaded anywhere.",
            "Some protected folders may be unreadable without administrator rights; they are listed in the report, not hidden.",
            "You can cancel at any time.",
        ],
    }
