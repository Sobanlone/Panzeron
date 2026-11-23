"""Integrity-based self-trust.

Panzeron's own files contain the very strings a scanner looks for (test markers, detection patterns), so a naive scan of its own
folder reports "threats". Trusting a FOLDER by name would be dangerous (malware could hide there), so trust is based on CONTENT:
a manifest of SHA-256 hashes is shipped with the program. A file is trusted only if its hash matches the manifest.
  * a trusted file is skipped (no findings),
  * a file whose hash DIFFERS is reported as "modified" (that is real tamper detection),
  * an unexpected program file (exe/dll/script) in the folder is reported,
  * everything else in the folder is scanned normally.
Limitation: someone who can write to the install folder could rewrite the manifest too; signing the installer (Authenticode) is the real
fix for that and is out of scope here.
"""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Any

MANIFEST_NAME = "MANIFEST.sha256"
PRUNE_DIRS = {"__pycache__", ".git", ".pytest_cache", "node_modules", "dist", "build", "Output"}
PROGRAM_EXTS = {".exe", ".dll", ".pyd", ".scr", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".msi", ".lnk", ".com", ".cpl", ".jar"}


def install_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class TrustStore:
    def __init__(self, root: Path | None = None):
        self.root = Path(root or install_root()).resolve()
        self.manifest: dict[str, str] = {}
        self.load()

    @property
    def manifest_path(self) -> Path:
        return self.root / MANIFEST_NAME

    def load(self) -> None:
        self.manifest = {}
        try:
            for line in self.manifest_path.read_text(encoding="utf-8").splitlines():
                sha, _, rel = line.partition("  ")
                if len(sha) == 64 and rel:
                    self.manifest[rel.strip().lower()] = sha.lower()
        except OSError:
            pass

    @property
    def available(self) -> bool:
        return bool(self.manifest)

    def contains(self, p: Path) -> bool:
        try:
            p.resolve().relative_to(self.root)
            return True
        except (ValueError, OSError):
            return False

    def rel(self, p: Path) -> str:
        return p.resolve().relative_to(self.root).as_posix().lower()

    def classify(self, p: Path, sha: str) -> str:
        """'trusted' | 'modified' | 'unknown'"""
        rel = self.rel(p)
        if rel == MANIFEST_NAME.lower():
            return "trusted"
        if rel.endswith(".pyc") and "/__pycache__/" in "/" + rel:      # Python's own bytecode cache of our modules
            return "trusted"
        want = self.manifest.get(rel)
        if want is None:
            return "unknown"
        return "trusted" if want == sha.lower() else "modified"

    def _walk(self):
        """Yields (path, relative posix path in lower case). The relative path comes from the walk itself, so no per-file resolve() is needed."""
        root = str(self.root)
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in PRUNE_DIRS]
            base = os.path.relpath(dirpath, root)
            for f in files:
                if f == MANIFEST_NAME and base == ".":
                    continue
                rel = (f if base == "." else f"{base}/{f}").replace("\\", "/").lower()
                yield Path(dirpath) / f, rel

    def verify(self) -> dict[str, Any]:
        """Re-hash every shipped file and compare with the manifest."""
        modified, unexpected, seen = [], [], set()
        checked = 0
        for p, rel in self._walk():
            want = self.manifest.get(rel)
            if want is None:
                if p.suffix.lower() in PROGRAM_EXTS:
                    unexpected.append(rel)
                continue
            seen.add(rel)
            checked += 1
            try:
                if file_sha256(p) != want:
                    modified.append(rel)
            except OSError:
                modified.append(rel + " (unreadable)")
        missing = sorted(set(self.manifest) - seen)
        return {"manifest_found": self.available, "root": str(self.root), "files_in_manifest": len(self.manifest), "checked": checked,
                "modified": modified, "missing": missing[:50], "unexpected_programs": unexpected, "ok": self.available and not modified and not unexpected}

    def rebuild(self) -> int:
        lines = []
        for p, rel in sorted(self._walk(), key=lambda x: x[1]):
            try:
                lines.append(f"{file_sha256(p)}  {rel}")
            except OSError:
                continue
        self.manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.load()
        return len(lines)

    def fingerprint(self) -> str:
        try:
            return hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()[:16]
        except OSError:
            return "none"
