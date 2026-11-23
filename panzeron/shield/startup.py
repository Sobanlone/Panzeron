"""Startup / persistence review and hosts-file check (Windows). Read-only.

Malware must survive a reboot, so it registers itself to start automatically. This lists those entries, resolves the program
each one launches, and flags the ones that start from temporary or download folders, use script engines with risky arguments, or
point at files that no longer exist. A flag is a reason to look, not a verdict.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any, Callable

from ..core.models import Confidence, Evidence, EvidenceTier as T, Finding, Module, Severity, make_entity

RISKY_LOCATIONS = ["/appdata/local/temp/", "/temp/", "/downloads/", "/users/public/", "/appdata/roaming/microsoft/windows/start menu/programs/startup/"]
LOLBINS = ("powershell", "pwsh", "mshta", "wscript", "cscript", "regsvr32", "rundll32", "cmd.exe", "bitsadmin", "certutil")
RISKY_ARGS = re.compile(r"(?i)(https?://|-enc(odedcommand)?\b|-w(indowstyle)?\s+hidden|javascript:|\.sct\b|frombase64|downloadstring|-nop\b|-ep\s+bypass|-executionpolicy\s+bypass)")
TARGET_RX = re.compile(r'(?i)^\s*"([^"]+)"|^\s*([a-z]:\\[^"\n]*?\.(?:exe|bat|cmd|ps1|vbs|js|com|scr|lnk|msi|cpl|hta))')
SECURITY_DOMAINS = ("windowsupdate", "update.microsoft", "defender", "smartscreen", "virustotal", "malwarebytes", "kaspersky", "avast", "avg.com",
                    "bitdefender", "norton", "mcafee", "eset.com", "sophos", "trendmicro", "symantec")
BRAND_DOMAINS = ("paypal", "microsoft", "google", "apple", "amazon", "facebook", "instagram", "netflix", "linkedin", "bankofamerica", "chase", "wellsfargo")


def collect() -> dict[str, Any]:
    if sys.platform != "win32":
        return {"available": False, "reason": "Startup review needs Windows.", "entries": []}
    import winreg
    entries: list[dict[str, str]] = []
    keys = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Registry: current user, Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "Registry: current user, RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "Registry: all users, Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "Registry: all users, RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Registry: all users, Run (32-bit)")]
    for hive, path, label in keys:
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    entries.append({"source": label, "name": str(name), "command": str(value)})
                    i += 1
        except OSError:
            continue
    for base in (os.environ.get("APPDATA"), os.environ.get("PROGRAMDATA")):
        if base:
            d = Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if d.is_dir():
                for f in d.iterdir():
                    if f.is_file() and f.name.lower() != "desktop.ini":
                        entries.append({"source": "Startup folder", "name": f.name, "command": str(f)})
    return {"available": True, "reason": None, "entries": entries}


def parse_target(command: str) -> str | None:
    cmd = os.path.expandvars(command or "")
    m = TARGET_RX.match(cmd)
    if m:
        return (m.group(1) or m.group(2)).strip()
    tok = cmd.strip().split(" ")[0]
    return tok or None


def assess(entries: list[dict[str, str]], salt: bytes, exists: Callable[[str], bool] = os.path.exists) -> list[Finding]:
    out: list[Finding] = []
    for e in entries:
        cmd, name = e["command"], e["name"]
        target = parse_target(cmd)
        norm = (target or "").replace("\\", "/").lower()
        inds: list[tuple[str, int]] = []
        if any(loc in norm + "/" for loc in RISKY_LOCATIONS) and not norm.endswith(".lnk") or "/temp/" in norm:
            inds.append((f"launches a program from a temporary, download or public folder: {target}", 2))
        base = os.path.basename(norm)
        if any(base.startswith(b) for b in LOLBINS) and RISKY_ARGS.search(cmd):
            inds.append((f"starts the script engine '{base}' with risky arguments (download, encoded command or hidden window)", 3))
        if re.search(r"(?i)\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|bat|cmd|com)\b", cmd):
            inds.append(("the program name has a document-style double extension", 2))
        if target and not exists(target) and not any(base.startswith(b) for b in LOLBINS):
            inds.append(("the program it points to no longer exists (a leftover entry)", 1))
        score = sum(w for _, w in inds)
        if score < 2:
            continue
        sev = Severity.HIGH if score >= 4 else Severity.MEDIUM
        out.append(Finding(
            Module.SHIELD, f"Startup item needs review: {name}", sev, Confidence.MEDIUM if score >= 4 else Confidence.LOW,
            "This program starts automatically with Windows. Malware uses startup entries to survive a reboot, but many legitimate programs use the same mechanism. "
            "Check that you recognise it.",
            [Evidence(f"{e['source']}: '{name}' runs: {cmd[:200]}", f"{e['source']} @ {name}", "startup:entry", T.VERIFIED)]
            + [Evidence(d, f"{e['source']} @ {name}", "startup:indicator", T.VERIFIED) for d, _ in inds]
            + [Evidence(f"Indicator score {score} (reporting threshold 2)", name, "rule:SH-STARTUP-1", T.DERIVED)],
            f"Startup: {name}", [make_entity("file", name, salt)],
            ["Check that you installed this program", "Scan it with Windows Defender", "Disable it in Task Manager > Startup if unrecognised"],
            target if target and exists(target) and os.path.isfile(target) else None, category="shield.startup"))
    return out


def read_hosts() -> str | None:
    if sys.platform != "win32":
        return None
    p = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def check_hosts(text: str, salt: bytes) -> list[Finding]:
    """Flags hosts-file entries that block security/update sites or redirect well-known brands to other addresses."""
    out: list[Finding] = []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.split("#", 1)[0].strip()
        parts = s.split()
        if len(parts) < 2:
            continue
        ip, hosts = parts[0], parts[1:]
        for h in hosts:
            hl = h.lower()
            loop = ip in ("127.0.0.1", "0.0.0.0", "::1")
            if any(d in hl for d in SECURITY_DOMAINS):
                out.append(Finding(
                    Module.SHIELD, f"Hosts file blocks a security or update site: {h}", Severity.HIGH, Confidence.MEDIUM,
                    "The Windows hosts file overrides DNS. Malware edits it to stop antivirus and Windows updates from working. Some people edit it on purpose, so check that you did.",
                    [Evidence(f"hosts line {n}: {ip} {h}", f"hosts @ line {n}", "hosts:security-block", T.VERIFIED)],
                    "hosts file", [make_entity("url", h, salt)], ["Open the hosts file in Notepad (as administrator) and remove entries you did not add"], None, category="shield.hosts"))
            elif not loop and any(b in hl for b in BRAND_DOMAINS):
                out.append(Finding(
                    Module.SHIELD, f"Hosts file redirects a well-known site: {h}", Severity.HIGH, Confidence.MEDIUM,
                    "The hosts file sends this well-known website to a different address, which can silently take you to a fake copy of the site to steal your login.",
                    [Evidence(f"hosts line {n}: {ip} {h}", f"hosts @ line {n}", "hosts:brand-redirect", T.VERIFIED)],
                    "hosts file", [make_entity("url", h, salt)], ["Remove the entry unless you added it deliberately"], None, category="shield.hosts"))
    return out
