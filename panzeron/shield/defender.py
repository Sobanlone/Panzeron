"""Windows Security integration through documented interfaces (Defender PowerShell module, SecurityCenter2 WMI).

Read-only except for an explicit, user-triggered Start-MpScan. Panzeron never changes Defender settings,
never adds exclusions to Defender, and never disables anything.

On non-Windows systems every call returns {"available": False, "reason": ...}. "Unavailable" is not zero.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..core.log import get_logger

log = get_logger("defender")
# Hide the console window PowerShell would otherwise flash on every call (matters in a windowed desktop app).
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _is_windows() -> bool:
    return sys.platform == "win32"


def _ps(script: str, env_extra: dict[str, str] | None = None, timeout: int = 20) -> subprocess.CompletedProcess:
    """Run a fixed PowerShell script. User data is passed ONLY via environment variables, never interpolated."""
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=timeout, env=env, shell=False, creationflags=NO_WINDOW)


def _json_list(text: str) -> list[dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    obj = json.loads(text)
    return obj if isinstance(obj, list) else [obj]


def _unavailable(reason: str) -> dict[str, Any]:
    return {"available": False, "reason": reason}


def status() -> dict[str, Any]:
    if not _is_windows():
        return _unavailable("Not running on Windows; Windows Security is not present on this system.")
    script = ("Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
              "AntivirusSignatureVersion,AntivirusSignatureLastUpdated,AMEngineVersion,QuickScanEndTime,"
              "FullScanEndTime,IsTamperProtected | ConvertTo-Json -Compress")
    try:
        cp = _ps(script)
    except (OSError, subprocess.TimeoutExpired) as e:
        return _unavailable(f"Could not run PowerShell: {e}")
    if cp.returncode != 0:
        return _unavailable((cp.stderr or "Get-MpComputerStatus failed").strip()[:300])
    try:
        rows = _json_list(cp.stdout)
    except json.JSONDecodeError as e:
        return _unavailable(f"Unexpected Defender output: {e}")
    if not rows:
        return _unavailable("Defender returned no status (a third-party antivirus may be active).")
    r = rows[0]
    return {"available": True, "antivirus_enabled": r.get("AntivirusEnabled"),
            "service_enabled": r.get("AMServiceEnabled"),
            "realtime_protection": r.get("RealTimeProtectionEnabled"),
            "signature_version": r.get("AntivirusSignatureVersion"),
            "signature_updated": str(r.get("AntivirusSignatureLastUpdated")),
            "engine_version": r.get("AMEngineVersion"),
            "tamper_protected": r.get("IsTamperProtected"),
            "last_quick_scan": str(r.get("QuickScanEndTime")), "last_full_scan": str(r.get("FullScanEndTime"))}


def security_products() -> dict[str, Any]:
    if not _is_windows():
        return _unavailable("Not running on Windows.")
    script = ("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
              "Select-Object displayName,productState | ConvertTo-Json -Compress")
    try:
        cp = _ps(script)
        if cp.returncode != 0:
            return _unavailable(cp.stderr.strip()[:300] or "SecurityCenter2 query failed")
        return {"available": True, "products": _json_list(cp.stdout)}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return _unavailable(str(e))


def detections(limit: int = 20) -> dict[str, Any]:
    """Defender's own detection history (read-only)."""
    if not _is_windows():
        return _unavailable("Not running on Windows.")
    script = (f"Get-MpThreatDetection | Select-Object -First {int(limit)} ThreatID,InitialDetectionTime,"
              "ProcessName,Resources,ActionSuccess | ConvertTo-Json -Compress")
    try:
        cp = _ps(script)
        if cp.returncode != 0:
            return _unavailable(cp.stderr.strip()[:300] or "Get-MpThreatDetection failed")
        return {"available": True, "detections": _json_list(cp.stdout)}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return _unavailable(str(e))


def start_scan(path: str) -> dict[str, Any]:
    """Ask Defender to scan a path. Requires an explicit user click; may need elevation."""
    if not _is_windows():
        return _unavailable("Not running on Windows.")
    p = Path(path)
    if not p.exists():
        return {"started": False, "reason": "path does not exist"}
    script = "Start-MpScan -ScanType CustomScan -ScanPath $env:PANZERON_SCAN_PATH"
    try:
        cp = _ps(script, {"PANZERON_SCAN_PATH": str(p)}, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"started": False, "reason": str(e)}
    if cp.returncode != 0:
        return {"started": False, "reason": (cp.stderr or "Start-MpScan failed (administrator rights may be required)").strip()[:300]}
    return {"started": True, "reason": "Defender scan completed"}


def authenticode_status(path: str) -> str | None:
    """'Valid' | 'NotSigned' | 'HashMismatch' | ... or None when unavailable."""
    if not _is_windows():
        return None
    try:
        cp = _ps("(Get-AuthenticodeSignature -LiteralPath $env:PANZERON_SCAN_PATH).Status.ToString()",
                 {"PANZERON_SCAN_PATH": path}, timeout=20)
        return cp.stdout.strip() or None if cp.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def snapshot() -> dict[str, Any]:
    """Everything the UI shows about Windows Security, gathered in parallel (3 PowerShell calls overlap instead of queueing)."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as ex:
        fs, fp, fd = ex.submit(status), ex.submit(security_products), ex.submit(detections)
        return {"status": fs.result(), "products": fp.result(), "detections": fd.result()}
