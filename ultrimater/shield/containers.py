"""Archive (ZIP) and Office-document inspection. Read-only; members are never extracted to disk or executed.

Safety caps protect Ultrimater itself: entry count, per-member and total bytes read, nesting depth, and zip-bomb ratio.
"""
from __future__ import annotations

import io
import re
import zipfile
import zlib
from pathlib import Path
from typing import Any, BinaryIO, Callable

from ..core.models import Confidence, Evidence, EvidenceTier as T, Finding, Module, Severity, make_entity

MAX_ENTRIES = 3000
MAX_MEMBER_READ = 8 * 1024 * 1024
MAX_TOTAL_READ = 64 * 1024 * 1024
MAX_DEPTH = 2
BOMB_RATIO, BOMB_BYTES = 100, 500 * 1024 * 1024
DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".rtf", ".csv"}
EXEC_EXTS = {".exe", ".scr", ".com", ".dll", ".cpl", ".msi"}
SCRIPT_EXTS = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".lnk"}
MACRO_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xlsb"}
AUTOEXEC = re.compile(rb"(AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec|Auto_Close)", re.I)
RISKY_MACRO = re.compile(rb"(WScript\.Shell|CreateObject|powershell|cmd\.exe|URLDownloadToFile|XMLHTTP|ADODB\.Stream|MSXML2)", re.I)
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_VBA_NAMES = [n.encode("utf-16le") for n in ("_VBA_PROJECT", "VBA", "Macros", "_VBA_PROJECT_CUR")]

InspectFn = Callable[..., list[Finding]]
# Hostile archives can corrupt any layer (zip structure, zlib stream, encryption, truncation). None of these may ever escape a scan.
READ_ERRORS = (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError, zlib.error, EOFError, ValueError, KeyError, OverflowError)


def _f(title: str, sev: Severity, conf: Confidence, why: str, evidence: list[Evidence], name: str, path: str | None, salt: bytes, category: str, actions: list[str]) -> Finding:
    return Finding(Module.SHIELD, title, sev, conf, why, evidence, name, [make_entity("file", name, salt)], actions, path, category=category)


def inspect_ole(data: bytes, name: str, path: str | None, salt: bytes) -> list[Finding]:
    """Legacy Office (.doc/.xls/.ppt) macro presence: VBA storages appear as UTF-16 names in the compound-file directory."""
    if not data.startswith(OLE_MAGIC):
        return []
    found = [n.decode("utf-16le") for n in _VBA_NAMES if n in data[:4 * 1024 * 1024]]
    if not found:
        return []
    ext = Path(name).suffix.lower()
    risky = bool(RISKY_MACRO.search(data[:4 * 1024 * 1024]))
    return [_f("Office document contains macros", Severity.MEDIUM if risky else Severity.LOW, Confidence.MEDIUM if risky else Confidence.LOW,
               "This document contains VBA macro code. Macros are a very common way to deliver malware, but also widely used in legitimate spreadsheets and templates. "
               "Only enable macros if you know and trust who sent the file." + (" Strings associated with running programs or downloading files were also present." if risky else ""),
               [Evidence(f"VBA storage present in compound file ({', '.join(found)})", f"{name} @ OLE directory", "ole:vba-storage", T.VERIFIED)]
               + ([Evidence("Macro-related strings that run programs or fetch files are present", name, "rule:OL-MACRO-RISKY", T.DERIVED)] if risky else []),
               name, path, salt, "shield.macro", ["Do not enable macros", "Confirm who sent the file", "Scan with Windows Defender"])]


def _is_ooxml(z: zipfile.ZipFile) -> bool:
    return "[Content_Types].xml" in z.namelist()


def inspect_ooxml(z: zipfile.ZipFile, name: str, path: str | None, salt: bytes) -> list[Finding]:
    out: list[Finding] = []
    names = z.namelist()
    ext = Path(name).suffix.lower()
    vba = [n for n in names if n.lower().endswith("vbaproject.bin")]
    if vba or ext in MACRO_EXTS:
        raw = b""
        for n in vba[:2]:
            try:
                raw += z.read(n)[:5 * 1024 * 1024]
            except READ_ERRORS:
                pass
        auto, risky = bool(AUTOEXEC.search(raw)), bool(RISKY_MACRO.search(raw))
        sev = Severity.MEDIUM if (auto and risky) else Severity.LOW
        out.append(_f("Office document contains macros", sev, Confidence.MEDIUM if (auto and risky) else Confidence.LOW,
                      "This document contains VBA macro code. Macros are a very common malware delivery method but also used legitimately. "
                      "Macro source is stored compressed, so Ultrimater can confirm macros exist but cannot read all of what they do. Only enable them if you trust the sender.",
                      [Evidence(f"vbaProject.bin present ({len(vba)} part(s)); extension '{ext}'", f"{name} @ {vba[0] if vba else 'package'}", "ooxml:vba-project", T.VERIFIED)]
                      + ([Evidence("Auto-run entry names and program/download-related strings both visible", name, "rule:OX-MACRO-AUTOEXEC", T.DERIVED)] if (auto and risky) else []),
                      name, path, salt, "shield.macro", ["Do not enable macros", "Confirm who sent the file"]))
    for n in names:
        if n.lower().endswith(".rels") and "settings" in n.lower():
            try:
                txt = z.read(n)[:200_000]
            except READ_ERRORS:
                continue
            if re.search(rb'attachedTemplate[^>]*Target="https?://', txt, re.I) or re.search(rb'Target="https?://[^"]*"[^>]*TargetMode="External"[^>]*attachedTemplate', txt, re.I):
                out.append(_f("Document loads a template from the internet", Severity.MEDIUM, Confidence.MEDIUM,
                              "The document is set to fetch a template from a remote address when opened (remote template injection), a technique used to pull in malicious macros after the fact.",
                              [Evidence("attachedTemplate relationship points at an http(s) address", f"{name} @ {n}", "ooxml:remote-template", T.VERIFIED)],
                              name, path, salt, "shield.remote_template", ["Do not open the document", "Confirm who sent it"]))
    if "word/document.xml" in names:
        try:
            doc = z.read("word/document.xml")[:5 * 1024 * 1024]
            if re.search(rb"DDE(AUTO)?\b", doc) and re.search(rb"<w:(instrText|fldSimple)", doc):
                out.append(_f("Document contains a DDE field", Severity.MEDIUM, Confidence.MEDIUM,
                              "A Dynamic Data Exchange field can launch programs when the document is opened. It is rarely used legitimately today.",
                              [Evidence("DDE/DDEAUTO field instruction found in word/document.xml", f"{name} @ word/document.xml", "ooxml:dde", T.VERIFIED)],
                              name, path, salt, "shield.dde", ["Do not open the document"]))
        except READ_ERRORS:
            pass
    return out


def inspect_zip(src: str | Path | BinaryIO, name: str, path: str | None, salt: bytes, inspect_content: InspectFn, depth: int = 0, budget: list[int] | None = None) -> list[Finding]:
    """Inspect a ZIP (or OOXML) file. `inspect_content` is the scanner's per-file inspector, applied to members."""
    out: list[Finding] = []
    budget = budget if budget is not None else [MAX_TOTAL_READ]
    try:
        z = zipfile.ZipFile(src)
    except READ_ERRORS:
        return out
    with z:
        infos = z.infolist()
        if _is_ooxml(z):
            return inspect_ooxml(z, name, path, salt)
        total_u = sum(i.file_size for i in infos)
        total_c = sum(i.compress_size for i in infos) or 1
        if len(infos) > MAX_ENTRIES or (total_u > BOMB_BYTES and total_u / total_c > BOMB_RATIO):
            out.append(_f("Archive looks like a decompression bomb", Severity.MEDIUM, Confidence.MEDIUM,
                          "The archive expands to a huge size or has an extreme number of entries, a trick used to exhaust a computer's memory or disk. Ultrimater did not unpack it.",
                          [Evidence(f"{len(infos)} entries, {total_u // (1024 * 1024)} MB uncompressed, ratio {total_u // total_c}:1", name, "zip:bomb-heuristic", T.DERIVED)],
                          name, path, salt, "shield.archive_bomb", ["Do not extract the archive"]))
            return out
        encrypted = 0
        for info in infos:
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                encrypted += 1
                continue
            member = info.filename
            mext = Path(member).suffix.lower()
            if budget[0] <= 0 or info.file_size == 0:
                continue
            want = min(info.file_size, MAX_MEMBER_READ)
            try:
                with z.open(info) as fh:
                    data = fh.read(want)
            except READ_ERRORS:
                continue
            budget[0] -= len(data)
            label = f"{name}!{member}"
            if data[:2] == b"MZ" and mext in DOC_EXTS:
                out.append(_f("Program hidden inside archive as a document", Severity.HIGH, Confidence.MEDIUM,
                              f"The archive contains '{member}', which looks like a document or image but is actually a Windows program (it starts with the 'MZ' program header). "
                              "This is a well-known way to trick people into running malware. It is an observed fact, not proof of malicious behaviour.",
                              [Evidence(f"Member '{member}' has program header 'MZ' but extension '{mext}'", label, "zip:disguised-member", T.VERIFIED)],
                              name, path, salt, "shield.archive_disguised", ["Do not extract or open the archive", "Quarantine it if unexpected"]))
            if depth < MAX_DEPTH and data[:4] == b"PK\x03\x04":
                out += inspect_zip(io.BytesIO(data), label, path, salt, inspect_content, depth + 1, budget)
            for f in inspect_content(label, data, path, salt, "0" * 64, depth=depth + 1):
                if f.category == "shield.disguised":      # already reported once, with archive context, above
                    continue
                f.source = name
                f.title = f"{f.title} (inside archive: {member})"
                out.append(f)
        if encrypted:
            execs = [i.filename for i in infos if Path(i.filename).suffix.lower() in EXEC_EXTS | SCRIPT_EXTS]
            out.append(_f("Archive has password-protected contents", Severity.LOW if not execs else Severity.MEDIUM, Confidence.LOW,
                          f"{encrypted} item(s) are encrypted, so Ultrimater and most antivirus engines cannot inspect them. Attackers use password-protected archives to bypass scanning, "
                          "but many people also protect archives for privacy.",
                          [Evidence(f"{encrypted} encrypted entr{'y' if encrypted == 1 else 'ies'}", name, "zip:encrypted", T.VERIFIED)],
                          name, path, salt, "shield.archive_encrypted", ["Only open it if you know who sent it and expect the password"]))
    return out
