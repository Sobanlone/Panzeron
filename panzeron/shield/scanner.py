"""Panzeron SHIELD scanner: static, read-only file inspection. Nothing is ever executed.

Design rules:
  * A file is never called malicious because of its NAME, extension or location alone.
  * Every finding carries evidence, a confidence level, and says what it does NOT prove.
  * This is an on-demand scanner (plus an optional folder watcher). It is not kernel-level real-time protection.
  * Coverage is reported honestly: what was fully read, quick-inspected, skipped, excluded or unreadable.

Modes: "smart" reads executables, scripts, documents, archives and small files in full, and quick-inspects the first 64 KB of
large media-like files; "deep" reads every byte of every file.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import os
import re
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..core.log import get_logger
from ..core.models import (SEVERITY_RANK, Confidence, Evidence, EvidenceTier as T, Finding, Module, Severity, make_entity, new_id, now_iso, weakest_tier)
from . import containers, pe as pelib
from .rules import BUILTIN_RULES, Rule, evaluate
from .trust import PROGRAM_EXTS as OWN_PROGRAM_EXTS

log = get_logger("shield")

# The EICAR string is assembled at runtime so this source file is not itself flagged by antivirus.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + "!$H+H*").encode()
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
PANZERON_MARKER = b"PANZERON-TEST-MARKER-HARMLESS-V1"

PANZERON_SIM = b"PANZERON-SIMULATED-THREAT-V1"
SIGNATURES = [
    ("SIG-EICAR", "EICAR standard antivirus test file", EICAR,
     "The industry-standard harmless string used to test antivirus products. It is not real malware.", "test"),
    ("SIG-PANZERON-TEST", "Panzeron harmless test marker", PANZERON_MARKER,
     "A harmless marker string used by Panzeron's own test fixtures. Not real malware.", "test"),
    ("SIG-PANZERON-SIM", "Panzeron simulated threat (demo marker)", PANZERON_SIM,
     "A harmless marker that Panzeron's demo data uses to SIMULATE a serious detection.", "sim"),
]
EXACT_TEST_FILE_MAX = 256          # a real antivirus test file is just the test string (the EICAR specification allows at most 128 bytes)
RULESET_FAMILIES = 3               # a file matching this many unrelated rule families is a ruleset / test / notes, not an attack
SOURCE_EXTS = {".py", ".pyi", ".rs", ".go", ".java", ".cs", ".c", ".cpp", ".h", ".hpp", ".ts", ".kt", ".swift", ".rb"}
HEURISTIC_FAMILIES = {"rule", "pe", "script", "disguised", "macro", "remote_template", "dde", "archive_disguised", "startup"}
_MAX_SIG_LEN = max(len(s[2]) for s in SIGNATURES)
KNOWN_HASHES = {EICAR_SHA256: "EICAR standard antivirus test file"}

MAX_SIG_SCAN_BYTES = 64 * 1024 * 1024
CHUNK = 1024 * 1024
KEEP_BYTES = 8 * 1024 * 1024
QUICK_BYTES = 64 * 1024
SMALL_FULL = 256 * 1024

MAGIC = [(b"MZ", "pe"), (b"%PDF", "pdf"), (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"),
         (b"PK\x03\x04", "zip"), (b"\x7fELF", "elf"), (b"{\\rtf", "rtf"), (b"\xd0\xcf\x11\xe0", "ole")]
NON_EXEC_EXTS = {".txt", ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".docx", ".xlsx", ".pptx", ".csv", ".md", ".mp3", ".mp4", ".zip", ".rtf"}
SCRIPT_EXTS = {".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta", ".wsf", ".vbe", ".jse", ".psm1"}
# Files read in full even in smart mode: the types attackers actually use.
RISKY_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".msi", ".ocx", ".drv", ".efi", ".lnk", ".jar", ".inf",
              ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".sh", ".py",
              ".doc", ".docx", ".docm", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".xlam", ".ppt", ".pptx", ".pptm", ".rtf", ".pdf",
              ".zip", ".php", ".phtml", ".asp", ".aspx", ".jsp", ".jspx", ".cfm", ".txt", ".html", ".htm", ".iso", ".img"}

SCRIPT_INDICATORS = [
    ("encoded_command", re.compile(rb"(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}"), "PowerShell encoded command"),
    ("base64_decode", re.compile(rb"(?i)FromBase64String"), "Base64 decoding at runtime"),
    ("invoke_expression", re.compile(rb"(?i)\b(Invoke-Expression|iex)\b\s*[\(\$]"), "Dynamic code evaluation"),
    ("download_exec", re.compile(rb"(?i)(DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient)"), "Downloads content from the network"),
    ("hidden_window", re.compile(rb"(?i)-w(indowstyle)?\s+hidden"), "Runs with a hidden window"),
    ("exec_policy_bypass", re.compile(rb"(?i)-exec(utionpolicy)?\s+bypass"), "Bypasses execution policy"),
]
ENC_PAYLOAD = re.compile(rb"(?i)-e(?:nc(?:odedcommand)?|c)\s+([A-Za-z0-9+/=]{40,})")


@dataclass
class ScanResult:
    id: str
    target: str
    started_at: str
    finished_at: str | None = None
    status: str = "running"            # running | completed | cancelled | failed
    scope: str = "custom"
    mode: str = "smart"
    enumerating: bool = True
    files_total: int = 0               # discovered so far
    files_scanned: int = 0
    files_full: int = 0
    files_quick: int = 0
    files_trusted: int = 0             # Panzeron's own files, verified by hash against the shipped manifest
    files_cached: int = 0              # unchanged since a previous clean scan
    files_excluded: int = 0
    bytes_scanned: int = 0
    current: str = ""
    duration_s: float = 0.0
    errors: list[dict[str, str]] = field(default_factory=list)          # unreadable files are REPORTED, not hidden
    access_denied: int = 0
    skipped_dirs: list[dict[str, str]] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    verdict: str = "running"           # threats | review | test | clean | incomplete

    def to_dict(self) -> dict[str, Any]:
        d = {k: getattr(self, k) for k in (
            "id", "target", "started_at", "finished_at", "status", "scope", "mode", "enumerating", "files_total", "files_scanned", "files_full",
            "files_quick", "files_trusted", "files_cached", "files_excluded", "bytes_scanned", "current", "duration_s", "errors", "access_denied", "skipped_dirs", "finding_ids",
            "severity_counts", "verdict")}
        d["errors"] = d["errors"][:200]
        d["throughput_mb_s"] = round(self.bytes_scanned / 1048576 / self.duration_s, 1) if self.duration_s else 0.0
        return d


def shannon_entropy(data: bytes) -> float:
    return pelib.shannon_entropy(data)


def parse_pe(data: bytes) -> dict[str, Any] | None:
    """Compatibility wrapper around the full PE parser."""
    info = pelib.parse(data)
    if not info:
        return None
    return {"machine": info.machine, "timestamp": info.timestamp, "is_dll": info.is_dll,
            "sections": [{"name": s.name, "raw_size": s.raw_size, "entropy": s.entropy} for s in info.sections]}


def sniff_family(head: bytes) -> str | None:
    for magic, fam in MAGIC:
        if head.startswith(magic):
            return fam
    return None


def decode_encoded_commands(data: bytes) -> list[bytes]:
    """Decode PowerShell -EncodedCommand payloads (base64 of UTF-16LE) so what they REALLY do can be inspected."""
    out: list[bytes] = []
    for m in ENC_PAYLOAD.finditer(data[:2 * 1024 * 1024]):
        if len(out) >= 5:
            break
        b64 = m.group(1)
        try:
            raw = base64.b64decode(b64 + b"=" * (-len(b64) % 4), validate=False)
            out.append(raw.decode("utf-16le", "ignore").encode("utf-8", "ignore")[:200_000] if b"\x00" in raw[:8] else raw[:200_000])
        except (ValueError, TypeError):
            continue
    return out


_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _lower(sev: Severity) -> Severity:
    return _ORDER[max(0, _ORDER.index(sev) - 1)]


def _raise(sev: Severity) -> Severity:
    return _ORDER[min(_ORDER.index(Severity.HIGH), _ORDER.index(sev) + 1)]


def _family(category: str) -> str:
    parts = category.split(".")
    return parts[1] if len(parts) > 1 else category


def _corroborate(findings: list[Finding]) -> list[Finding]:
    """Heuristics alone are weak; independent KINDS of check agreeing on the same file are strong. Raise the top finding one level (never above High)."""
    heur = [f for f in findings if _family(f.category) in HEURISTIC_FAMILIES]
    fams = {_family(f.category) for f in heur}
    if len(fams) >= 2:
        top = max(heur, key=lambda f: SEVERITY_RANK[f.severity])
        if SEVERITY_RANK[top.severity] < SEVERITY_RANK[Severity.HIGH]:
            top.severity = _raise(top.severity)
            top.evidence.append(Evidence(f"Corroborated: {len(fams)} independent kinds of check agree ({', '.join(sorted(fams))}); severity raised one level",
                                         top.source, "rule:SH-CORROBORATE", T.DERIVED))
            top.tier = weakest_tier(e.tier for e in top.evidence)
    return findings


def inspect_content(name: str, data: bytes, path: str | None, salt: bytes, sha256: str, authenticode: Any = None,
                    known_hashes: dict[str, str] | None = None, rules: list[Rule] | None = None, depth: int = 0) -> list[Finding]:
    """Pure function: given a file's name and bytes, return findings. Used by scan, archive members, and tests.
    `authenticode` may be a status string or a callable(path)->str, only invoked when a PE finding needs it."""
    findings: list[Finding] = []
    ext = Path(name.split("!")[-1]).suffix.lower()
    fe = lambda desc, ref, by, tier=T.VERIFIED: Evidence(desc, ref, by, tier)  # noqa: E731
    ents = [make_entity("file", name, salt)]
    known = KNOWN_HASHES if known_hashes is None else known_hashes
    fam = sniff_family(data[:16])

    # 1. Signatures. An antivirus TEST FILE is the test string by itself; the same string inside a larger file (documentation, test code,
    #    a security tool such as Panzeron itself) is only a mention and is not a threat.
    for sid, sname, pattern, desc, kind in SIGNATURES:
        idx = data.find(pattern)
        if idx < 0:
            continue
        ev = [fe(f"Exact byte pattern for '{sname}' found at offset {idx} in a file of {len(data)} bytes", f"{name} @ offset {idx}", f"sig:{sid}")]
        if len(data) > EXACT_TEST_FILE_MAX:
            findings.append(Finding(
                Module.SHIELD, f"Contains the {sname} string (not a test file)", Severity.INFO, Confidence.HIGH,
                "An antivirus test file is just the test string on its own (at most 256 bytes). This file is larger and merely CONTAINS the string, which is normal for "
                "documentation, test code and security tools. It is not a threat.", ev, name, ents, ["No action needed"], path, category="shield.signature_mention"))
        elif kind == "sim":
            findings.append(Finding(
                Module.SHIELD, f"Simulated threat detected: {sname}", Severity.HIGH, Confidence.HIGH,
                "This is a SIMULATED threat: a harmless file made by Panzeron's demo data to show what a serious detection looks like and how the response workflow behaves. "
                "Nothing here can harm your computer.", ev, name, ents, ["Try the response actions: they work exactly as they would on a real threat", "Quarantine it (reversible)"],
                path, category="shield.signature"))
        else:
            findings.append(Finding(
                Module.SHIELD, f"Antivirus test file detected (harmless): {sname}", Severity.LOW, Confidence.HIGH,
                f"{desc} It is a test file, so it is not a danger. Panzeron reports it so you can see detection working. It is only worth acting on if you did not expect it to be here.",
                ev, name, ents, ["Delete it if you do not need it", "If this is an intentional test file, add an exclusion"], path, category="shield.signature"))

    # 2. Known-hash match (built-in list plus any hash lists you imported)
    if sha256 in known and not any(f.category.startswith("shield.signature") for f in findings):
        findings.append(Finding(
            Module.SHIELD, f"Known malicious file hash: {known[sha256]}", Severity.HIGH, Confidence.HIGH,
            "The SHA-256 of this file matches an entry in your local known-bad hash lists. A hash match means this exact file is known, regardless of its name.",
            [fe(f"SHA-256 {sha256[:16]}… is in the local list ({known[sha256]})", name, "hash:local-list")],
            name, ents, ["Quarantine the file (reversible)"], path, category="shield.hash"))

    # 3. Executable content behind a non-executable extension (an observed fact; not proof of malice)
    if fam == "pe" and ext in NON_EXEC_EXTS:
        findings.append(Finding(
            Module.SHIELD, "Executable content with a non-executable extension", Severity.MEDIUM, Confidence.MEDIUM,
            f"The file is named '{name}' but begins with the 'MZ' header used by Windows programs. "
            "This pattern is used to disguise programs as documents or images, but it can also occur through renaming mistakes. It is an observed fact, not proof the file is malicious.",
            [fe(f"File header bytes are 'MZ' (Windows executable) but the extension is '{ext}'", f"{name} @ offset 0", "magic:mz-vs-extension")],
            name, ents, ["Do not open the file", "If you did not create it, quarantine it (reversible)", "Scan it with Windows Defender"], path, category="shield.disguised"))
    # NOTE: the reverse (an '.exe' that is plain text) and double-extension names are deliberately NOT flagged:
    # name-only evidence is not evidence of malicious behaviour.

    # 4. PE structure: sections, entry point, import table
    if fam == "pe":
        info = pelib.parse(data, len(data))
        if info:
            inds = pelib.assess(info, len(data))
            score = sum(w for _, _, w in inds)
            if score >= 3:
                auth = authenticode(path) if callable(authenticode) and path else authenticode
                signed = auth == "Valid"
                sev = Severity.MEDIUM if score >= 6 else Severity.LOW
                conf = Confidence.MEDIUM if score >= 8 else Confidence.LOW
                if signed:
                    sev = Severity.INFO if sev == Severity.LOW else Severity.LOW
                findings.append(Finding(
                    Module.SHIELD, "Executable shows packing or suspicious-behaviour indicators", sev, conf,
                    "These traits are used by malware to hide or perform harmful actions, but also by many legitimate installers, games and protection tools. "
                    "Treat this as a reason to look closer, not as a verdict. The file was NOT executed."
                    + (" It has a valid digital signature, which lowers concern." if signed else (" It carries an embedded certificate that was not validated here." if info.has_signature_blob and auth is None else "")),
                    [fe(d, f"{name} @ PE headers/import table", f"pe:{code}") for code, d, _ in inds]
                    + [fe(f"Indicator score {score} reached the reporting threshold of 3 (weak signals alone are never reported)", name, "rule:SH-PE-2", T.DERIVED)],
                    name, ents, ["Check where the file came from", "Scan with Windows Defender"], path, category="shield.pe"))

    # 5. Script behaviour indicators (static text only), including payloads hidden in -EncodedCommand
    if ext in SCRIPT_EXTS or ext in {".lnk"}:
        hits: list[tuple[str, str, int, bool]] = []
        for key, rx, desc in SCRIPT_INDICATORS:
            m = rx.search(data)
            if m:
                hits.append((key, desc, m.start(), False))
        decoded = decode_encoded_commands(data)
        seen = {k for k, *_ in hits}
        for blob in decoded:
            for key, rx, desc in SCRIPT_INDICATORS:
                if key != "encoded_command" and key not in seen and rx.search(blob):
                    hits.append((key, f"{desc} (inside the decoded -EncodedCommand payload)", 0, True))
                    seen.add(key)
        if len(hits) >= 2:
            findings.append(Finding(
                Module.SHIELD, "Script contains multiple suspicious behaviour indicators", Severity.MEDIUM, Confidence.LOW,
                "The script uses several techniques common in malicious loaders. Administrators also use these techniques, so confidence is low until you know where the script came from. "
                "It was NOT executed." + (f" {len(decoded)} hidden encoded command(s) were decoded and inspected." if decoded else ""),
                [fe(f"{d} (offset {o})" if not dec else d, f"{name} @ offset {o}" if not dec else f"{name} @ decoded payload", f"static:{k}") for k, d, o, dec in hits]
                + [fe(f"{len(hits)} distinct indicators matched (threshold: 2)", name, "rule:SH-SCRIPT-1", T.DERIVED)],
                name, ents, ["Do not run the script", "Confirm its origin", "Quarantine if unrecognised"], path, category="shield.script"))

    # 6. Rule engine, calibrated for context
    hits = evaluate(BUILTIN_RULES if rules is None else rules, name.split("!")[-1], ext, fam, data)
    if len({h.rule.id for h in hits}) >= RULESET_FAMILIES:
        fam_names = sorted({h.rule.name for h in hits})
        findings.append(Finding(
            Module.SHIELD, "Contains many security-tool patterns (looks like detection rules, tests or notes)", Severity.INFO, Confidence.MEDIUM,
            "This file contains patterns from several unrelated attack techniques at once. Real malware almost never does that; antivirus rules, security tests and research notes do. "
            "It is not treated as a threat.", [fe(f"Matches {len(fam_names)} different rule families: {', '.join(fam_names)}", name, "rule:SH-RULESET-LIKE", T.DERIVED)],
            name, ents, ["No action needed if you recognise this file"], path, category="shield.ruleset_like"))
    else:
        for hit in hits:
            r, sev, notes = hit.rule, hit.rule.severity, []
            if sev == Severity.HIGH and r.precision != "high":
                sev = Severity.MEDIUM
                notes.append("Capped at Medium: this rule's patterns also appear in documentation and security tools, so a single match is not enough for High.")
            if ext in SOURCE_EXTS:
                sev = _lower(sev)
                notes.append("Lowered one level: this is a source-code file, where such patterns are usually strings inside a program rather than an attack.")
            findings.append(Finding(
                Module.SHIELD, r.name, sev, r.confidence, f"{r.description} The file was NOT executed.",
                [fe(f"Pattern '{lbl}' matched at offset {off}", f"{name} @ offset {off}", f"rule:{r.id}") for lbl, off in hit.matches[:12]]
                + [fe(f"Rule {r.id} matched ({len(hit.matches)} pattern hit{'s' if len(hit.matches) != 1 else ''})" + (f"; tags: {', '.join(r.tags)}" if r.tags else ""), name, f"rule:{r.id}", T.DERIVED)]
                + [fe(n, name, f"rule:{r.id}", T.DERIVED) for n in notes],
                name, ents, ["Do not run or open the file", "Confirm where it came from", "Quarantine if unrecognised (reversible)"], path, category=f"shield.rule.{r.id}"))
    return _corroborate(findings)


def _is_excluded(path: str, sha256: str | None, exclusions: list[dict[str, Any]]) -> bool:
    norm = path.replace("\\", "/").lower()
    for ex in exclusions:
        pat = str(ex["pattern"]).replace("\\", "/").lower()
        if ex["kind"] == "path" and (norm == pat or fnmatch.fnmatch(norm, pat) or norm.startswith(pat.rstrip("/") + "/")):
            return True
        if ex["kind"] == "hash" and sha256 and sha256.lower() == pat:
            return True
    return False


class Scanner:
    def __init__(self, salt: bytes, exclusions: list[dict[str, Any]] | None = None, max_file_mb: int = 200,
                 authenticode_fn: Callable[[str], str | None] | None = None, mode: str = "deep",
                 known_hashes: dict[str, str] | None = None, rules: list[Rule] | None = None, workers: int | None = None,
                 trust: Any = None, cache: Any = None):
        self.salt = salt
        self.exclusions = exclusions or []
        self.max_bytes = max_file_mb * 1024 * 1024
        self.authenticode_fn = authenticode_fn
        self.mode = mode if mode in ("smart", "deep") else "smart"
        self.known = {**KNOWN_HASHES, **(known_hashes or {})}
        self.rules = rules
        self.trust = trust            # TrustStore: recognises Panzeron's own files by hash
        self.cache = cache            # ScanCache: skips unchanged files that were clean last time (smart mode only)
        self.workers = workers or max(2, min(8, (os.cpu_count() or 2)))
        self.cancel_event = threading.Event()
        self._lock = threading.Lock()

    # ---- enumeration ------------------------------------------------------------------------------------
    def _walk(self, roots: list[Path], res: ScanResult, skip: list[tuple[str, str]]):
        stack = list(reversed(roots))
        skip_l = [(s.replace("\\", "/").lower(), why) for s, why in skip]
        while stack and not self.cancel_event.is_set():
            cur = stack.pop()
            if cur.is_file():
                yield cur
                continue
            norm = str(cur).replace("\\", "/").lower() + "/"
            hit = next(((s, why) for s, why in skip_l if (norm.startswith(s[1:]) if s.startswith('^') else s in norm)), None)
            if hit:
                if len(res.skipped_dirs) < 60:
                    res.skipped_dirs.append({"path": str(cur), "reason": hit[1]})
                continue
            if any(ex["kind"] == "path" and norm.rstrip("/").startswith(str(ex["pattern"]).replace("\\", "/").lower().rstrip("/")) for ex in self.exclusions):
                res.files_excluded += 1
                continue
            try:
                with os.scandir(cur) as it:
                    entries = list(it)
            except PermissionError:
                res.access_denied += 1
                if len(res.errors) < 200:
                    res.errors.append({"path": str(cur), "error": "access denied (needs administrator rights or is protected)"})
                continue
            except OSError as e:
                if len(res.errors) < 200:
                    res.errors.append({"path": str(cur), "error": str(e)})
                continue
            subdirs = []
            for e in entries:
                try:
                    if e.is_symlink() or getattr(e, "is_junction", lambda: False)():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        subdirs.append(Path(e.path))
                    elif e.is_file(follow_symlinks=False):
                        yield Path(e.path)
                except OSError:
                    continue
            stack.extend(reversed(subdirs))

    # ---- one file ---------------------------------------------------------------------------------------
    def _inspect_member(self, name, data, path, salt, sha, depth=0):
        return inspect_content(name, data, path, salt, hashlib.sha256(data).hexdigest(), self.authenticode_fn, self.known, self.rules, depth)

    def _own_file_findings(self, status: str, p: Path, sha: str) -> list[Finding]:
        rel = self.trust.rel(p)
        ents = [make_entity("file", p.name, self.salt)]
        if status == "modified":
            want = self.trust.manifest.get(rel, "")
            return [Finding(Module.SHIELD, "An Panzeron program file was modified", Severity.MEDIUM, Confidence.MEDIUM,
                            "This file is part of Panzeron, but its contents no longer match the manifest that shipped with it. If you edited it yourself, rebuild trust in "
                            "Settings → Protection. If you did not, treat this as suspicious: something may have tampered with the program.",
                            [Evidence(f"SHA-256 {sha[:16]}… differs from the shipped manifest ({want[:16]}…)", rel, "trust:manifest-mismatch", T.VERIFIED)],
                            p.name, ents, ["Rebuild trust if you changed it yourself", "Otherwise reinstall Panzeron from a source you trust"], str(p), category="shield.self_modified")]
        if p.suffix.lower() in OWN_PROGRAM_EXTS:
            return [Finding(Module.SHIELD, "Unexpected program file in Panzeron's folder", Severity.LOW, Confidence.MEDIUM,
                            "A program or script appears in Panzeron's own folder that was not part of the shipped files. It may be something you added, or something that was dropped there.",
                            [Evidence(f"'{rel}' is not listed in the shipped manifest", rel, "trust:not-in-manifest", T.VERIFIED)],
                            p.name, ents, ["Check that you added it", "Rebuild trust if it is yours"], str(p), category="shield.self_unexpected")]
        return []

    def scan_file_ex(self, p: Path) -> tuple[list[Finding], int, str | None, str]:
        """Returns (findings, bytes_read, sha256 or None, how) with how in full|quick|trusted|cached. Raises OSError if unreadable."""
        st = p.stat()
        size = st.st_size
        if size > self.max_bytes:
            raise OSError(f"skipped: file is {size // (1024 * 1024)} MB, above the {self.max_bytes // (1024 * 1024)} MB limit")
        own = bool(self.trust and self.trust.contains(p))
        use_cache = bool(self.cache and self.mode == "smart" and not own)
        if use_cache and self.cache.hit(str(p), size, st.st_mtime_ns):
            return [], 0, None, "cached"
        ext = p.suffix.lower()
        full = self.mode == "deep" or ext in RISKY_EXTS or size <= SMALL_FULL or own
        h, keep, tail, sig_hits, read = hashlib.sha256(), bytearray(), b"", bytearray(), 0
        with open(p, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK if full else QUICK_BYTES)
                if not chunk:
                    break
                if full:
                    h.update(chunk)
                read += len(chunk)
                if read <= MAX_SIG_SCAN_BYTES:
                    window = tail + chunk
                    for _, _, pat, *_ in SIGNATURES:
                        if pat in window and pat not in sig_hits:
                            sig_hits += pat + b"\n"
                    tail = window[-(_MAX_SIG_LEN - 1):]
                if len(keep) < KEEP_BYTES:
                    keep += chunk[: KEEP_BYTES - len(keep)]
                if not full:
                    break
        sha = h.hexdigest() if full else None
        extra: list[Finding] = []
        if own and sha:
            status = self.trust.classify(p, sha)
            if status == "trusted":
                return [], read, sha, "trusted"
            extra = self._own_file_findings(status, p, sha)
        data = bytes(keep)
        for line in bytes(sig_hits).split(b"\n"):      # signature hits beyond the kept window still report
            if line and line not in data:
                data += b"\n" + line
        findings = extra + inspect_content(p.name, data, str(p), self.salt, sha or "", self.authenticode_fn, self.known, self.rules)
        fam = sniff_family(data[:16])
        if full and fam == "zip":
            findings += containers.inspect_zip(p, p.name, str(p), self.salt, self._inspect_member)
        elif full and fam == "ole":
            findings += containers.inspect_ole(data, p.name, str(p), self.salt)
        if use_cache and full and not findings:
            self.cache.add(str(p), size, st.st_mtime_ns)           # only fully-read, finding-free files are remembered
        return findings, read, sha, "full" if full else "quick"

    def scan_file(self, p: Path) -> tuple[list[Finding], int, str | None]:
        f, n, sha, _ = self.scan_file_ex(p)
        return f, n, sha

    def _scan_one(self, p: Path, res: ScanResult, out: list[Finding]) -> None:
        sp = str(p)
        if self.cancel_event.is_set():
            return
        if _is_excluded(sp, None, self.exclusions):
            with self._lock:
                res.files_excluded += 1
            return
        res.current = sp
        try:
            fnds, nbytes, sha, how = self.scan_file_ex(p)
            if sha and self.exclusions and _is_excluded(sp, sha, self.exclusions):
                with self._lock:
                    res.files_excluded += 1
                return
            with self._lock:
                out.extend(fnds)
                res.bytes_scanned += nbytes
                res.files_scanned += 1
                res.files_full += how == "full"
                res.files_quick += how == "quick"
                res.files_trusted += how == "trusted"
                res.files_cached += how == "cached"
        except OSError as e:
            log.warning("unreadable file during scan", extra={"ctx": {"path": sp, "error": str(e)}})
            with self._lock:
                if "Permission" in str(e) or "denied" in str(e).lower():
                    res.access_denied += 1
                if len(res.errors) < 200:
                    res.errors.append({"path": sp, "error": str(e)})

    # ---- whole scan -------------------------------------------------------------------------------------
    def scan(self, target: Any, on_progress: Callable[[ScanResult], None] | None = None, skip: list[tuple[str, str]] | None = None,
             scope: str = "custom", result: ScanResult | None = None) -> tuple[ScanResult, list[Finding]]:
        targets = target if isinstance(target, (list, tuple)) else [target]
        roots = [Path(t) for t in targets]
        res = result if result is not None else ScanResult(id=new_id("scan"), target="", started_at=now_iso())
        res.target, res.scope, res.mode = ", ".join(str(r) for r in roots)[:300], scope, self.mode
        findings: list[Finding] = []
        t0 = time.monotonic()
        missing = [r for r in roots if not r.exists()]
        if missing and len(missing) == len(roots):
            res.status, res.finished_at, res.enumerating, res.verdict = "failed", now_iso(), False, "incomplete"
            res.errors.append({"path": str(missing[0]), "error": "path does not exist"})
            return res, findings
        pending: set = set()
        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="shield") as pool:
            for p in self._walk([r for r in roots if r.exists()], res, skip or []):
                res.files_total += 1
                pending.add(pool.submit(self._scan_one, p, res, findings))
                if len(pending) >= self.workers * 8:
                    _, pending = wait(pending, return_when=FIRST_COMPLETED)
                    if on_progress:
                        on_progress(res)
            res.enumerating = False
            while pending:
                _, pending = wait(pending, timeout=0.3, return_when=FIRST_COMPLETED)
                if on_progress:
                    on_progress(res)
        res.status = "cancelled" if self.cancel_event.is_set() else "completed"
        res.finished_at = now_iso()
        res.duration_s = round(time.monotonic() - t0, 2)
        res.finding_ids = [f.id for f in findings]
        for f in findings:
            res.severity_counts[f.severity.value] = res.severity_counts.get(f.severity.value, 0) + 1
        sc = res.severity_counts
        only_tests = bool(findings) and all(f.category in ("shield.signature",) and f.severity == Severity.LOW or f.severity == Severity.INFO for f in findings)
        res.verdict = ("incomplete" if res.status != "completed" else "threats" if sc.get("high") or sc.get("critical")
                       else "review" if sc.get("medium") else "test" if only_tests and any(f.category == "shield.signature" for f in findings) else "clean")
        return res, findings
