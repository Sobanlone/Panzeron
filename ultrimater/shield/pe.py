"""Windows PE static analysis (stdlib only): sections, entry point, import table, anomalies.

Nothing here executes or loads the file. Anomaly scoring is deliberately conservative: single weak signals never
produce a finding, and every indicator is explained in plain language.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Any

SEC_EXEC, SEC_CODE, SEC_WRITE = 0x20000000, 0x20, 0x80000000
PACKER_SECTIONS = {b"UPX0", b"UPX1", b"UPX2", b".aspack", b".adata", b".petite", b".themida", b".vmp0", b".vmp1", b"MPRESS1", b"MPRESS2", b".enigma1", b".nsp0", b".nsp1"}

API_GROUPS = {
    "process injection": ({"virtualallocex", "writeprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext", "ntunmapviewofsection"}, 3, 3),
    "keystroke capture": ({"setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeyboardstate", "getkeystate", "registerrawinputdevices"}, 2, 2),
    "download and execute": ({"urldownloadtofilea", "urldownloadtofilew", "internetopenurla", "internetopenurlw", "internetreadfile", "winhttpopen", "winexec", "shellexecutea", "shellexecutew", "createprocessa", "createprocessw"}, 3, 2),
    "file encryption sweep": ({"cryptencrypt", "bcryptencrypt", "cryptgenkey", "findfirstfilew", "findnextfilew", "findfirstfilea", "movefileexw", "deletefilew"}, 5, 2),
    "anti-debugging": ({"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa"}, 3, 1),
    "persistence via registry": ({"regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw"}, 2, 0),   # informational only
}


@dataclass
class Section:
    name: bytes
    vsize: int
    vaddr: int
    raw_size: int
    raw_ptr: int
    flags: int
    entropy: float


@dataclass
class PEInfo:
    machine: str
    timestamp: int
    is_dll: bool
    is_64: bool
    entry_rva: int
    sections: list[Section]
    imports: dict[str, list[str]] = field(default_factory=dict)       # dll -> function names
    has_signature_blob: bool = False
    overlay_size: int = 0

    @property
    def import_count(self) -> int:
        return sum(len(v) for v in self.imports.values())


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _cstr(data: bytes, off: int, limit: int = 260) -> str:
    end = data.find(b"\0", off, off + limit)
    return data[off:end if end >= 0 else off + limit].decode("ascii", "replace") if 0 <= off < len(data) else ""


def parse(data: bytes, total_size: int | None = None) -> PEInfo | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    machine, nsec, ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0] if opt + 2 <= len(data) else 0
    is64 = magic == 0x20B
    entry = struct.unpack_from("<I", data, opt + 16)[0] if magic in (0x10B, 0x20B) and opt + 20 <= len(data) else 0
    sec_off = opt + opt_size
    sections: list[Section] = []
    for i in range(min(nsec, 96)):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\0")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
        fl = struct.unpack_from("<I", data, o + 36)[0]
        body = data[rawptr:rawptr + rawsize] if rawptr and rawsize else b""
        sections.append(Section(name, vsize, vaddr, rawsize, rawptr, fl, round(shannon_entropy(body), 2)))
    info = PEInfo(hex(machine), ts, bool(chars & 0x2000), is64, entry, sections)

    def rva2off(rva: int) -> int | None:
        for s in sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
                return rva - s.vaddr + s.raw_ptr
        return None

    try:  # data directories: import (1) and security/certificate (4)
        dd = opt + (112 if is64 else 96)
        if magic in (0x10B, 0x20B) and dd + 40 <= len(data):
            imp_rva, imp_size = struct.unpack_from("<II", data, dd + 8)
            sec_ptr, sec_size = struct.unpack_from("<II", data, dd + 32)
            info.has_signature_blob = bool(sec_ptr and sec_size)
            io = rva2off(imp_rva) if imp_rva and imp_size else None
            n_funcs = 0
            for k in range(256 if io is not None else 0):
                d = io + k * 20
                if d + 20 > len(data):
                    break
                oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, d)
                if not name_rva and not ft:
                    break
                no = rva2off(name_rva)
                dll = _cstr(data, no).lower() if no is not None else "?"
                funcs: list[str] = []
                to = rva2off(oft or ft)
                step = 8 if is64 else 4
                while to is not None and n_funcs < 6000 and to + step <= len(data):
                    thunk = int.from_bytes(data[to:to + step], "little")
                    if thunk == 0:
                        break
                    if not thunk >> (63 if is64 else 31) & 1:
                        ho = rva2off(thunk & 0x7FFFFFFF)
                        if ho is not None:
                            funcs.append(_cstr(data, ho + 2, 120))
                    to += step
                    n_funcs += 1
                info.imports[dll] = funcs
    except (struct.error, IndexError):
        pass
    if sections and total_size:
        end = max(s.raw_ptr + s.raw_size for s in sections)
        info.overlay_size = max(0, total_size - end)
    return info


def assess(pe: PEInfo, total_size: int) -> list[tuple[str, str, int]]:
    """Returns [(code, plain-language description, weight)]. Weights are summed by the caller."""
    out: list[tuple[str, str, int]] = []
    names = lambda s: s.name.decode(errors="replace")  # noqa: E731
    for s in pe.sections:
        if s.name in PACKER_SECTIONS:
            out.append(("packer_section", f"section '{names(s)}' is a known packer section name", 3))
        if s.flags & SEC_WRITE and s.flags & SEC_EXEC:
            out.append(("rwx_section", f"section '{names(s)}' is both writable and executable (self-modifying code)", 2))
        if s.raw_size > 4096 and s.entropy > 7.2:
            out.append(("high_entropy", f"section '{names(s)}' has high entropy ({s.entropy}), typical of compressed or encrypted code", 1))
    if pe.entry_rva and pe.sections:
        host = next((s for s in pe.sections if s.vaddr <= pe.entry_rva < s.vaddr + max(s.vsize, s.raw_size)), None)
        if host is None:
            out.append(("entry_outside", "program entry point lies outside every section", 2))
        elif not host.flags & (SEC_EXEC | SEC_CODE):
            out.append(("entry_nonexec", f"program entry point is in non-executable section '{names(host)}'", 2))
        elif host is pe.sections[-1] and len(pe.sections) > 2 and host.name not in (b".text", b"CODE"):
            out.append(("entry_last_section", f"program entry point is in the last section '{names(host)}' (common for packers)", 1))
    funcs = {f.lower() for v in pe.imports.values() for f in v}
    if pe.import_count and pe.import_count <= 6 and total_size > 50_000 and any(s.entropy > 7.0 for s in pe.sections):
        out.append(("tiny_imports", f"only {pe.import_count} imported functions in a {total_size // 1024} KB file with high-entropy data (typical of a packed loader)", 2))
    for label, (apis, need, weight) in API_GROUPS.items():
        hit = sorted(funcs & apis)
        if weight and len(hit) >= need:
            out.append(("api_combo", f"imports {len(hit)} APIs associated with {label}: {', '.join(hit[:5])}", weight))
    return out
